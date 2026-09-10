from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
import tempfile
from contextlib import contextmanager
from threading import RLock
from typing import Any, Optional

from firewall.authority_epoch import record_widening


class SecurityContextError(Exception):
    """Base security-context error."""


class SecurityBudgetExceeded(SecurityContextError):
    """Raised when a security context budget would be exceeded."""


@dataclass(frozen=True)
class SecuritySnapshot:
    agent: str
    action_count: int
    total_amount: float
    denial_count: int
    used_capabilities: tuple[str, ...]


@dataclass
class SecurityContext:
    """
    Runtime security state for a single agent/session.

    v1.4 optionally persists cumulative security state so that
    process restart does not silently reset consumed budgets.

    Persistent state includes:
    - cumulative action count
    - cumulative amount
    - denial count
    - used capability fingerprints

    Persistence is atomic and integrity checked.
    """

    agent: str

    max_actions: Optional[int] = None
    max_total_amount: Optional[float] = None

    action_count: int = 0
    total_amount: float = 0.0
    denial_count: int = 0

    state_path: Optional[str] = None

    _used_capabilities: set[str] = field(
        default_factory=set,
        repr=False,
    )

    _lock: RLock = field(
        default_factory=RLock,
        init=False,
        repr=False,
    )

    _file_lock_path: Optional[str] = field(
        default=None,
        init=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        if (
            not isinstance(
                self.agent,
                str,
            )
            or not self.agent
        ):
            raise ValueError(
                "agent must be a non-empty string"
            )

        if (
            self.max_actions is not None
            and (
                not isinstance(
                    self.max_actions,
                    int,
                )
                or isinstance(
                    self.max_actions,
                    bool,
                )
                or self.max_actions < 0
            )
        ):
            raise ValueError(
                "max_actions must be a non-negative integer"
            )

        if (
            self.max_total_amount is not None
            and (
                not isinstance(
                    self.max_total_amount,
                    (int, float),
                )
                or isinstance(
                    self.max_total_amount,
                    bool,
                )
                or self.max_total_amount < 0
            )
        ):
            raise ValueError(
                "max_total_amount must be non-negative"
            )

        if self.action_count < 0:
            raise ValueError(
                "action_count cannot be negative"
            )

        if self.total_amount < 0:
            raise ValueError(
                "total_amount cannot be negative"
            )

        if self.denial_count < 0:
            raise ValueError(
                "denial_count cannot be negative"
            )

        if self.state_path is not None:
            if (
                not isinstance(
                    self.state_path,
                    (str, os.PathLike),
                )
            ):
                raise ValueError(
                    "state_path must be a path-like value"
                )

            self.state_path = os.fspath(
                self.state_path
            )

            self._file_lock_path = (
                f"{os.path.abspath(self.state_path)}.lock"
            )

            with self._exclusive_file_lock():
                self._load_persistent_state()

    @contextmanager
    def _exclusive_file_lock(self):
        """
        Serialize persistent read/modify/write operations across
        independent SecurityContext instances and processes.

        The lock lives in a sidecar file so replacing the JSON
        state file cannot invalidate the lock identity.
        """
        if self._file_lock_path is None:
            yield
            return

        directory = os.path.dirname(
            os.path.abspath(
                self._file_lock_path
            )
        )
        os.makedirs(
            directory,
            exist_ok=True,
        )

        handle = open(
            self._file_lock_path,
            "a+b",
        )

        try:
            handle.seek(0, os.SEEK_END)

            if handle.tell() == 0:
                handle.write(b"0")
                handle.flush()

            handle.seek(0)

            if os.name == "nt":
                import msvcrt

                msvcrt.locking(
                    handle.fileno(),
                    msvcrt.LK_LOCK,
                    1,
                )
            else:
                import fcntl

                fcntl.flock(
                    handle.fileno(),
                    fcntl.LOCK_EX,
                )

            yield

        finally:
            try:
                handle.seek(0)

                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(
                        handle.fileno(),
                        msvcrt.LK_UNLCK,
                        1,
                    )
                else:
                    import fcntl

                    fcntl.flock(
                        handle.fileno(),
                        fcntl.LOCK_UN,
                    )
            finally:
                handle.close()

    # =========================================================
    # Persistence
    # =========================================================

    def _state_payload(self) -> dict[str, Any]:
        return {
            "version": 1,
            "agent": self.agent,
            "action_count": self.action_count,
            "total_amount": self.total_amount,
            "denial_count": self.denial_count,
            "used_capabilities": sorted(
                self._used_capabilities
            ),
        }

    @staticmethod
    def _integrity_hash(
        payload: dict[str, Any],
    ) -> str:
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

        return hashlib.sha256(
            encoded
        ).hexdigest()

    def _refresh_from_disk_locked(self) -> None:
        """
        Refresh this context from the latest persistent state.

        Must be called while the process-local lock and file lock
        are both held.
        """
        if self.state_path is None:
            return

        self._load_persistent_state()

    def _persist_locked(self) -> None:
        if self.state_path is None:
            return

        payload = self._state_payload()

        document = {
            "payload": payload,
            "integrity_hash": self._integrity_hash(
                payload
            ),
        }

        directory = os.path.dirname(
            os.path.abspath(
                self.state_path
            )
        )

        os.makedirs(
            directory,
            exist_ok=True,
        )

        fd = None
        temp_path = None

        try:
            fd, temp_path = tempfile.mkstemp(
                prefix=".security_context_",
                suffix=".tmp",
                dir=directory,
            )

            with os.fdopen(
                fd,
                "w",
                encoding="utf-8",
            ) as handle:
                fd = None

                json.dump(
                    document,
                    handle,
                    sort_keys=True,
                    separators=(",", ":"),
                )

                handle.flush()
                os.fsync(
                    handle.fileno()
                )

            os.replace(
                temp_path,
                self.state_path,
            )

            temp_path = None

        except (
            OSError,
            TypeError,
            ValueError,
        ) as exc:
            raise SecurityContextError(
                "security context persistence failed"
            ) from exc

        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass

            if temp_path is not None:
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass

    def _load_persistent_state(self) -> None:
        try:
            with open(
                self.state_path,
                "r",
                encoding="utf-8",
            ) as handle:
                document = json.load(handle)

        except FileNotFoundError:
            return

        except (
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:
            raise SecurityContextError(
                "security context persistent state is unavailable"
            ) from exc

        if not isinstance(
            document,
            dict,
        ):
            raise SecurityContextError(
                "security context persistent state is invalid"
            )

        payload = document.get(
            "payload"
        )

        stored_hash = document.get(
            "integrity_hash"
        )

        if (
            not isinstance(
                payload,
                dict,
            )
            or not isinstance(
                stored_hash,
                str,
            )
        ):
            raise SecurityContextError(
                "security context persistent state is invalid"
            )

        if (
            self._integrity_hash(payload)
            != stored_hash
        ):
            raise SecurityContextError(
                "security context persistent state integrity check failed"
            )

        if payload.get("version") != 1:
            raise SecurityContextError(
                "unsupported security context state version"
            )

        if payload.get("agent") != self.agent:
            raise SecurityContextError(
                "security context state agent mismatch"
            )

        action_count = payload.get(
            "action_count"
        )
        total_amount = payload.get(
            "total_amount"
        )
        denial_count = payload.get(
            "denial_count"
        )
        used_capabilities = payload.get(
            "used_capabilities"
        )

        if (
            not isinstance(
                action_count,
                int,
            )
            or isinstance(
                action_count,
                bool,
            )
            or action_count < 0
        ):
            raise SecurityContextError(
                "invalid persisted action count"
            )

        if (
            isinstance(
                total_amount,
                bool,
            )
            or not isinstance(
                total_amount,
                (int, float),
            )
            or total_amount < 0
        ):
            raise SecurityContextError(
                "invalid persisted total amount"
            )

        if (
            not isinstance(
                denial_count,
                int,
            )
            or isinstance(
                denial_count,
                bool,
            )
            or denial_count < 0
        ):
            raise SecurityContextError(
                "invalid persisted denial count"
            )

        if not isinstance(
            used_capabilities,
            list,
        ) or not all(
            isinstance(
                fingerprint,
                str,
            )
            for fingerprint in used_capabilities
        ):
            raise SecurityContextError(
                "invalid persisted capability usage"
            )

        if (
            self.max_actions is not None
            and action_count > self.max_actions
        ):
            raise SecurityContextError(
                "persisted action count exceeds configured budget"
            )

        if (
            self.max_total_amount is not None
            and float(total_amount)
            > float(self.max_total_amount)
        ):
            raise SecurityContextError(
                "persisted total amount exceeds configured budget"
            )

        self.action_count = action_count
        self.total_amount = float(
            total_amount
        )
        self.denial_count = denial_count
        self._used_capabilities = set(
            used_capabilities
        )

    # =========================================================
    # Request helpers
    # =========================================================

    @staticmethod
    def _amount(
        request: dict[str, Any],
    ) -> float:
        value = request.get(
            "amount",
            0,
        )

        if isinstance(
            value,
            bool,
        ):
            raise ValueError(
                "amount must be numeric"
            )

        if not isinstance(
            value,
            (int, float),
        ):
            raise ValueError(
                "amount must be numeric"
            )

        if value < 0:
            raise ValueError(
                "amount cannot be negative"
            )

        return float(value)

    @staticmethod
    def _validate_fingerprint(
        capability_fingerprint: Optional[str],
    ) -> None:
        if (
            capability_fingerprint is not None
            and not isinstance(
                capability_fingerprint,
                str,
            )
        ):
            raise ValueError(
                "capability_fingerprint must be a string"
            )

    # =========================================================
    # Budget checks
    # =========================================================

    def _check_action_budget(
        self,
    ) -> None:
        if (
            self.max_actions is not None
            and (
                self.action_count + 1
                > self.max_actions
            )
        ):
            raise SecurityBudgetExceeded(
                "action budget exceeded"
            )

    def _check_amount_budget(
        self,
        amount: float,
    ) -> None:
        if (
            self.max_total_amount is not None
            and (
                self.total_amount + amount
                > self.max_total_amount
            )
        ):
            raise SecurityBudgetExceeded(
                "total amount budget exceeded"
            )

    # =========================================================
    # Non-mutating preflight
    # =========================================================

    def check(
        self,
        request: dict[str, Any],
    ) -> None:
        """
        Check whether an action would fit inside the current
        budgets without mutating state.
        """

        if not isinstance(
            request,
            dict,
        ):
            raise ValueError(
                "request must be a dictionary"
            )

        amount = self._amount(
            request
        )

        with self._lock:
            self._check_action_budget()
            self._check_amount_budget(
                amount
            )

    # =========================================================
    # Atomic authorization + recording
    # =========================================================

    def authorize_and_record(
        self,
        *,
        request: dict[str, Any],
        capability_fingerprint: Optional[str] = None,
    ) -> None:
        """
        Atomically check budgets, mutate state, and persist it.

        Cross-process callers sharing state_path are serialized by
        the sidecar file lock. The latest persisted state is loaded
        before the budget check, preventing lost updates.
        """

        if not isinstance(
            request,
            dict,
        ):
            raise ValueError(
                "request must be a dictionary"
            )

        self._validate_fingerprint(
            capability_fingerprint
        )

        amount = self._amount(
            request
        )

        with self._lock:
            with self._exclusive_file_lock():
                self._refresh_from_disk_locked()

                self._check_action_budget()
                self._check_amount_budget(
                    amount
                )

                old_action_count = (
                    self.action_count
                )
                old_total_amount = (
                    self.total_amount
                )
                old_used_capabilities = set(
                    self._used_capabilities
                )

                self.action_count += 1
                self.total_amount += amount

                if capability_fingerprint is not None:
                    self._used_capabilities.add(
                        capability_fingerprint
                    )

                try:
                    self._persist_locked()

                except SecurityContextError:
                    self.action_count = (
                        old_action_count
                    )
                    self.total_amount = (
                        old_total_amount
                    )
                    self._used_capabilities = (
                        old_used_capabilities
                    )
                    raise

    # =========================================================
    # Record
    # =========================================================

    def record(
        self,
        *,
        request: dict[str, Any],
        capability_fingerprint: Optional[str] = None,
    ) -> None:
        self.authorize_and_record(
            request=request,
            capability_fingerprint=(
                capability_fingerprint
            ),
        )

    # =========================================================
    # Denials
    # =========================================================

    def record_denial(
        self,
    ) -> None:
        with self._lock:
            with self._exclusive_file_lock():
                self._refresh_from_disk_locked()

                old_denial_count = (
                    self.denial_count
                )

                self.denial_count += 1

                try:
                    self._persist_locked()
                except SecurityContextError:
                    self.denial_count = (
                        old_denial_count
                    )
                    raise

    # =========================================================
    # Capability tracking
    # =========================================================

    def has_used_capability(
        self,
        fingerprint: str,
    ) -> bool:
        if not isinstance(
            fingerprint,
            str,
        ):
            raise ValueError(
                "fingerprint must be a string"
            )

        with self._lock:
            return (
                fingerprint
                in self._used_capabilities
            )

    # =========================================================
    # Snapshot
    # =========================================================

    def snapshot(
        self,
    ) -> SecuritySnapshot:
        with self._lock:
            return SecuritySnapshot(
                agent=self.agent,
                action_count=self.action_count,
                total_amount=self.total_amount,
                denial_count=self.denial_count,
                used_capabilities=tuple(
                    sorted(
                        self._used_capabilities
                    )
                ),
            )

    # =========================================================
    # Reset
    # =========================================================

    def reset(
        self,
    ) -> None:
        """
        Reset runtime state while preserving budget
        configuration and persist the reset.

        This widens: a budget that had reached its ceiling denied, and a
        capability already in ``_used_capabilities`` could not be used
        again. Both become permitted again here, so the reset is bracketed
        by the authority epoch and an authorization in flight across it
        refuses. See :mod:`firewall.authority_epoch`.

        The bracket wraps a call rather than the body because the body has
        to run under both this object's lock and its file lock; nesting the
        epoch interval outside them keeps the epoch's own lock a leaf that
        is never held while either of those is acquired.
        """

        with record_widening(self, "security_budget_reset"):
            self._reset_under_locks()

    def _reset_under_locks(
        self,
    ) -> None:
        """The body of :meth:`reset`. Do not call directly.

        Split out only so the epoch bracket can enclose it. Calling this
        instead of ``reset`` performs the same widening without counting
        it, which is what the epoch exists to prevent.
        """

        with self._lock:
            with self._exclusive_file_lock():
                self._refresh_from_disk_locked()

                old_state = (
                    self.action_count,
                    self.total_amount,
                    self.denial_count,
                    set(self._used_capabilities),
                )

                self.action_count = 0
                self.total_amount = 0.0
                self.denial_count = 0
                self._used_capabilities.clear()

                try:
                    self._persist_locked()
                except SecurityContextError:
                    (
                        self.action_count,
                        self.total_amount,
                        self.denial_count,
                        used_capabilities,
                    ) = old_state

                    self._used_capabilities = (
                        used_capabilities
                    )
                    raise

    def close(self) -> None:
        """Compatibility no-op for callers treating contexts as resources."""
        return None
