from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Optional
import time

from firewall.lifecycle import LifecycleEventType


class RevocationError(Exception):
    """Base revocation error."""


class AlreadyRevokedError(RevocationError):
    """Raised when an already-revoked capability is revoked again."""


class InvalidFingerprintError(RevocationError):
    """Raised for malformed capability fingerprints."""


class RevokedCapabilityError(RevocationError):
    """Raised when an operation requires an active capability."""


@dataclass(frozen=True)
class RevocationRecord:
    fingerprint: str
    revoked_at: float
    reason: str = ""


class RevocationRegistry:
    """
    One-way capability revocation registry.

    Supports:

    - in-memory storage
    - optional persistent backend
    - optional lifecycle recording

    Successful revocation emits exactly one
    LifecycleEventType.REVOKED event.
    """

    def __init__(
        self,
        *,
        clock=None,
        backend=None,
        lifecycle_recorder=None,
    ):
        self._clock = (
            clock
            if clock is not None
            else time.time
        )

        self._backend = backend
        self._lifecycle = (
            lifecycle_recorder
        )

        self._records: dict[
            str,
            RevocationRecord,
        ] = {}

        self._lock = RLock()

    # ========================================================
    # Validation
    # ========================================================

    @staticmethod
    def _validate_fingerprint(
        fingerprint: str,
    ) -> str:
        if not isinstance(
            fingerprint,
            str,
        ):
            raise InvalidFingerprintError(
                "fingerprint must be a string"
            )

        fingerprint = fingerprint.strip()

        if not fingerprint:
            raise InvalidFingerprintError(
                "fingerprint cannot be empty"
            )

        return fingerprint

    # ========================================================
    # Backend conversion
    # ========================================================

    @staticmethod
    def _record_from_backend(
        record,
    ) -> Optional[RevocationRecord]:
        if record is None:
            return None

        fingerprint = getattr(
            record,
            "fingerprint",
            None,
        )

        revoked_at = getattr(
            record,
            "revoked_at",
            None,
        )

        reason = getattr(
            record,
            "reason",
            "",
        )

        if not isinstance(
            fingerprint,
            str,
        ):
            raise RevocationError(
                "backend returned invalid fingerprint"
            )

        if not isinstance(
            revoked_at,
            (int, float),
        ):
            raise RevocationError(
                "backend returned invalid timestamp"
            )

        return RevocationRecord(
            fingerprint=fingerprint,
            revoked_at=float(
                revoked_at
            ),
            reason=str(reason),
        )

    # ========================================================
    # Lifecycle
    # ========================================================

    def _record_lifecycle(
        self,
        record: RevocationRecord,
    ) -> None:
        if self._lifecycle is None:
            return

        self._lifecycle.record(
            LifecycleEventType.REVOKED,
            record.fingerprint,
            reason=record.reason,
            details={
                "revoked": True,
                "revoked_at": record.revoked_at,
            },
        )

    # ========================================================
    # Revoke
    # ========================================================

    def revoke(
        self,
        fingerprint: str,
        *,
        reason: str = "",
    ) -> RevocationRecord:
        fingerprint = self._validate_fingerprint(
            fingerprint
        )

        with self._lock:

            if self._backend is not None:

                try:
                    backend_record = (
                        self._backend.revoke(
                            fingerprint,
                            reason=reason,
                        )
                    )

                except Exception as exc:

                    if (
                        exc.__class__.__name__
                        == "StoreAlreadyRevokedError"
                    ):
                        raise AlreadyRevokedError(
                            "capability is already revoked"
                        ) from exc

                    raise

                record = (
                    self._record_from_backend(
                        backend_record
                    )
                )

                if record is None:
                    raise RevocationError(
                        "backend returned no revocation record"
                    )

                self._record_lifecycle(
                    record
                )

                return record

            if fingerprint in self._records:
                raise AlreadyRevokedError(
                    "capability is already revoked"
                )

            record = RevocationRecord(
                fingerprint=fingerprint,
                revoked_at=float(
                    self._clock()
                ),
                reason=str(reason),
            )

            self._records[
                fingerprint
            ] = record

            self._record_lifecycle(
                record
            )

            return record

    # ========================================================
    # Check
    # ========================================================

    def is_revoked(
        self,
        fingerprint: str,
    ) -> bool:
        fingerprint = self._validate_fingerprint(
            fingerprint
        )

        with self._lock:

            if self._backend is not None:
                return bool(
                    self._backend.is_revoked(
                        fingerprint
                    )
                )

            return (
                fingerprint
                in self._records
            )

    # ========================================================
    # Require active
    # ========================================================

    def require_active(
        self,
        fingerprint: str,
    ) -> None:
        if self.is_revoked(
            fingerprint
        ):
            raise RevokedCapabilityError(
                "capability is revoked"
            )

    # ========================================================
    # Lookup
    # ========================================================

    def get(
        self,
        fingerprint: str,
    ) -> Optional[
        RevocationRecord
    ]:
        fingerprint = self._validate_fingerprint(
            fingerprint
        )

        with self._lock:

            if self._backend is not None:
                return self._record_from_backend(
                    self._backend.get(
                        fingerprint
                    )
                )

            return self._records.get(
                fingerprint
            )

    # ========================================================
    # Size
    # ========================================================

    def size(self) -> int:
        with self._lock:

            if self._backend is not None:
                return int(
                    self._backend.size()
                )

            return len(
                self._records
            )

    # ========================================================
    # Snapshot
    # ========================================================

    def records(
        self,
    ) -> tuple[
        RevocationRecord,
        ...,
    ]:
        with self._lock:

            if self._backend is not None:

                backend_records = (
                    self._backend.records()
                )

                return tuple(
                    self._record_from_backend(
                        record
                    )
                    for record
                    in backend_records
                )

            return tuple(
                self._records.values()
            )

    # ========================================================
    # Backend
    # ========================================================

    @property
    def backend(self):
        return self._backend

    # ========================================================
    # Lifecycle recorder
    # ========================================================

    @property
    def lifecycle_recorder(self):
        return self._lifecycle