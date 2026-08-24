from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from typing import Any, Optional


class RefusalStateError(Exception):
    """Base refusal-state error."""


@dataclass(frozen=True)
class RefusalKey:
    agent: str
    capability_fingerprint: str
    action: str
    request_fingerprint: str

    def as_tuple(self) -> tuple[str, str, str, str]:
        return (
            self.agent,
            self.capability_fingerprint,
            self.action,
            self.request_fingerprint,
        )


@dataclass(frozen=True)
class RefusalRecord:
    key: RefusalKey
    reason: str


class RefusalState:
    """
    Tracks specific refused request intents.

    Refusal scope:

        agent
        capability fingerprint
        action
        request fingerprint

    This prevents a fresh nonce from bypassing a refusal for
    the same exact request intent while allowing a changed
    request to be evaluated normally.
    """

    def __init__(self) -> None:
        self._refusals: dict[
            RefusalKey,
            str,
        ] = {}

        self._lock = threading.RLock()

    @staticmethod
    def _validate(
        value: str,
        name: str,
    ) -> None:
        if (
            not isinstance(value, str)
            or not value.strip()
        ):
            raise ValueError(
                f"{name} must be a non-empty string"
            )

    @staticmethod
    def fingerprint_request(
        request: dict[str, Any],
    ) -> str:
        if not isinstance(
            request,
            dict,
        ):
            raise ValueError(
                "request must be a dictionary"
            )

        try:
            payload = json.dumps(
                request,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
        except (
            TypeError,
            ValueError,
        ) as exc:
            raise RefusalStateError(
                "request is not deterministically serializable"
            ) from exc

        return hashlib.sha256(
            payload.encode("utf-8")
        ).hexdigest()

    def _make_key(
        self,
        *,
        agent: str,
        capability_fingerprint: str,
        action: str,
        request: dict[str, Any],
    ) -> RefusalKey:
        self._validate(
            agent,
            "agent",
        )

        self._validate(
            capability_fingerprint,
            "capability_fingerprint",
        )

        self._validate(
            action,
            "action",
        )

        return RefusalKey(
            agent=agent,
            capability_fingerprint=(
                capability_fingerprint
            ),
            action=action,
            request_fingerprint=(
                self.fingerprint_request(
                    request
                )
            ),
        )

    def record(
        self,
        *,
        agent: str,
        capability_fingerprint: str,
        action: str,
        request: dict[str, Any],
        reason: str,
    ) -> None:
        self._validate(
            reason,
            "reason",
        )

        key = self._make_key(
            agent=agent,
            capability_fingerprint=(
                capability_fingerprint
            ),
            action=action,
            request=request,
        )

        with self._lock:
            self._refusals[key] = reason

    def is_refused(
        self,
        *,
        agent: str,
        capability_fingerprint: str,
        action: str,
        request: dict[str, Any],
    ) -> bool:
        key = self._make_key(
            agent=agent,
            capability_fingerprint=(
                capability_fingerprint
            ),
            action=action,
            request=request,
        )

        with self._lock:
            return key in self._refusals

    def reason(
        self,
        *,
        agent: str,
        capability_fingerprint: str,
        action: str,
        request: dict[str, Any],
    ) -> Optional[str]:
        key = self._make_key(
            agent=agent,
            capability_fingerprint=(
                capability_fingerprint
            ),
            action=action,
            request=request,
        )

        with self._lock:
            return self._refusals.get(
                key
            )

    def check(
        self,
        *,
        agent: str,
        capability_fingerprint: str,
        action: str,
        request: dict[str, Any],
    ) -> Optional[RefusalRecord]:
        key = self._make_key(
            agent=agent,
            capability_fingerprint=(
                capability_fingerprint
            ),
            action=action,
            request=request,
        )

        with self._lock:
            reason = self._refusals.get(
                key
            )

            if reason is None:
                return None

            return RefusalRecord(
                key=key,
                reason=reason,
            )

    def check_action(
        self,
        *,
        agent: str,
        capability_fingerprint: str,
        action: str,
    ) -> Optional[RefusalRecord]:
        self._validate(
            agent,
            "agent",
        )

        self._validate(
            capability_fingerprint,
            "capability_fingerprint",
        )

        self._validate(
            action,
            "action",
        )

        with self._lock:
            for key, reason in self._refusals.items():
                if (
                    key.agent == agent
                    and key.capability_fingerprint
                    == capability_fingerprint
                    and key.action == action
                ):
                    return RefusalRecord(
                        key=key,
                        reason=reason,
                    )

            return None

    def clear(
        self,
        *,
        agent: str,
        capability_fingerprint: str,
        action: str,
        request: dict[str, Any],
    ) -> bool:
        key = self._make_key(
            agent=agent,
            capability_fingerprint=(
                capability_fingerprint
            ),
            action=action,
            request=request,
        )

        with self._lock:
            return (
                self._refusals.pop(
                    key,
                    None,
                )
                is not None
            )

    def snapshot(
        self,
    ) -> tuple[RefusalRecord, ...]:
        with self._lock:
            return tuple(
                RefusalRecord(
                    key=key,
                    reason=reason,
                )
                for key, reason in sorted(
                    self._refusals.items(),
                    key=lambda item: (
                        item[0].agent,
                        item[0].capability_fingerprint,
                        item[0].action,
                        item[0].request_fingerprint,
                    ),
                )
            )

    def size(self) -> int:
        with self._lock:
            return len(
                self._refusals
            )

    def clear_all(self) -> None:
        with self._lock:
            self._refusals.clear()
