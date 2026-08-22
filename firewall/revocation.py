from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Optional
import time


class RevocationError(Exception):
    """Base revocation error."""


class AlreadyRevokedError(RevocationError):
    """Raised when revoking an already-revoked capability."""


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
    In-memory, one-way capability revocation registry.

    A capability fingerprint can be revoked exactly once.
    Revocation cannot be undone.
    """

    def __init__(
        self,
        *,
        clock=None,
    ):
        self._clock = (
            clock
            if clock is not None
            else time.time
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
            return self._records.get(
                fingerprint
            )

    # ========================================================
    # Size
    # ========================================================

    def size(self) -> int:
        with self._lock:
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
            return tuple(
                self._records.values()
            )