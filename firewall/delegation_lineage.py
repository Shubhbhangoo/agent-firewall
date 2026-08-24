from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Optional


class DelegationLineageError(Exception):
    """Base delegation-lineage error."""


class LineageCycleError(DelegationLineageError):
    """Raised when a delegation lineage cycle is detected."""


@dataclass(frozen=True)
class LineageRecord:
    child_fingerprint: str
    parent_fingerprint: str


class DelegationLineage:
    """
    Runtime registry mapping delegated capabilities to their
    direct parent capability fingerprints.

    The registry tracks:

        child -> parent -> ancestor

    Revocation remains owned by the SDK's revocation registry.
    """

    def __init__(
        self,
        *,
        max_depth: int = 64,
    ) -> None:
        if (
            not isinstance(max_depth, int)
            or isinstance(max_depth, bool)
            or max_depth <= 0
        ):
            raise ValueError(
                "max_depth must be a positive integer"
            )

        self.max_depth = max_depth

        self._parents: dict[str, str] = {}

        self._lock = threading.RLock()

    @staticmethod
    def _validate_fingerprint(
        value: str,
        name: str,
    ) -> None:
        if (
            not isinstance(value, str)
            or not value
        ):
            raise ValueError(
                f"{name} must be a non-empty string"
            )

    def register(
        self,
        *,
        child_fingerprint: str,
        parent_fingerprint: str,
    ) -> None:
        self._validate_fingerprint(
            child_fingerprint,
            "child_fingerprint",
        )

        self._validate_fingerprint(
            parent_fingerprint,
            "parent_fingerprint",
        )

        if child_fingerprint == parent_fingerprint:
            raise LineageCycleError(
                "child and parent fingerprints must differ"
            )

        with self._lock:
            existing = self._parents.get(
                child_fingerprint
            )

            if (
                existing is not None
                and existing != parent_fingerprint
            ):
                raise DelegationLineageError(
                    "child fingerprint already has "
                    "a different parent"
                )

            current = parent_fingerprint
            visited: set[str] = {
                child_fingerprint
            }

            depth = 0

            while current in self._parents:
                if current in visited:
                    raise LineageCycleError(
                        "delegation lineage cycle detected"
                    )

                visited.add(current)

                current = self._parents[
                    current
                ]

                depth += 1

                if depth > self.max_depth:
                    raise DelegationLineageError(
                        "delegation lineage exceeds maximum depth"
                    )

            self._parents[
                child_fingerprint
            ] = parent_fingerprint

    def parent_of(
        self,
        child_fingerprint: str,
    ) -> Optional[str]:
        self._validate_fingerprint(
            child_fingerprint,
            "child_fingerprint",
        )

        with self._lock:
            return self._parents.get(
                child_fingerprint
            )

    def chain(
        self,
        fingerprint: str,
    ) -> tuple[str, ...]:
        """
        Return direct parent first, followed by ancestors.

        child -> parent -> root

        returns:

            ("parent", "root")
        """

        self._validate_fingerprint(
            fingerprint,
            "fingerprint",
        )

        with self._lock:
            result: list[str] = []

            current = fingerprint
            visited: set[str] = {
                fingerprint
            }

            while current in self._parents:
                parent = self._parents[
                    current
                ]

                if parent in visited:
                    raise LineageCycleError(
                        "delegation lineage cycle detected"
                    )

                visited.add(parent)

                result.append(parent)

                current = parent

                if len(result) > self.max_depth:
                    raise DelegationLineageError(
                        "delegation lineage exceeds maximum depth"
                    )

            return tuple(result)

    def is_descendant_of(
        self,
        *,
        child_fingerprint: str,
        ancestor_fingerprint: str,
    ) -> bool:
        self._validate_fingerprint(
            child_fingerprint,
            "child_fingerprint",
        )

        self._validate_fingerprint(
            ancestor_fingerprint,
            "ancestor_fingerprint",
        )

        if child_fingerprint == ancestor_fingerprint:
            return False

        return (
            ancestor_fingerprint
            in self.chain(
                child_fingerprint
            )
        )

    def snapshot(
        self,
    ) -> tuple[LineageRecord, ...]:
        with self._lock:
            return tuple(
                LineageRecord(
                    child_fingerprint=child,
                    parent_fingerprint=parent,
                )
                for child, parent in sorted(
                    self._parents.items()
                )
            )

    def clear(
        self,
    ) -> None:
        with self._lock:
            self._parents.clear()