"""Result types for the v2.2 machine-checkable security invariants.

The important design decision is the three-valued status. A check that
cannot reach the thing it is supposed to check does **not** report
success -- it reports :data:`InvariantStatus.UNVERIFIABLE`, and
:attr:`InvariantReport.holds` is false whenever any invariant is
unverifiable. "Unknown is not trusted" applies to the checker itself:
an invariant suite that silently passes when its evidence is missing is
worse than no suite, because it converts absent verification into a
positive claim.

Nothing in this module -- or anywhere else in
:mod:`firewall.invariants` -- can grant authority. The package reads
source text and live state and reports findings. It never constructs an
``AuthorizationResult``, and the AUTHORIZATION_UNIQUENESS invariant it
ships would flag it if it tried.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class InvariantStatus(str, Enum):
    """Outcome of one invariant check.

    ``UNVERIFIABLE`` is deliberately distinct from both ``HOLDS`` and
    ``VIOLATED``. It means the check ran but could not establish the
    property -- a source file that would not parse, a subsystem that is
    not wired, a live check with no state to inspect. Treating that as
    ``HOLDS`` would be the fail-open bug this package exists to catch.
    """

    HOLDS = "holds"
    VIOLATED = "violated"
    UNVERIFIABLE = "unverifiable"


class InvariantViolation(AssertionError):
    """Raised by :func:`firewall.invariants.assert_all` on any failure.

    Subclasses ``AssertionError`` so it reads naturally in a test, but
    carries the full report so a caller can inspect every finding rather
    than only the message.
    """

    def __init__(self, message: str, report: "InvariantReport"):
        super().__init__(message)
        self.report = report


@dataclass(frozen=True)
class InvariantResult:
    """The outcome of one named invariant.

    ``findings`` lists concrete, individually actionable evidence -- a
    file and line, a capability fingerprint, a probe that returned the
    wrong verdict. A ``VIOLATED`` result with no findings would be an
    assertion the caller cannot act on, so
    :meth:`InvariantReport.summary` reports the count.
    """

    name: str
    status: InvariantStatus
    reason: str
    findings: tuple[str, ...] = ()
    details: dict[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:
        """True only for ``HOLDS``.

        Explicit, because the natural mistake is ``if not result.violated``
        which quietly accepts ``UNVERIFIABLE``.
        """

        return self.status is InvariantStatus.HOLDS

    @property
    def holds(self) -> bool:
        return self.status is InvariantStatus.HOLDS

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "reason": self.reason,
            "findings": list(self.findings),
            "details": dict(self.details),
        }


def holds(
    name: str,
    reason: str,
    **details: Any,
) -> InvariantResult:
    return InvariantResult(
        name=name,
        status=InvariantStatus.HOLDS,
        reason=reason,
        details=details,
    )


def violated(
    name: str,
    reason: str,
    findings: tuple[str, ...] = (),
    **details: Any,
) -> InvariantResult:
    return InvariantResult(
        name=name,
        status=InvariantStatus.VIOLATED,
        reason=reason,
        findings=findings,
        details=details,
    )


def unverifiable(
    name: str,
    reason: str,
    findings: tuple[str, ...] = (),
    **details: Any,
) -> InvariantResult:
    return InvariantResult(
        name=name,
        status=InvariantStatus.UNVERIFIABLE,
        reason=reason,
        findings=findings,
        details=details,
    )


@dataclass(frozen=True)
class InvariantReport:
    """Every invariant result from one :func:`check_all` run."""

    results: tuple[InvariantResult, ...]
    checked_at: float

    def __bool__(self) -> bool:
        return self.holds

    @property
    def holds(self) -> bool:
        """True only when every invariant reports ``HOLDS``.

        An unverifiable invariant makes the whole report false. The
        report is a claim about the system; it cannot be true while part
        of the system is unexamined.
        """

        return all(
            item.status is InvariantStatus.HOLDS
            for item in self.results
        )

    @property
    def violations(self) -> tuple[InvariantResult, ...]:
        return tuple(
            item
            for item in self.results
            if item.status is InvariantStatus.VIOLATED
        )

    @property
    def unverifiable(self) -> tuple[InvariantResult, ...]:
        return tuple(
            item
            for item in self.results
            if item.status is InvariantStatus.UNVERIFIABLE
        )

    def get(self, name: str) -> Optional[InvariantResult]:
        for item in self.results:
            if item.name == name:
                return item
        return None

    def summary(self) -> str:
        """One line per non-holding invariant, plus a count line.

        Violations first: an unverifiable invariant might be a wiring
        gap, but a violated one is a security defect.
        """

        lines = [
            f"{len(self.results)} invariants: "
            f"{len(self.results) - len(self.violations) - len(self.unverifiable)}"
            f" holds, {len(self.violations)} violated, "
            f"{len(self.unverifiable)} unverifiable"
        ]

        for item in self.violations + self.unverifiable:
            lines.append(
                f"  [{item.status.value}] {item.name}: {item.reason}"
            )
            for finding in item.findings[:20]:
                lines.append(f"      - {finding}")
            if len(item.findings) > 20:
                lines.append(
                    f"      ... and {len(item.findings) - 20} more"
                )

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "holds": self.holds,
            "checked_at": self.checked_at,
            "results": [item.to_dict() for item in self.results],
        }

