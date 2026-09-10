"""The Security Replay Laboratory (v1.8).

Turns a recorded artifact into an analyzable history and answers the
central counterfactual question: *what would have happened if the
policy had been different?*

The laboratory reuses the v1.7 simulation machinery rather than
reinventing it. Each recorded authorization decision becomes a
:class:`~firewall.simulation.case.RequestCase` (the material facts of
the capability chain, the request, and the observed decision), and the
v1.7 ``simulate`` engine replays those cases under two rule sets in
isolated throwaway workspaces using the real authorization pipeline.

Every row in a report distinguishes, explicitly and never conflated:

``observed``
    The decision actually recorded in the artifact.

``replayed``
    The decision a fresh workspace reaches under the recorded baseline
    rules. When it matches the observed decision the replay is faithful;
    when it does not, the row is ``unverifiable`` -- the laboratory does
    not stand behind it.

``counterfactual``
    The decision under the proposed rules.

``simulated``
    A decision produced by the replay engine (the counterfactual side).

``unverifiable``
    The case could not be reconstructed or the replay diverged from
    what was observed. Never counted as evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

from firewall.artifact import (
    ArtifactError,
    artifact_from_path,
    validate_manifest,
)
from firewall.recorder.events import EventType, SecurityEvent
from firewall.simulation import (
    MAX_CASES,
    CaseSet,
    DelegationHop,
    RequestCase,
    RuleSet,
    SimulationError,
    simulate,
)

#: Default replay lifetime for cases reconstructed from artifacts. The
#: original expiration is not recorded (it is a validity fact, not a
#: secret); a fresh lifetime keeps the gates honest about time.
DEFAULT_LIFETIME = 3600.0


class ReplayLabError(ValueError):
    """Raised when an artifact cannot be replayed."""


# ----------------------------------------------------------------------
# Case extraction
# ----------------------------------------------------------------------


def extract_cases(
    artifact: dict[str, Any],
    *,
    limit: int = MAX_CASES,
) -> CaseSet:
    """Build replayable cases from the artifact's authorization events.

    Only authorization events with a recorded capability chain and
    request become cases. Everything else is ignored: the laboratory
    reconstructs decisions, not commentary.
    """

    validate_manifest(artifact)

    case_set = CaseSet()

    for entry in artifact.get("events", []):
        if not isinstance(entry, dict):
            continue

        try:
            event = SecurityEvent.from_dict(entry)
        except Exception:
            continue

        if event.type != EventType.AUTHORIZATION:
            continue

        payload = event.payload or {}

        chain = payload.get("chain")
        request = payload.get("request")

        if not isinstance(chain, list) or not chain:
            continue

        if not isinstance(request, dict):
            continue

        root = chain[0]

        if not isinstance(root, dict):
            continue

        root_agent = root.get("agent")
        root_constraints = root.get("constraints") or {}

        hops: list[DelegationHop] = []

        for member in chain[1:]:
            if not isinstance(member, dict):
                continue
            hops.append(
                DelegationHop(
                    delegatee=member.get("agent") or "?",
                    constraints=dict(
                        member.get("constraints") or {}
                    ),
                )
            )

        allowed = payload.get("allowed")
        reason = payload.get("reason")

        try:
            case = RequestCase(
                case_id=f"evt-{event.seq}",
                action=payload.get("action") or "?",
                capability=payload.get("capability") or "?",
                root_agent=root_agent or "?",
                issuer=payload.get("issuer") or "trusted-issuer",
                root_constraints=dict(root_constraints),
                hops=tuple(hops),
                request=dict(request),
                tool=payload.get("tool"),
                lifetime=DEFAULT_LIFETIME,
                baseline_allowed=(
                    allowed
                    if isinstance(allowed, bool)
                    else None
                ),
                baseline_reason=(
                    reason if isinstance(reason, str) else None
                ),
                recorded_at=event.timestamp,
                note=f"recorded from artifact event {event.seq}",
            )
        except SimulationError:
            continue

        case_set.add(case)

        if len(case_set) >= limit:
            break

    return case_set


def baseline_rules(
    artifact: dict[str, Any],
) -> RuleSet:
    """The rule set the artifact was recorded under.

    Trusts exactly the issuers the recorded decisions name (the same
    convention v1.7's CLI uses), with no depth ceiling unless the
    artifact recorded one.
    """

    validate_manifest(artifact)

    issuers: set[str] = set()
    depth: Optional[int] = None

    for entry in artifact.get("events", []):
        if not isinstance(entry, dict):
            continue

        try:
            event = SecurityEvent.from_dict(entry)
        except Exception:
            continue

        payload = event.payload or {}

        if event.type == EventType.AUTHORIZATION:
            issuer = payload.get("issuer")
            if isinstance(issuer, str) and issuer:
                issuers.add(issuer)
        elif event.type == EventType.POLICY_ACTIVE:
            recorded = payload.get("max_delegation_depth")
            if isinstance(recorded, int) and not isinstance(
                recorded, bool
            ):
                depth = recorded

    return RuleSet(
        max_delegation_depth=depth,
        trusted_issuers=issuers or {"trusted-issuer"},
    )


# ----------------------------------------------------------------------
# Counterfactual report
# ----------------------------------------------------------------------


@dataclass(frozen=True)
class CounterfactualRow:
    """One recorded decision and its two replays."""

    seq: int
    agent: str
    action: str
    capability: str

    observed_allowed: Optional[bool]
    observed_reason: Optional[str]

    replayed_allowed: Optional[bool]
    replayed_reason: Optional[str]
    faithful: bool

    counterfactual_allowed: Optional[bool]
    counterfactual_reason: Optional[str]

    classification: str
    changed: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "agent": self.agent,
            "action": self.action,
            "capability": self.capability,
            "observed": {
                "allowed": self.observed_allowed,
                "reason": self.observed_reason,
            },
            "replayed": {
                "allowed": self.replayed_allowed,
                "reason": self.replayed_reason,
                "faithful": self.faithful,
            },
            "counterfactual": {
                "allowed": self.counterfactual_allowed,
                "reason": self.counterfactual_reason,
            },
            "classification": self.classification,
            "changed": self.changed,
        }


@dataclass(frozen=True)
class CounterfactualReport:
    """The full actual-vs-counterfactual comparison."""

    baseline: dict[str, Any]
    proposed: dict[str, Any]
    rows: tuple[CounterfactualRow, ...]
    skipped: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline": dict(self.baseline),
            "proposed": dict(self.proposed),
            "rows": [row.to_dict() for row in self.rows],
            "skipped": self.skipped,
            "summary": self.summary(),
        }

    def to_json(self, *, indent: int = 2) -> str:
        import json

        return json.dumps(
            self.to_dict(),
            indent=indent,
            sort_keys=True,
        )

    def summary(self) -> dict[str, Any]:
        verified = [
            row for row in self.rows
            if row.classification == "verified"
        ]
        counterfactual = [
            row for row in self.rows
            if row.classification == "counterfactual"
        ]
        unverifiable = [
            row for row in self.rows
            if row.classification == "unverifiable"
        ]

        newly_denied = [
            row for row in counterfactual
            if row.observed_allowed
            and not row.counterfactual_allowed
        ]
        newly_allowed = [
            row for row in counterfactual
            if not row.observed_allowed
            and row.counterfactual_allowed
        ]

        return {
            "decisions_recorded": len(self.rows) + self.skipped,
            "decisions_replayed": len(self.rows),
            "verified": len(verified),
            "counterfactual_changes": len(counterfactual),
            "newly_denied": len(newly_denied),
            "newly_allowed": len(newly_allowed),
            "unverifiable": len(unverifiable),
            "skipped": self.skipped,
        }

    def text(self) -> str:
        lines = [
            "counterfactual analysis",
            f"  baseline: {self.baseline}",
            f"  proposed: {self.proposed}",
        ]

        for row in self.rows:
            observed = (
                "ALLOWED"
                if row.observed_allowed
                else "DENIED"
            )
            counterfactual = (
                "ALLOWED"
                if row.counterfactual_allowed
                else "DENIED"
            )

            marker = {
                "counterfactual": "!",
                "unverifiable": "?",
                "verified": " ",
            }.get(row.classification, "?")

            lines.append(
                f"  {marker} event {row.seq}: {row.agent} "
                f"{row.action}: observed {observed}"
                f" ({row.observed_reason}) -> counterfactual "
                f"{counterfactual} ({row.counterfactual_reason})"
                f" [{row.classification}]"
            )

        for key, value in self.summary().items():
            lines.append(f"  {key}: {value}")

        return "\n".join(lines)


# ----------------------------------------------------------------------
# Laboratory
# ----------------------------------------------------------------------


class Laboratory:
    """A replayable, counterfactual view over one artifact."""

    def __init__(
        self,
        artifact: dict[str, Any],
    ) -> None:
        self.artifact = validate_manifest(artifact)
        self.baseline = baseline_rules(self.artifact)
        self.cases = extract_cases(self.artifact)

    @classmethod
    def from_path(
        cls,
        path: str | Path,
    ) -> "Laboratory":
        try:
            return cls(artifact_from_path(path))
        except ArtifactError as exc:
            raise ReplayLabError(str(exc)) from exc

    # ------------------------------------------------------------------
    # Replay
    # ------------------------------------------------------------------

    def replay(
        self,
        proposed: Optional[RuleSet] = None,
        *,
        limit: int = MAX_CASES,
    ) -> CounterfactualReport:
        """Replay the recorded decisions under the proposed rules."""

        after = (
            proposed
            if proposed is not None
            else self.baseline
        )

        if not isinstance(after, RuleSet):
            raise ReplayLabError(
                "proposed rules must be a RuleSet"
            )

        if isinstance(limit, bool) or not isinstance(
            limit, int
        ):
            raise ReplayLabError(
                "limit must be an integer"
            )

        if limit <= 0:
            raise ReplayLabError(
                "limit must be positive"
            )

        ordered = list(self.cases)
        selected = ordered[:limit]
        skipped = len(ordered) - len(selected)

        try:
            report = simulate(
                selected,
                self.baseline,
                after,
                limit=limit,
            )
        except SimulationError as exc:
            raise ReplayLabError(str(exc)) from exc

        by_case = {
            outcome.case_id: outcome
            for outcome in report.outcomes
        }

        rows: list[CounterfactualRow] = []

        for case in selected:
            outcome = by_case.get(case.case_id)

            if outcome is None:
                continue

            seq_text = case.case_id.removeprefix("evt-")
            try:
                seq = int(seq_text)
            except ValueError:
                seq = -1

            observed_allowed = case.baseline_allowed
            observed_reason = case.baseline_reason

            replayed_allowed = outcome.before_allowed
            replayed_reason = outcome.before_reason
            faithful = outcome.faithful and not outcome.error

            counterfactual_allowed = outcome.after_allowed
            counterfactual_reason = outcome.after_reason

            if outcome.error:
                classification = "unverifiable"
            elif (
                observed_allowed is not None
                and observed_reason is not None
                and not faithful
            ):
                # The replay diverged from what was actually observed.
                # Not evidence.
                classification = "unverifiable"
            elif (
                counterfactual_allowed is not None
                and observed_allowed is not None
                and counterfactual_allowed != observed_allowed
            ):
                classification = "counterfactual"
            else:
                classification = "verified"

            changed = (
                observed_allowed is not None
                and counterfactual_allowed is not None
                and observed_allowed != counterfactual_allowed
            )

            rows.append(
                CounterfactualRow(
                    seq=seq,
                    agent=case.agent,
                    action=case.action,
                    capability=case.capability,
                    observed_allowed=observed_allowed,
                    observed_reason=observed_reason,
                    replayed_allowed=replayed_allowed,
                    replayed_reason=replayed_reason,
                    faithful=faithful,
                    counterfactual_allowed=counterfactual_allowed,
                    counterfactual_reason=counterfactual_reason,
                    classification=classification,
                    changed=changed,
                )
            )

        return CounterfactualReport(
            baseline=self.baseline.to_dict(),
            proposed=after.to_dict(),
            rows=tuple(rows),
            skipped=skipped,
        )

    # ------------------------------------------------------------------
    # History
    # ------------------------------------------------------------------

    def history(
        self,
        *,
        limit: int = MAX_CASES,
    ) -> list[dict[str, Any]]:
        """Chronological replay of the recorded decisions."""

        report = self.replay(
            self.baseline,
            limit=limit,
        )

        return [row.to_dict() for row in report.rows]
