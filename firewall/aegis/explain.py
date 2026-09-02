"""Explaining an adaptive action from structured state.

§17 sets out six questions every adaptive action must answer:

    What changed?
    What evidence established the change?
    What authority was affected?
    What rule required narrowing?
    What authority remains?
    What could not be established?

They are the six fields of :class:`Explanation`, in that order, and each
one is populated from a structured record that already exists -- a
:class:`~firewall.aegis.response.Classification`'s contributions, a
:class:`~firewall.aegis.restriction.Restriction`, an
:class:`~firewall.aegis.state.AegisGrant`'s transition history, an
:class:`~firewall.aegis.envelope.AuthorityEnvelope`, a
:class:`~firewall.aegis.blast.BlastRadius`'s unanalyzable entries. Nothing
here generates prose about the system's reasoning; it reports the
reasoning's inputs. There is no model in this module, and no string in it
that was not either typed by a developer or read out of a dataclass.

The sixth question is the one that is easy to skip
--------------------------------------------------

"What could not be established" is the field that makes the other five
honest. An explanation that lists four confident findings and omits that
the blast-radius traversal hit its node cap is a misleading explanation,
and :meth:`Explanation.complete` exists so a caller can tell the
difference. It is deliberately not defaulted to empty: the builder
collects gaps from every source it is given, and a source it was not given
is itself recorded as a gap.

Relationship to ``firewall/explain.py``
---------------------------------------

``firewall.explain`` explains a *capability's lifecycle* -- what happened
to a credential. This explains an *adaptive action* -- why Aegis narrowed,
suspended or revalidated. Different subjects, so not a competing
representation; :attr:`Explanation.lifecycle` carries the former when a
caller has it, rather than restating it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Optional

from firewall.aegis.blast import BlastRadius
from firewall.aegis.preflight import Preflight, StageStatus
from firewall.aegis.response import Classification
from firewall.aegis.restriction import Restriction
from firewall.aegis.state import AegisGrant


@dataclass(frozen=True)
class Explanation:
    """The six §17 answers, derived and nothing else."""

    #: What changed.
    changes: tuple[str, ...] = ()
    #: What established it. Each entry names a rule or a record.
    evidence: tuple[str, ...] = ()
    #: What authority was affected -- fingerprints, and how.
    affected: tuple[str, ...] = ()
    #: Which rule required the action.
    rules: tuple[str, ...] = ()
    #: What authority remains, read off the envelope.
    remaining: tuple[str, ...] = ()
    #: What could not be established.
    gaps: tuple[str, ...] = ()
    #: The action being explained, e.g. ``"narrow"``.
    action: Optional[str] = None
    #: A lifecycle explanation, when the caller has one.
    lifecycle: Optional[Any] = None
    details: Mapping[str, Any] = field(default_factory=dict)

    @property
    def complete(self) -> bool:
        """Was everything the explanation touched establishable?"""

        return not self.gaps

    def describe(self) -> dict:
        return {
            "action": self.action,
            "what_changed": list(self.changes),
            "what_evidence_established_the_change": list(self.evidence),
            "what_authority_was_affected": list(self.affected),
            "what_rule_required_the_action": list(self.rules),
            "what_authority_remains": list(self.remaining),
            "what_could_not_be_established": list(self.gaps),
            "complete": self.complete,
            "lifecycle": (
                None
                if self.lifecycle is None
                else getattr(self.lifecycle, "describe", lambda: None)()
                or getattr(self.lifecycle, "to_dict", lambda: None)()
            ),
            "details": dict(self.details),
        }

    def render(self) -> str:
        """Plain text, for an operator reading a terminal.

        Sections appear in §17's order and an empty section still appears,
        marked. A section silently omitted because it was empty is how an
        explanation ends up implying more confidence than it has.
        """

        sections = (
            ("What changed", self.changes),
            ("What evidence established the change", self.evidence),
            ("What authority was affected", self.affected),
            ("What rule required the action", self.rules),
            ("What authority remains", self.remaining),
            ("What could not be established", self.gaps),
        )

        lines: list[str] = []

        if self.action:
            lines.append(f"Aegis action: {self.action}")
            lines.append("")

        for title, entries in sections:
            lines.append(f"{title}:")

            if entries:
                lines.extend(f"  - {entry}" for entry in entries)
            else:
                lines.append("  (nothing recorded)")

            lines.append("")

        return "\n".join(lines).rstrip() + "\n"
def _envelope_summary(envelope: Any) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """``(remaining, gaps)`` read off an authority envelope."""

    if envelope is None:
        return (), ("no authority envelope was supplied, so what remains is unstated",)

    describe = getattr(envelope, "describe", None)

    if not callable(describe):
        return (), (
            f"{type(envelope).__name__} is not an authority envelope, so what "
            f"remains could not be read",
        )

    try:
        shape = describe()
    except Exception as error:  # noqa: BLE001 - reported, never raised
        return (), (f"{type(error).__name__} reading the authority envelope",)

    if not isinstance(shape, Mapping):
        return (), ("the envelope description is not readable",)

    if shape.get("bottom"):
        reasons = shape.get("reasons") or ()
        return (
            ("no authority remains: the envelope is empty",),
            tuple(f"envelope is empty because {reason}" for reason in reasons),
        )

    remaining: list[str] = []

    patterns = shape.get("patterns") or ()

    if patterns:
        remaining.append("actions matching " + ", ".join(map(str, patterns)))

    tool = shape.get("tool")

    if tool:
        remaining.append(f"bound to tool {tool}")

    window = shape.get("window")

    if isinstance(window, (list, tuple)) and len(window) == 2:
        remaining.append(f"valid from {window[0]} until {window[1]}")

    constraints = shape.get("constraints")

    if isinstance(constraints, Mapping):
        for label, key in (
            ("ceiling", "ceilings"),
            ("floor", "floors"),
            ("exact", "exact"),
        ):
            values = constraints.get(key)

            if isinstance(values, Mapping) and values:
                remaining.extend(
                    f"{name} {label} {value}" for name, value in sorted(
                        values.items(), key=lambda item: str(item[0])
                    )
                )

        enumerations = constraints.get("enumerations")

        if isinstance(enumerations, Mapping):
            for name, values in sorted(
                enumerations.items(), key=lambda item: str(item[0])
            ):
                remaining.append(f"{name} limited to {list(values)}")

        opaque = constraints.get("opaque")

        if opaque:
            remaining.append(
                f"{len(opaque)} constraint fragment(s) the boundary evaluates "
                f"exactly but the envelope does not summarise"
            )

    depth = shape.get("depth")
    ceiling = shape.get("depth_ceiling")

    if depth is not None:
        remaining.append(
            f"delegation depth {depth}"
            + ("" if ceiling is None else f" of at most {ceiling}")
        )

    budget = shape.get("budget")

    if isinstance(budget, Mapping):
        if budget.get("readable") is False:
            return tuple(remaining), (
                "the delegation budget could not be read, so remaining budget "
                "is unknown",
            )

        for name in ("remaining_actions", "remaining_amount"):
            value = budget.get(name)

            if value is not None:
                remaining.append(f"{name.replace('_', ' ')} {value}")

    if not remaining:
        return (
            ("the envelope imposes no summarisable bound",),
            (
                "no bound could be summarised, which is not the same as no "
                "bound existing: opaque constraint fragments are evaluated by "
                "the boundary and not shown here",
            ),
        )

    return tuple(remaining), ()
def explain(
    *,
    action: Optional[str] = None,
    classification: Optional[Classification] = None,
    restriction: Optional[Restriction] = None,
    restrictions: Iterable[Restriction] = (),
    grant: Optional[AegisGrant] = None,
    envelope: Any = None,
    blast: Optional[BlastRadius] = None,
    preflight: Optional[Preflight] = None,
    lifecycle: Any = None,
    extra_gaps: Iterable[str] = (),
) -> Explanation:
    """Build an :class:`Explanation` from whatever structured state exists.

    Total: every argument is optional and an absent one becomes a recorded
    gap rather than a silent omission. Never raises, because an
    explanation that fails to render would leave an enforced restriction
    unexplained -- and §17 requires the reverse.
    """

    changes: list[str] = []
    evidence: list[str] = []
    affected: list[str] = []
    rules: list[str] = []
    gaps: list[str] = []

    resolved_action = action

    # -- what changed, and which rule required the action ---------------

    if classification is None:
        gaps.append(
            "no change classification was supplied, so what changed is unstated"
        )
    else:
        if resolved_action is None:
            resolved_action = classification.response.value

        if classification.trigger:
            changes.append(f"trigger: {classification.trigger}")

        if classification.state_changed is True:
            changes.append("the security-state hash changed across the event")
        elif classification.state_changed is False:
            changes.append("the security-state hash did not change")
        else:
            gaps.append(
                "the two snapshots could not be compared, so whether the "
                "security state changed is unknown"
            )

        for contribution in classification.contributions:
            changes.append(contribution.detail)
            rules.append(f"{contribution.rule} -> {contribution.response.value}")
            evidence.append(
                f"rule {contribution.rule} read structured state and returned "
                f"{contribution.response.value}"
            )

        for degraded in classification.degraded:
            gaps.append(f"security dependency {degraded} could not be read")

    # -- what authority was affected ------------------------------------

    applied = tuple(restrictions)

    if restriction is not None:
        applied = (restriction,) + tuple(
            item for item in applied if item is not restriction
        )

    for item in applied:
        if item.suspends:
            affected.append(
                f"{item.fingerprint}: suspended under key {item.key} "
                f"({item.reason})"
            )
        else:
            detail = []

            if item.constraints:
                detail.append(f"constraints {dict(item.constraints)}")

            if item.patterns:
                detail.append(f"actions limited to {list(item.patterns)}")

            affected.append(
                f"{item.fingerprint}: narrowed under key {item.key} to "
                + "; ".join(detail)
                + f" ({item.reason})"
            )

        if item.trigger:
            evidence.append(
                f"restriction {item.key} records trigger {item.trigger}"
            )

    if grant is not None:
        affected.append(
            f"{grant.fingerprint}: Aegis state {grant.state.value} "
            f"(residual authority {grant.residual})"
        )

        for transition in grant.history:
            evidence.append(
                f"transition {transition.from_state.value} -> "
                f"{transition.to_state.value} at {transition.at} "
                f"({transition.reason})"
                + (
                    ""
                    if transition.evidence is None
                    else f", backed by a canonical allow for "
                    f"{transition.evidence}"
                )
            )
    elif not applied:
        gaps.append(
            "no grant or restriction was supplied, so the affected authority "
            "is unstated"
        )

    # -- what authority remains -----------------------------------------
    #
    # The envelope describes the *capability's* bounds. Active
    # restrictions subtract further, so reporting the envelope alone would
    # answer §17's fifth question with more authority than actually
    # remains -- the single most misleading thing this function could do.

    remaining, envelope_gaps = _envelope_summary(envelope)
    gaps.extend(envelope_gaps)

    if any(item.suspends for item in applied):
        suspending = ", ".join(
            item.key for item in applied if item.suspends
        )
        remaining = (
            f"no authority remains: suspended by {suspending}",
        ) + remaining
    else:
        for item in applied:
            limits = []

            if item.constraints:
                limits.extend(
                    f"{name} further limited to {value}"
                    for name, value in sorted(
                        item.constraints.items(), key=lambda entry: str(entry[0])
                    )
                )

            if item.patterns:
                limits.append(
                    "actions further limited to " + ", ".join(item.patterns)
                )

            remaining = remaining + tuple(
                f"{limit} (restriction {item.key})" for limit in limits
            )

    # -- what could not be established ----------------------------------

    if blast is not None:
        for item in blast.unanalyzable:
            gaps.append(
                f"blast radius: {item.kind} -- {item.detail}"
                + ("" if item.at is None else f" (at {item.at})")
            )

    if preflight is not None:
        for stage in preflight.stages:
            if stage.status is StageStatus.UNAVAILABLE:
                gaps.append(f"preflight stage {stage.name}: {stage.detail}")

        evidence.append(
            f"preflight impact {preflight.impact.value}, recommendation "
            f"{preflight.recommendation.value}"
        )

    gaps.extend(str(item) for item in extra_gaps)

    return Explanation(
        changes=tuple(changes),
        evidence=tuple(evidence),
        affected=tuple(affected),
        rules=tuple(rules),
        remaining=remaining,
        gaps=tuple(gaps),
        action=resolved_action,
        lifecycle=lifecycle,
        details={
            "sources": {
                "classification": classification is not None,
                "restrictions": len(applied),
                "grant": grant is not None,
                "envelope": envelope is not None,
                "blast": blast is not None,
                "preflight": preflight is not None,
            }
        },
    )
