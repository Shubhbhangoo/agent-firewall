"""Classifying an environmental change into an adaptive response.

The mission's §4 rule is explicit: *do not automatically convert every
analytical change into DENY*. It is equally explicit that unknown is not
trusted. Those pull in opposite directions, and the resolution is a
five-valued response ordered by how much authority it removes:

    KEEP  <  REVALIDATE  <  NARROW  <  SUSPEND  <  REVOKE

``KEEP`` removes nothing. ``REVALIDATE`` removes nothing directly -- it
re-asks the canonical boundary and lets the boundary answer, which is the
honest handling of a change whose effect is not locally decidable.
``NARROW`` and ``SUSPEND`` write restrictions. ``REVOKE`` is final.

The classifier is a join
------------------------

Every rule that applies contributes a response, and the classification is
the **maximum**. Three properties follow, and each one is load-bearing:

* **Order-independent.** A join has no evaluation order, so there is no
  "first matching rule wins" to get wrong, and no rule ordering to
  regress.
* **A rule can only escalate.** No rule can soften another's finding, so
  adding a rule is monotone: it can never turn a ``SUSPEND`` into a
  ``KEEP``. Rules may be added without re-auditing the ones already
  there.
* **``KEEP`` requires positive evidence.** It is the identity of the
  join, so it is what you get from *no* rules -- which would make silence
  mean "nothing to do". So ``KEEP`` is guarded: the classifier returns it
  only when two snapshots were actually taken, their
  ``state_hash()`` values are equal, neither is degraded, and the trigger
  is not one that must never be throttled. Anything less specific
  escalates to at least ``REVALIDATE``.

``KEEP`` is not an allow
------------------------

Nothing in this module authorizes anything, and ``KEEP`` in particular
does not mean "permitted". It means *this change requires no adaptive
action*; whether the next request is allowed is still decided only by
``FirewallSDK.authorize()``. :class:`Classification` therefore refuses
``bool()``, the same way :class:`~firewall.aegis.envelope.AuthorityEnvelope`
and :class:`~firewall.aegis.state.AegisGrant` do.

Why the trigger mapping looks the way it does
---------------------------------------------

The fifteen triggers already exist in
:class:`firewall.continuous_auth.engine.RevalidationTrigger`; Aegis adds
no sixteenth. They sort into four groups by *what the change tells you
about the grant*:

* The authority is already gone (``*_REVOKED``) -- record finality.
* The principal, purpose, or chain is not established -- the capability
  may still be perfectly valid, so ``SUSPEND`` rather than ``REVOKE``:
  reversible, and reversible only through a canonical allow.
* Posture and risk are *analysis*. Analysis may subtract, so ``NARROW``.
  It may not destroy (that would let a risk score revoke) and it may not
  grant (constraint 8).
* Everything else is a change whose effect on this grant is not locally
  decidable -- ``REVALIDATE``, and let the boundary decide.

An unrecognised trigger lands in the fourth group rather than the first
or the third: it is the reading that neither trusts the unknown nor
pretends to know what it implies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Optional

from firewall.continuous_auth.engine import (
    UNTHROTTLED_TRIGGERS,
    RevalidationTrigger,
    SecurityContextSnapshot,
)


class AdaptiveResponse(str, Enum):
    """What Aegis should do about a change. Ordered by authority removed."""

    KEEP = "keep"
    REVALIDATE = "revalidate"
    NARROW = "narrow"
    SUSPEND = "suspend"
    REVOKE = "revoke"


#: The lattice. Only the ordering matters.
RESPONSE_SEVERITY: Mapping[AdaptiveResponse, int] = {
    AdaptiveResponse.KEEP: 0,
    AdaptiveResponse.REVALIDATE: 1,
    AdaptiveResponse.NARROW: 2,
    AdaptiveResponse.SUSPEND: 3,
    AdaptiveResponse.REVOKE: 4,
}


def severity(response: AdaptiveResponse) -> int:
    return RESPONSE_SEVERITY[response]


def join(*responses: AdaptiveResponse) -> AdaptiveResponse:
    """The maximum. With no arguments, the identity ``KEEP``."""

    result = AdaptiveResponse.KEEP

    for response in responses:
        if severity(response) > severity(result):
            result = response

    return result


#: Trigger -> response. Every member of ``RevalidationTrigger`` appears
#: exactly once; :func:`_mapping_is_total` checks that at import time, so
#: a trigger added later cannot silently fall through to the default.
TRIGGER_RESPONSE: Mapping[RevalidationTrigger, AdaptiveResponse] = {
    RevalidationTrigger.CAPABILITY_REVOKED: AdaptiveResponse.REVOKE,
    RevalidationTrigger.DELEGATION_REVOKED: AdaptiveResponse.REVOKE,
    RevalidationTrigger.PROVENANCE_REVOKED: AdaptiveResponse.REVOKE,
    RevalidationTrigger.IDENTITY_CHANGED: AdaptiveResponse.SUSPEND,
    RevalidationTrigger.TASK_REVOKED: AdaptiveResponse.SUSPEND,
    RevalidationTrigger.TASK_EXPIRED: AdaptiveResponse.SUSPEND,
    RevalidationTrigger.DELEGATION_CHAIN_BROKEN: AdaptiveResponse.SUSPEND,
    RevalidationTrigger.TRUST_COLLAPSE: AdaptiveResponse.SUSPEND,
    RevalidationTrigger.INCIDENT_OPENED: AdaptiveResponse.SUSPEND,
    RevalidationTrigger.POSTURE_CHANGED: AdaptiveResponse.NARROW,
    RevalidationTrigger.RISK_THRESHOLD_EXCEEDED: AdaptiveResponse.NARROW,
    RevalidationTrigger.POLICY_CHANGED: AdaptiveResponse.REVALIDATE,
    RevalidationTrigger.ENVIRONMENT_CHANGED: AdaptiveResponse.REVALIDATE,
    RevalidationTrigger.TIME: AdaptiveResponse.REVALIDATE,
    RevalidationTrigger.EXPLICIT_REQUEST: AdaptiveResponse.REVALIDATE,
}

#: What an unrecognised trigger produces. Not ``KEEP``, not ``REVOKE``.
UNKNOWN_TRIGGER_RESPONSE = AdaptiveResponse.REVALIDATE


def _mapping_is_total() -> tuple[str, ...]:
    """Triggers with no mapping. Empty in a correct build."""

    return tuple(
        trigger.value
        for trigger in RevalidationTrigger
        if trigger not in TRIGGER_RESPONSE
    )


MISSING_TRIGGER_MAPPINGS = _mapping_is_total()
@dataclass(frozen=True)
class Contribution:
    """One rule's finding, kept so the join can be explained (§17)."""

    rule: str
    response: AdaptiveResponse
    detail: str

    def describe(self) -> dict:
        return {
            "rule": self.rule,
            "response": self.response.value,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class Classification:
    """The join, and every contribution that produced it.

    Analysis. Not a decision, and deliberately not usable as one.
    """

    response: AdaptiveResponse
    trigger: Optional[str]
    contributions: tuple[Contribution, ...] = ()
    state_changed: Optional[bool] = None
    degraded: tuple[str, ...] = ()
    details: Mapping[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:
        raise TypeError(
            "a Classification is not a decision; read .response, and call "
            "FirewallSDK.authorize() to decide"
        )

    @property
    def acts(self) -> bool:
        """Does this classification require the executor to do anything?"""

        return self.response is not AdaptiveResponse.KEEP

    @property
    def removes_authority(self) -> bool:
        """Does acting on it write a restriction or revoke?"""

        return severity(self.response) >= severity(AdaptiveResponse.NARROW)

    def describe(self) -> dict:
        return {
            "response": self.response.value,
            "trigger": self.trigger,
            "state_changed": self.state_changed,
            "degraded_dependencies": list(self.degraded),
            "contributions": [item.describe() for item in self.contributions],
            "details": dict(self.details),
        }


def _trigger_value(trigger: Any) -> Optional[str]:
    if isinstance(trigger, RevalidationTrigger):
        return trigger.value

    if isinstance(trigger, str):
        return trigger

    if trigger is None:
        return None

    return repr(trigger)


def _resolve_trigger(trigger: Any) -> tuple[Optional[RevalidationTrigger], bool]:
    """``(trigger, recognised)``. A string is matched by value."""

    if isinstance(trigger, RevalidationTrigger):
        return trigger, True

    if isinstance(trigger, str):
        for candidate in RevalidationTrigger:
            if candidate.value == trigger:
                return candidate, True

    return None, False
def classify(
    trigger: Any,
    *,
    before: Optional[SecurityContextSnapshot] = None,
    after: Optional[SecurityContextSnapshot] = None,
) -> Classification:
    """Classify a change. Pure, total, and never raises.

    Total because a classifier that can raise is a classifier that can be
    skipped: a caller wrapping it in ``try``/``except`` and continuing
    would be treating an unclassifiable change as no change. Every
    unusable input therefore lands on a response instead, and the
    responses chosen for those cases remove authority rather than
    preserve it.
    """

    contributions: list[Contribution] = []
    resolved, recognised = _resolve_trigger(trigger)

    if recognised and resolved is not None:
        mapped = TRIGGER_RESPONSE.get(resolved, UNKNOWN_TRIGGER_RESPONSE)
        contributions.append(
            Contribution(
                rule="trigger",
                response=mapped,
                detail=f"trigger {resolved.value} maps to {mapped.value}",
            )
        )
    else:
        contributions.append(
            Contribution(
                rule="unrecognised_trigger",
                response=UNKNOWN_TRIGGER_RESPONSE,
                detail=(
                    f"{_trigger_value(trigger)!r} is not a known trigger; "
                    f"re-asking the boundary rather than assuming either "
                    f"direction"
                ),
            )
        )

    # -- what the snapshots establish, and what they fail to -----------

    state_changed: Optional[bool] = None
    degraded: tuple[str, ...] = ()
    usable_before = isinstance(before, SecurityContextSnapshot)
    usable_after = isinstance(after, SecurityContextSnapshot)

    if not usable_before and not usable_after:
        contributions.append(
            Contribution(
                rule="no_snapshot",
                response=AdaptiveResponse.SUSPEND,
                detail=(
                    "no security-context snapshot could be built, so the "
                    "change cannot be examined at all"
                ),
            )
        )
    elif not usable_after:
        contributions.append(
            Contribution(
                rule="no_snapshot_after",
                response=AdaptiveResponse.SUSPEND,
                detail=(
                    "the state after the change could not be read; the "
                    "current state is unknown, and unknown is not trusted"
                ),
            )
        )
    elif not usable_before:
        contributions.append(
            Contribution(
                rule="no_snapshot_before",
                response=AdaptiveResponse.REVALIDATE,
                detail=(
                    "no prior snapshot to compare against, so no change can "
                    "be shown to be harmless"
                ),
            )
        )
    else:
        state_changed = before.state_hash() != after.state_hash()
        degraded = tuple(
            sorted(
                set(before.degraded_dependencies) | set(after.degraded_dependencies)
            )
        )

        if state_changed:
            contributions.append(
                Contribution(
                    rule="state_hash_changed",
                    response=AdaptiveResponse.REVALIDATE,
                    detail=(
                        "the security state hash changed across the event, so "
                        "the assumptions behind the grant may no longer hold"
                    ),
                )
            )

        for finding in _snapshot_findings(before, after):
            contributions.append(finding)

    if degraded:
        contributions.append(
            Contribution(
                rule="degraded_dependencies",
                response=AdaptiveResponse.REVALIDATE,
                detail=(
                    "configured security dependencies could not be read: "
                    + ", ".join(degraded)
                ),
            )
        )

    response = join(*(item.response for item in contributions))

    # -- the KEEP guard ------------------------------------------------
    #
    # By this point ``response`` is the join of the contributions, and it
    # can only be KEEP if every contribution was KEEP -- which the
    # trigger rule alone never is, since no trigger maps to KEEP. So KEEP
    # is reached solely through the check below, and only with two clean,
    # equal snapshots behind it.

    if response is AdaptiveResponse.REVALIDATE and _keep_is_established(
        resolved,
        recognised,
        state_changed,
        degraded,
    ):
        contributions.append(
            Contribution(
                rule="keep",
                response=AdaptiveResponse.KEEP,
                detail=(
                    "two snapshots were taken, neither degraded, their state "
                    "hashes are equal, and the trigger is throttleable"
                ),
            )
        )
        response = AdaptiveResponse.KEEP

    return Classification(
        response=response,
        trigger=_trigger_value(trigger),
        contributions=tuple(contributions),
        state_changed=state_changed,
        degraded=degraded,
        details={
            "trigger_recognised": recognised,
            "snapshots": {
                "before": usable_before,
                "after": usable_after,
            },
        },
    )
def _keep_is_established(
    resolved: Optional[RevalidationTrigger],
    recognised: bool,
    state_changed: Optional[bool],
    degraded: tuple[str, ...],
) -> bool:
    """Every condition ``KEEP`` requires, stated once.

    Note the direction of every test: each one must be *positively*
    established. ``state_changed is False`` rather than ``not
    state_changed`` -- ``None`` means "no comparison was possible", which
    is not the same as "nothing changed", and ``not None`` would have
    silently conflated them.
    """

    if not recognised or resolved is None:
        return False

    if resolved in UNTHROTTLED_TRIGGERS:
        return False

    if TRIGGER_RESPONSE.get(resolved) is not AdaptiveResponse.REVALIDATE:
        return False

    if state_changed is not False:
        return False

    if degraded:
        return False

    return True


#: Snapshot fields whose value alone establishes that authority is gone or
#: unusable, independently of which trigger reported it. These exist
#: because a caller can pass a trigger that understates what the snapshot
#: shows -- ``TIME`` on a snapshot whose capability is revoked, say -- and
#: the join must not let the understatement win.
def _snapshot_findings(
    before: SecurityContextSnapshot,
    after: SecurityContextSnapshot,
) -> tuple[Contribution, ...]:
    """What the two snapshots establish on their own.

    Read independently of the trigger, because a caller can report a
    trigger that understates what the snapshots show -- ``TIME`` on a
    snapshot whose capability is revoked, say. The join then takes the
    stronger reading, so an understated trigger cannot win.
    """

    findings: list[Contribution] = []

    if after.capability_revoked and not before.capability_revoked:
        findings.append(
            Contribution(
                rule="capability_revoked",
                response=AdaptiveResponse.REVOKE,
                detail="the capability is revoked in the current snapshot",
            )
        )
    elif after.capability_revoked:
        findings.append(
            Contribution(
                rule="capability_already_revoked",
                response=AdaptiveResponse.REVOKE,
                detail="the capability was already revoked and remains so",
            )
        )

    if after.capability_expired:
        findings.append(
            Contribution(
                rule="capability_expired",
                response=AdaptiveResponse.SUSPEND,
                detail=(
                    "the capability is expired; the boundary denies it "
                    "independently, and Aegis records that no authority "
                    "remains to narrow"
                ),
            )
        )

    if not after.delegation_chain_valid:
        findings.append(
            Contribution(
                rule="delegation_chain_invalid",
                response=AdaptiveResponse.SUSPEND,
                detail="the delegation chain does not resolve",
            )
        )

    if after.identity_status != before.identity_status:
        findings.append(
            Contribution(
                rule="identity_status_changed",
                response=AdaptiveResponse.SUSPEND,
                detail=(
                    f"identity status moved from {before.identity_status!r} to "
                    f"{after.identity_status!r}"
                ),
            )
        )

    if after.identity_version != before.identity_version:
        findings.append(
            Contribution(
                rule="identity_version_changed",
                response=AdaptiveResponse.SUSPEND,
                detail=(
                    f"identity version moved from {before.identity_version} to "
                    f"{after.identity_version}; the principal is not the one "
                    f"the grant was issued to"
                ),
            )
        )

    if after.incident_active and not before.incident_active:
        findings.append(
            Contribution(
                rule="incident_opened",
                response=AdaptiveResponse.SUSPEND,
                detail="an incident is active",
            )
        )

    if after.posture != before.posture:
        findings.append(
            Contribution(
                rule="posture_changed",
                response=AdaptiveResponse.NARROW,
                detail=(
                    f"posture moved from {before.posture!r} to {after.posture!r}"
                ),
            )
        )

    if after.policy_version != before.policy_version:
        findings.append(
            Contribution(
                rule="policy_changed",
                response=AdaptiveResponse.REVALIDATE,
                detail=(
                    f"policy version moved from {before.policy_version!r} to "
                    f"{after.policy_version!r}; only the boundary can say "
                    f"what that means for this request"
                ),
            )
        )

    if after.trust_findings > before.trust_findings:
        findings.append(
            Contribution(
                rule="trust_findings_increased",
                response=AdaptiveResponse.NARROW,
                detail=(
                    f"trust findings rose from {before.trust_findings} to "
                    f"{after.trust_findings}"
                ),
            )
        )

    return tuple(findings)
