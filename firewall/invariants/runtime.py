"""Runtime (live-state) checks for the v2.2/v2.4 security invariants.

Eleven of the sixteen invariants are properties of a *running* system:
whether the delegation edges that actually exist narrow, whether a
revocation actually propagated, whether the authorization path denies
rather than raises on hostile input, whether a simulation left the
control plane untouched, whether the envelope a chain projects is
contained in its parent's, whether every exclusion the envelope states
is one the boundary actually enforces, whether a revalidation ever
reports an authority the boundary denies, whether the Aegis histories that
were recorded are legal. Those cannot be read off the source, so they
are checked here against a live :class:`~firewall.sdk.FirewallSDK`.

Two rules shape every check in this module.

**Nothing here grants authority.** Each function returns an
:class:`~firewall.invariants.model.InvariantResult`. No function
constructs an ``AuthorizationResult``, mutates the capability registry,
or writes to the revocation registry -- AUTHORIZATION_UNIQUENESS and
CONTROL_PLANE_INTEGRITY would flag it if it did.

**An unexercised property is not a satisfied property.** A fresh SDK has
no delegation edges, so DELEGATION_MONOTONICITY over it is
``UNVERIFIABLE``, not ``HOLDS``. This is the point of the three-valued
status: reporting "no violations found" over an empty registry as a pass
would convert absent evidence into a security claim. Callers who want a
green report must hand in an SDK that has actually issued, delegated,
attenuated and revoked -- see :func:`firewall.invariants.check_all`.

Two checks deliberately probe a scratch instance rather than the
supplied one, and say so in their ``details``: FAIL_CLOSED, because
probing a live SDK with hostile input trips its refusal state and so
would itself change the posture of the system under test, and
EVIDENCE_INTEGRITY, because demonstrating that tampering is detected
means tampering with something.
"""

from __future__ import annotations

import dataclasses
import time
from typing import Any, Mapping, Optional, Sequence

from firewall.aegis import blast as aegis_blast
from firewall.aegis import decay as aegis_decay
from firewall.aegis import envelope as aegis_envelope
from firewall.aegis import response as aegis_response
from firewall.aegis import state as aegis_state

# Imported from the submodule by name rather than as a module alias:
# ``firewall.aegis`` re-exports the ``preflight`` *function*, which shadows
# the submodule of the same name on the package.
from firewall.aegis.preflight import (
    IMPACT_RECOMMENDATION,
    MISSING_IMPACT_RECOMMENDATIONS,
    RECOMMENDATION_SEVERITY,
    SIZED_IMPACTS,
    Impact,
    Recommendation,
    preflight as run_preflight,
)
from firewall.authorization import AuthorizationResult
from firewall.capability import Capability
from firewall.continuous_auth.engine import (
    RevalidationTrigger,
    SecurityContextSnapshot,
)
from firewall.continuous_auth.predicates import (
    is_narrower_than,
    policy_transformation_monotonicity_check,
    revocation_monotonicity_check,
)
from firewall.invariants import static
from firewall.invariants.model import (
    InvariantResult,
    holds,
    unverifiable,
    violated,
)
from firewall.platform import (
    PROVENANCE_RANK,
    Provenance,
    coerce,
    combine,
    is_factual,
)
from firewall.sdk import FirewallSDK


def _require_sdk(sdk: Any, name: str) -> Optional[InvariantResult]:
    """``UNVERIFIABLE`` unless ``sdk`` really is a ``FirewallSDK``.

    A duck-typed stand-in would let a check pass against an object whose
    ``known_capabilities`` returns whatever the caller likes, which is
    the fail-open shape this package exists to catch.
    """

    if isinstance(sdk, FirewallSDK):
        return None

    return unverifiable(
        name,
        "no FirewallSDK was supplied, so live state cannot be "
        f"inspected (got {type(sdk).__name__})",
    )


def control_plane_snapshot(sdk: FirewallSDK) -> dict[str, Any]:
    """Comparable summary of the authorization data plane.

    Used by SIMULATION_ISOLATION as the before/after fingerprint. Sorted
    tuples rather than the live containers, so the snapshot cannot
    change under the caller between the two reads and cannot be used to
    mutate anything.
    """

    return {
        "capabilities": tuple(sorted(sdk.known_capabilities())),
        "lineage": tuple(
            sorted(
                (record.child_fingerprint, record.parent_fingerprint)
                for record in sdk.delegation_lineage.snapshot()
            )
        ),
        "revocations": tuple(
            sorted(
                record.fingerprint
                for record in sdk.revocation.records()
            )
        ),
    }


def check_delegation_monotonicity(
    sdk: FirewallSDK,
) -> InvariantResult:
    """Every *signed* delegation edge agrees with the registry and narrows.

    A delegated capability carries its parent's fingerprint inside the
    signed payload; an attenuated one does not (see
    :func:`check_capability_monotonicity` for those). The signature is
    the only unforgeable statement of parentage, so two things must hold
    for each signed edge:

    1. the registered parent is the signed parent. Where they disagree,
       authorization follows the signature -- but a disagreement means
       the registry can be used to point authorization at a different
       ancestor set than the one the issuer signed, so it is a finding
       even though ``authorize`` would not be fooled by it.
    2. the child is no broader than that parent, per
       :func:`~firewall.continuous_auth.predicates.is_narrower_than`.

    A signed parent the registry cannot resolve is also a finding: the
    ancestor walk needs it to decide which constraints the child is held
    to, and an unresolvable ancestor must not read as "no constraints".
    """

    name = "DELEGATION_MONOTONICITY"
    unavailable = _require_sdk(sdk, name)

    if unavailable is not None:
        return unavailable

    known = sdk.known_capabilities()
    findings: list[str] = []
    edges = 0

    for child_fingerprint, child in known.items():
        signed_parent = child.parent_fingerprint

        if not signed_parent:
            continue

        edges += 1
        registered_parent = sdk.delegation_lineage.parent_of(
            child_fingerprint
        )

        if registered_parent != signed_parent:
            findings.append(
                f"{child_fingerprint[:16]}: signed parent "
                f"{signed_parent[:16]} but the registry records "
                f"{(registered_parent or 'no parent')[:16]}"
            )

        parent = known.get(signed_parent)

        if parent is None:
            findings.append(
                f"{child_fingerprint[:16]}: signed parent "
                f"{signed_parent[:16]} is not in the capability "
                "registry, so the constraints it is held to cannot be "
                "resolved"
            )
            continue

        narrowing = is_narrower_than(parent, child)

        if not narrowing:
            findings.append(
                f"{child_fingerprint[:16]} is broader than its signed "
                f"parent {signed_parent[:16]}: {narrowing.reason}"
            )

    if findings:
        return violated(
            name,
            "a signed delegation edge widens authority or disagrees "
            "with the registry",
            findings=tuple(findings),
            signed_edges=edges,
        )

    if not edges:
        return unverifiable(
            name,
            "no capability in the registry carries a signed parent, so "
            "no delegation edge exists to check",
            capabilities=len(known),
        )

    return holds(
        name,
        f"all {edges} signed delegation edges narrow and agree with "
        "the registry",
        signed_edges=edges,
    )


def check_capability_monotonicity(
    sdk: FirewallSDK,
) -> InvariantResult:
    """Every *registered* lineage edge narrows.

    This is the wider claim of the two. It covers attenuation, which
    carries no signed parent and so is invisible to
    :func:`check_delegation_monotonicity`, and it covers any edge
    written into the lineage by a path other than ``delegate`` --
    exactly the case where a bug would show up.

    The two checks overlap on delegated edges deliberately. They are
    testing different things: that one is about the *signature* agreeing
    with the registry, this one is about the registry the ancestor walk
    actually reads.
    """

    name = "CAPABILITY_MONOTONICITY"
    unavailable = _require_sdk(sdk, name)

    if unavailable is not None:
        return unavailable

    known = sdk.known_capabilities()
    records = sdk.delegation_lineage.snapshot()
    findings: list[str] = []
    checked = 0

    for record in records:
        child = known.get(record.child_fingerprint)
        parent = known.get(record.parent_fingerprint)

        if child is None or parent is None:
            missing = (
                "child"
                if child is None
                else "parent"
            )
            findings.append(
                f"lineage edge "
                f"{record.child_fingerprint[:16]} -> "
                f"{record.parent_fingerprint[:16]} has an unresolvable "
                f"{missing}; the ancestor walk cannot establish what "
                "constraints apply"
            )
            continue

        checked += 1
        narrowing = is_narrower_than(parent, child)

        if not narrowing:
            findings.append(
                f"{record.child_fingerprint[:16]} is broader than its "
                f"registered parent "
                f"{record.parent_fingerprint[:16]}: "
                f"{narrowing.reason}"
            )

    if findings:
        return violated(
            name,
            "a registered lineage edge widens authority or cannot be "
            "resolved",
            findings=tuple(findings),
            edges_checked=checked,
        )

    if not records:
        return unverifiable(
            name,
            "the delegation lineage is empty, so no derivation edge "
            "exists to check",
            capabilities=len(known),
        )

    return holds(
        name,
        f"all {checked} registered lineage edges narrow",
        edges_checked=checked,
    )


def check_revocation_monotonicity(
    sdk: FirewallSDK,
) -> InvariantResult:
    """Revoking a fingerprint revokes every descendant of it.

    Revocation must only ever subtract. The failure mode worth naming is
    not "the revoked capability still works" -- that is caught
    everywhere -- but "a capability delegated *from* it still works",
    which is an escalation path that survives the containment action
    taken to close it.

    Registry-resolvable fingerprints go through
    :func:`~firewall.continuous_auth.predicates.revocation_monotonicity_check`,
    which owns the descendant walk. A fingerprint revoked without ever
    being issued here -- a revocation fed in from outside -- cannot be
    passed to that predicate because it needs the ``Capability``, so
    those are checked through the SDK's own public accessors instead and
    counted separately in ``details``.
    """

    name = "REVOCATION_MONOTONICITY"
    unavailable = _require_sdk(sdk, name)

    if unavailable is not None:
        return unavailable

    known = sdk.known_capabilities()
    lineage = sdk.delegation_lineage
    records = sdk.revocation.records()
    findings: list[str] = []
    via_predicate = 0
    via_accessors = 0

    for record in records:
        fingerprint = record.fingerprint
        capability = known.get(fingerprint)

        if capability is not None:
            via_predicate += 1
            result = revocation_monotonicity_check(
                capability=capability,
                delegation_lineage=lineage,
                revocation_registry=sdk.revocation,
                before_revocation=False,
                after_revocation=True,
                revoked_fingerprint=fingerprint,
            )

            if not result:
                findings.append(
                    f"{fingerprint[:16]}: {result.reason}"
                )

            continue

        # Not in this SDK's registry, so the predicate above cannot be
        # used. The property is the same: nothing descended from a
        # revoked fingerprint may remain effectively authorized.
        via_accessors += 1

        if not sdk.revocation.is_revoked(fingerprint):
            findings.append(
                f"{fingerprint[:16]} has a revocation record but the "
                "registry does not report it as revoked"
            )

        for descendant_fingerprint, descendant in known.items():
            if not lineage.is_descendant_of(
                child_fingerprint=descendant_fingerprint,
                ancestor_fingerprint=fingerprint,
            ):
                continue

            if not sdk.is_effectively_revoked(descendant):
                findings.append(
                    f"{descendant_fingerprint[:16]} descends from "
                    f"revoked {fingerprint[:16]} but is not "
                    "effectively revoked"
                )

    if findings:
        return violated(
            name,
            "revocation did not propagate to every descendant",
            findings=tuple(findings),
            revocations_checked=len(records),
        )

    if not records:
        return unverifiable(
            name,
            "nothing has been revoked, so revocation propagation is "
            "unexercised",
            capabilities=len(known),
        )

    return holds(
        name,
        f"all {len(records)} revocations propagate to every descendant",
        checked_via_predicate=via_predicate,
        checked_via_accessors=via_accessors,
    )


#: Constraints used by the FAIL_CLOSED probe capability.
#:
#: Only ``amount_max`` is used. Constraint keys must appear in the
#: request to be satisfied, so a capability carrying more keys would deny
#: every probe for the wrong reason and the positive control below could
#: never allow.
_PROBE_CONSTRAINTS = {"amount_max": 100}


def _probe_outcome(
    sdk: FirewallSDK,
    capability: Capability,
    action: str,
    request: Optional[dict],
    refusal_scope: str = "action",
) -> tuple[Optional[bool], Optional[str]]:
    """``(allowed, error)`` for one authorization probe.

    An exception is captured rather than propagated: a raise *is* the
    fail-open failure this invariant looks for, because a caller that
    wraps ``authorize`` in ``try``/``except`` and continues has been
    handed an unauthorized request with no verdict attached.
    """

    try:
        result = sdk.authorize(
            capability,
            action=action,
            request=request,
            refusal_scope=refusal_scope,
        )
    except Exception as error:
        return None, f"{type(error).__name__}: {error}"

    return bool(result.allowed), None


class _UnreadableDependency:
    """One SDK dependency whose named reads raise instead of answering.

    Everything else forwards to the real object, so a probe isolates a
    single unanswerable question rather than replacing a subsystem with a
    stub whose whole behaviour differs. Attribute writes forward too: the
    SDK refreshes verifier trust in place, and a wrapper that swallowed
    those writes would diverge from the object it wraps.
    """

    def __init__(
        self,
        wrapped: Any,
        failing: frozenset,
    ) -> None:
        object.__setattr__(self, "_wrapped", wrapped)
        object.__setattr__(self, "_failing", failing)

    def __getattr__(self, name: str) -> Any:
        if name in object.__getattribute__(self, "_failing"):

            def unreachable(*args: Any, **kwargs: Any) -> Any:
                raise RuntimeError(f"{name} is unreachable")

            return unreachable

        return getattr(
            object.__getattribute__(self, "_wrapped"),
            name,
        )

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(
            object.__getattribute__(self, "_wrapped"),
            name,
            value,
        )


#: Dependency-failure probes: ``(label, attribute, reads, request, scope)``.
#:
#: Each entry names one security-relevant read that ``authorize`` performs
#: and makes exactly that read raise. The malformed-input probes above all
#: run against a *healthy* SDK, so before these existed the invariant could
#: report HOLDS while five dependencies could turn any decision -- including
#: a denial -- into an exception at the call site. That is the shape of
#: green invariant this suite treats as insufficient: the relevant security
#: path was never exercised.
#:
#: The last two entries are the same unwritable evidence sink on opposite
#: verdicts, and they are checked together on purpose. Losing the audit
#: record of an *allow* withholds the allow; losing the audit record of a
#: *denial* must not withhold the denial, because a denial that raises is
#: handed to the caller as no verdict at all.
_UNAVAILABLE_PROBES: tuple[
    tuple[str, str, tuple[str, ...], Optional[dict], str], ...
] = (
    ("an unusable signature verifier", "verifier", ("verify",), {"amount": 10}, "action"),
    ("an unreadable clock", "verifier", ("clock",), {"amount": 10}, "action"),
    (
        "an unreadable refusal state",
        "refusal_state",
        ("check_action",),
        {"amount": 10},
        "action",
    ),
    (
        "an unreadable refusal state in request scope",
        "refusal_state",
        ("check",),
        {"amount": 10},
        "request",
    ),
    ("an unreadable revocation store", "revocation", ("is_revoked",), {"amount": 10}, "action"),
    (
        "an unreadable issuer trust store",
        "issuer_trust_store",
        ("is_trusted",),
        {"amount": 10},
        "action",
    ),
    (
        "an unreadable delegation lineage",
        "delegation_lineage",
        ("chain",),
        {"amount": 10},
        "action",
    ),
    (
        "an unwritable evidence log under an allow",
        "lifecycle",
        ("record",),
        {"amount": 10},
        "action",
    ),
    (
        "an unwritable evidence log under a denial",
        "lifecycle",
        ("record",),
        {"amount": 10_000},
        "action",
    ),
)


def _unavailable_dependency_finding(
    label: str,
    attribute: str,
    reads: tuple[str, ...],
    request: Optional[dict],
    refusal_scope: str,
) -> Optional[str]:
    """Probe one unreadable dependency; return a finding or ``None``.

    Runs its own control *on the instance being sabotaged* and requires it
    to allow before the sabotage lands. Without that, a denial afterwards
    would prove nothing -- a scratch SDK that denied for some unrelated
    reason would satisfy the probe while the dependency failure went
    unexercised. This is the per-probe form of the positive control that
    :func:`check_fail_closed` runs once at the top.
    """

    sdk = FirewallSDK()
    sdk.generate_key("invariant-probe")

    capability = sdk.issue(
        agent="probe-agent",
        capability="payments.send",
        constraints=dict(_PROBE_CONSTRAINTS),
    )

    control, control_error = _probe_outcome(
        sdk,
        capability,
        "payments.send",
        {"amount": 10},
        refusal_scope,
    )

    if control_error is not None:
        return (
            f"{label}: the control raised before the dependency was "
            f"sabotaged ({control_error})"
        )

    if control is not True:
        return (
            f"{label}: the control was denied before the dependency was "
            "sabotaged, so a denial after it would prove nothing"
        )

    dependency = getattr(sdk, attribute, None)

    if dependency is None:
        return f"{label}: there is no {attribute} to make unreadable"

    setattr(
        sdk,
        attribute,
        _UnreadableDependency(
            dependency,
            frozenset(reads),
        ),
    )

    outcome, error = _probe_outcome(
        sdk,
        capability,
        "payments.send",
        request,
        refusal_scope,
    )

    if error is not None:
        return f"{label}: raised instead of denying ({error})"

    if outcome is not False:
        return f"{label}: was allowed while the read was unanswerable"

    return None


def check_fail_closed() -> InvariantResult:
    """Hostile input and unavailable state produce a denial, never a raise.

    Two probe families, because they fail in different places.

    *Malformed input* against a healthy SDK: the request is wrong and the
    firewall is fine. *Unavailable state* against a legitimate request: the
    request is fine and the firewall cannot answer one of its own
    questions. The second family was added in v2.5 after the first, alone,
    reported HOLDS while five injected dependencies could turn any decision
    into an exception at the call site -- including a denial, which is the
    worse direction, since a caller that wraps ``authorize`` in
    ``except Exception`` and continues has been handed no verdict at all.

    Probed against a scratch ``FirewallSDK`` rather than a supplied one,
    for a security reason: the probes are denials, and a run of denials
    trips the SDK's refusal state. Probing a live instance would
    therefore change the posture of the system under test -- the
    measurement would alter what it measured. The authorization path is
    the same code either way.

    The positive control runs first and must *allow*. Without it a
    firewall that denied everything -- including legitimate requests --
    would satisfy every other probe here and report ``HOLDS``, which is
    the mirror-image bug: fail-closed is only meaningful if the system
    can still say yes. Every dependency probe repeats that control on its
    own instance before sabotaging it.

    What this does **not** establish. It does not show that a denial's
    evidence was durably recorded -- the unwritable-log probes require the
    verdict to survive the loss, and surfacing the loss is all they check.
    It does not enumerate every dependency the boundary might ever consult,
    only the reads ``authorize`` performs today. And it says nothing about
    concurrent failure: each probe sabotages one read on one thread.
    """

    name = "FAIL_CLOSED"

    sdk = FirewallSDK()
    sdk.generate_key("invariant-probe")

    foreign = FirewallSDK()
    foreign.generate_key("foreign")

    capability = sdk.issue(
        agent="probe-agent",
        capability="payments.send",
        constraints=dict(_PROBE_CONSTRAINTS),
    )

    findings: list[str] = []

    # Positive control, before any denial can trip the refusal state.
    allowed, error = _probe_outcome(
        sdk,
        capability,
        "payments.send",
        {"amount": 10},
    )

    if error is not None:
        return violated(
            name,
            "the authorization path raised on a legitimate request",
            findings=(f"positive control raised {error}",),
        )

    if allowed is not True:
        return violated(
            name,
            "the authorization path denied a legitimate request, so "
            "the denial probes below would pass for the wrong reason",
            findings=("positive control was denied",),
        )

    revoked = sdk.issue(
        agent="probe-agent",
        capability="payments.send",
        constraints=dict(_PROBE_CONSTRAINTS),
    )
    sdk.revoke(revoked)

    forged = foreign.issue(
        agent="probe-agent",
        capability="payments.send",
        constraints=dict(_PROBE_CONSTRAINTS),
    )

    # A capability whose signed payload says 100 but whose in-memory
    # copy says 10_000. The signature is over the original, so this must
    # be rejected as unverifiable rather than honoured.
    tampered = dataclasses.replace(
        capability,
        constraints={"amount_max": 10_000},
    )

    probes: tuple[tuple[str, Capability, str, Optional[dict]], ...] = (
        (
            "request exceeds the constraint ceiling",
            capability,
            "payments.send",
            {"amount": 10_000},
        ),
        (
            "action outside the capability namespace",
            capability,
            "admin.delete_everything",
            {"amount": 10},
        ),
        (
            "revoked capability",
            revoked,
            "payments.send",
            {"amount": 10},
        ),
        (
            "capability signed by an unknown key",
            forged,
            "payments.send",
            {"amount": 10},
        ),
        (
            "capability with constraints edited after signing",
            tampered,
            "payments.send",
            {"amount": 5_000},
        ),
        (
            "no request at all where a constraint needs a value",
            capability,
            "payments.send",
            None,
        ),
        (
            "request value of the wrong type",
            capability,
            "payments.send",
            {"amount": "not-a-number"},
        ),
        (
            "empty action",
            capability,
            "",
            {"amount": 10},
        ),
    )

    for label, probe_capability, action, request in probes:
        outcome, probe_error = _probe_outcome(
            sdk,
            probe_capability,
            action,
            request,
        )

        if probe_error is not None:
            findings.append(
                f"{label}: raised instead of denying ({probe_error})"
            )
            continue

        if outcome is not False:
            findings.append(f"{label}: was allowed")

    for (
        label,
        attribute,
        reads,
        probe_request,
        refusal_scope,
    ) in _UNAVAILABLE_PROBES:
        finding = _unavailable_dependency_finding(
            label,
            attribute,
            reads,
            probe_request,
            refusal_scope,
        )

        if finding is not None:
            findings.append(finding)

    total = len(probes) + len(_UNAVAILABLE_PROBES)

    if findings:
        return violated(
            name,
            "the authorization path did not fail closed on hostile "
            "input or unavailable state",
            findings=tuple(findings),
            probes=total,
        )

    return holds(
        name,
        f"a legitimate request is allowed, {len(probes)} hostile probes "
        f"are denied and {len(_UNAVAILABLE_PROBES)} unavailable "
        "dependencies deny without raising",
        probes=total,
        input_probes=len(probes),
        dependency_probes=len(_UNAVAILABLE_PROBES),
        probe_target="scratch FirewallSDK",
    )


def _isolation_cases() -> tuple[Any, ...]:
    """Cases replayed by the SIMULATION_ISOLATION probe.

    Deliberately includes a delegation hop and a revoked agent, because
    those are the two paths that would have to touch lineage and
    revocation state if the simulator were reaching for the real
    containers rather than its own sandbox. A replay of nothing but
    single-hop allows could not tell the two apart.

    Both cases carry a ``baseline_*`` pair so the replay can report
    ``faithful``; without one the simulator correctly caveats that it
    recorded no observed decision to compare against, and that caveat
    would mask the absence of the re-signing caveat this check requires.
    """

    from firewall.simulation.case import DelegationHop, RequestCase

    return (
        RequestCase(
            case_id="invariant-isolation-delegated",
            action="payments.send",
            capability="payments.send",
            root_agent="probe-root",
            issuer="trusted-issuer",
            root_constraints={"amount_max": 100},
            hops=(
                DelegationHop(
                    delegatee="probe-child",
                    constraints={"amount_max": 50},
                ),
            ),
            request={"amount": 10},
            baseline_allowed=True,
            baseline_reason="authorized",
        ),
        RequestCase(
            case_id="invariant-isolation-revoked",
            action="payments.send",
            capability="payments.send",
            root_agent="probe-revoked",
            issuer="trusted-issuer",
            root_constraints={"amount_max": 100},
            request={"amount": 10},
            revoked_agents=("probe-revoked",),
            baseline_allowed=False,
            baseline_reason="capability_revoked",
        ),
    )


#: Substring identifying the caveat that keeps a replay honest.
#:
#: ``simulate`` re-signs every replayed capability with a simulation
#: key, so the report cannot speak to failures of the original
#: signatures and says so. Matching on the caveat *text* is coarse, but
#: the alternative -- accepting any non-empty ``caveats`` tuple -- would
#: let a report satisfy the check with an unrelated caveat while
#: silently dropping the one that marks its decisions as simulated.
SIMULATION_KEY_CAVEAT = "re-signed with a simulation key"


def check_simulation_isolation(
    sdk: FirewallSDK,
) -> InvariantResult:
    """A simulation changes no production state and claims no fact.

    Two properties, both required by §10.

    *Isolation.* The control-plane snapshot -- registry keys, lineage
    edges, revocation records -- must be byte-identical either side of a
    replay. A simulator that reached for the live containers instead of
    its own sandbox would show up here as a diff, and the cases probed
    include a delegation hop and a revoked agent precisely because those
    are the paths that would have to touch that state.

    *Honesty.* The report must not present replayed decisions as
    observations. ``simulate`` re-signs every capability with a
    simulation key, so it cannot speak to the original signatures, and it
    must carry :data:`SIMULATION_KEY_CAVEAT` saying so. A replay that
    returned a clean report with no such caveat would be simulation
    laundered into fact.

    Both cases also act as a positive control. They are constructed with
    a known-correct baseline, so the replay must report them
    ``reproducible`` and ``faithful``. Without that, a simulator that
    short-circuited and decided nothing at all would satisfy the
    isolation diff trivially -- it is the same reason
    :func:`check_fail_closed` runs its allow probe first.
    """

    name = "SIMULATION_ISOLATION"
    unavailable = _require_sdk(sdk, name)

    if unavailable is not None:
        return unavailable

    from firewall.simulation.replay import simulate
    from firewall.simulation.ruleset import RuleSet

    before_state = control_plane_snapshot(sdk)

    cases = _isolation_cases()
    report = simulate(
        cases,
        RuleSet(
            max_delegation_depth=5,
            trusted_issuers=("trusted-issuer",),
        ),
        RuleSet(
            max_delegation_depth=1,
            trusted_issuers=("trusted-issuer",),
        ),
        limit=len(cases),
    )

    after_state = control_plane_snapshot(sdk)
    findings: list[str] = []

    for key, before_value in before_state.items():
        after_value = after_state[key]

        if before_value != after_value:
            findings.append(
                f"simulation changed control-plane {key}: "
                f"{len(before_value)} entries before, "
                f"{len(after_value)} after"
            )

    if not any(
        SIMULATION_KEY_CAVEAT in caveat for caveat in report.caveats
    ):
        findings.append(
            "the replay did not declare that its capabilities were "
            "re-signed with a simulation key, so it presents simulated "
            "decisions as if they were observed"
        )

    if len(report.outcomes) > len(cases):
        findings.append(
            f"the replay produced {len(report.outcomes)} outcomes for "
            f"{len(cases)} bounded cases, so it is not bounded by its "
            "input"
        )

    for outcome in report.outcomes:
        if outcome.error is not None:
            findings.append(
                f"positive control {outcome.case_id!r} errored: "
                f"{outcome.error}"
            )
            continue

        if not outcome.reproducible or not outcome.faithful:
            findings.append(
                f"positive control {outcome.case_id!r} replayed "
                f"reproducible={outcome.reproducible} "
                f"faithful={outcome.faithful}, so the replay is not "
                "exercising the authorization path it claims to model"
            )

    if findings:
        return violated(
            name,
            "simulation is not isolated from production state or does "
            "not declare itself simulated",
            findings=tuple(findings),
            cases=len(cases),
        )

    return holds(
        name,
        f"a {len(cases)}-case replay left the control plane unchanged "
        f"and declared {len(report.caveats)} caveat(s)",
        cases=len(cases),
        outcomes=len(report.outcomes),
        caveats=list(report.caveats),
    )


#: Values ``coerce`` must map to ``UNKNOWN`` rather than to a fact.
#:
#: Provenance labels arrive from adapters, tool output and deserialized
#: reports, so an unrecognized value is the normal case rather than a
#: programming error. Each of these is something a caller could plausibly
#: hand in: a wrong-cased member, a near-miss spelling, a truthy object,
#: an absent value, an empty string.
_UNRECOGNIZED_PROVENANCE = (
    "OBSERVED",
    "observation",
    "trusted",
    "",
    None,
    0,
    1,
    object(),
    ["observed"],
)


def check_provenance_integrity(
    sdk: Optional[FirewallSDK] = None,
) -> InvariantResult:
    """One provenance vocabulary, and an algebra that cannot launder it.

    Two halves, both required. The static half asks whether a second
    enum restates the canonical vocabulary -- two enums that subclass
    ``str`` compare equal member-by-member, so a duplicate breaks nothing
    visibly and lets two subsystems drift apart while appearing to agree.
    That half is delegated to
    :func:`firewall.invariants.static.duplicate_provenance_vocabularies`.

    The runtime half exercises the algebra, because §13's
    ``inferred != observed`` and ``simulated != observed`` are claims
    about ``combine`` and ``coerce``, not about the enum:

    1. ``combine()`` over no inputs is ``UNKNOWN``. Combining nothing
       must not synthesise a fact.
    2. ``combine(a, b)`` is factual only if ``a`` and ``b`` both are. One
       inferred input makes the whole derivation non-factual, which is
       what stops an inference from being aggregated into an
       observation.
    3. ``SIMULATED`` is absorbing: no input, in either position, washes
       it out. Simulation is the one label that must survive contact
       with real data, or a simulated decision mixed with an observed one
       would come back out as observed.
    4. ``combine`` never outranks its weakest input, so aggregation only
       ever weakens a claim.
    5. ``coerce`` maps every unrecognized value to ``UNKNOWN``. This is
       reachable from untrusted tool output, so a permissive default
       would be a direct fail-open.

    ``sdk`` is accepted and unused: the property is of the vocabulary and
    its algebra, which no per-instance state can change. The parameter
    exists so :func:`firewall.invariants.check_all` can call every check
    uniformly.
    """

    name = "PROVENANCE_INTEGRITY"
    findings: list[str] = []

    duplicates, parse_failures = (
        static.duplicate_provenance_vocabularies()
    )
    findings.extend(duplicates)

    if combine() is not Provenance.UNKNOWN:
        findings.append(
            f"combine() over no inputs is {combine()!r}, not UNKNOWN, "
            "so absent evidence is treated as a fact"
        )

    members = tuple(Provenance)

    for left in members:
        for right in members:
            result = combine(left, right)

            if is_factual(result) and not (
                is_factual(left) and is_factual(right)
            ):
                findings.append(
                    f"combine({left.value}, {right.value}) is "
                    f"{result.value}, which is factual although an "
                    "input was not"
                )

            if Provenance.SIMULATED in (left, right):
                if result is not Provenance.SIMULATED:
                    findings.append(
                        f"combine({left.value}, {right.value}) is "
                        f"{result.value}: a simulated input was washed "
                        "out, so simulation can re-enter as observation"
                    )
                continue

            weakest = min(
                PROVENANCE_RANK[left.value],
                PROVENANCE_RANK[right.value],
            )

            if PROVENANCE_RANK[result.value] > weakest:
                findings.append(
                    f"combine({left.value}, {right.value}) is "
                    f"{result.value}, which outranks its weakest input"
                )

    for value in _UNRECOGNIZED_PROVENANCE:
        try:
            coerced = coerce(value)
        except Exception as error:  # noqa: BLE001
            findings.append(
                f"coerce({value!r}) raised {type(error).__name__}: "
                "an unrecognized label must degrade to UNKNOWN, not "
                "propagate an exception into a caller's error handling"
            )
            continue

        if coerced is not Provenance.UNKNOWN:
            findings.append(
                f"coerce({value!r}) is {coerced.value}, not UNKNOWN"
            )

    if findings:
        return violated(
            name,
            "the provenance vocabulary is duplicated or its algebra "
            "can turn a non-fact into a fact",
            findings=tuple(findings),
            parse_failures=list(parse_failures),
        )

    if parse_failures:
        return unverifiable(
            name,
            "the algebra holds, but some modules could not be parsed "
            "so the duplicate-vocabulary census is incomplete",
            findings=tuple(parse_failures),
        )

    return holds(
        name,
        "one provenance vocabulary; combine over "
        f"{len(members) ** 2} pairs never strengthens a claim and "
        f"coerce degrades {len(_UNRECOGNIZED_PROVENANCE)} unrecognized "
        "values to UNKNOWN",
        pairs=len(members) ** 2,
        coerce_probes=len(_UNRECOGNIZED_PROVENANCE),
    )


def check_evidence_integrity() -> InvariantResult:
    """Recorded evidence cannot be edited without the record saying so.

    Probed on a scratch graph rather than on the supplied SDK's, because
    demonstrating that tampering is detected means tampering with
    something, and the whole value of an evidence graph is that nothing
    outside its own append path writes to it.

    Four steps, in order:

    1. an *unsigned* graph must report ``unverifiable`` -- not
       ``verified``. Nothing signed the events, so there is nothing to
       check, and a graph that reported success on that basis would make
       every later step meaningless.
    2. a signed graph must report ``verified``. This is the positive
       control: without it, an implementation that reported failure
       unconditionally would pass step 3 for the wrong reason.
    3. an event edited in place -- ``dataclasses.replace`` on the stored
       event, which is how a caller holding the container would do it --
       must flip ``verify()`` to ``failed``.
    4. ``detect_tampering()`` must name what happened. Detecting *that*
       something changed without saying the hash and the signature both
       stopped matching leaves an operator unable to distinguish
       corruption from forgery.
    """

    name = "EVIDENCE_INTEGRITY"

    from firewall.evidence_graph import EvidenceGraph
    from firewall.evidence_graph.graph import KeyEvidenceSigner

    findings: list[str] = []

    unsigned = EvidenceGraph()
    unsigned.append(
        "observed",
        "invariant-probe",
        "authorization",
        {"allowed": True},
    )
    unsigned_status = unsigned.verify().get("status")

    if unsigned_status != "unverifiable":
        findings.append(
            f"an unsigned graph reports {unsigned_status!r}; with no "
            "signatures to check the only honest answer is "
            "'unverifiable'"
        )

    graph = EvidenceGraph(KeyEvidenceSigner())

    for index in range(3):
        graph.append(
            "observed",
            "invariant-probe",
            "authorization",
            {"allowed": True, "sequence": index},
        )

    clean_status = graph.verify().get("status")

    if clean_status != "verified":
        return violated(
            name,
            "a freshly signed, untampered evidence graph does not "
            f"verify (status {clean_status!r}), so a later failure "
            "would prove nothing",
            findings=tuple(findings)
            + (f"signed graph verify() status is {clean_status!r}",),
        )

    if graph.detect_tampering():
        findings.append(
            "detect_tampering() reports findings on an untampered "
            "graph, so its findings carry no signal"
        )

    events = graph.events()

    if len(events) != 3:
        return unverifiable(
            name,
            f"the probe graph holds {len(events)} events rather than "
            "the 3 appended, so the tamper step would not be editing "
            "what it believes it is",
            findings=tuple(findings),
        )

    # Edit a recorded event in place: same field shape, different
    # payload. This is the strongest form of the attack the graph exists
    # to defeat -- not deleting an event, but changing what it says.
    target = graph._events[1]
    graph._events[1] = dataclasses.replace(
        target,
        payload={"allowed": True, "sequence": 1, "amount": 10_000},
    )

    tampered_status = graph.verify().get("status")

    if tampered_status != "failed":
        findings.append(
            f"an edited event leaves verify() at {tampered_status!r}; "
            "recorded evidence can be rewritten without the record "
            "saying so"
        )

    problems = graph.detect_tampering()
    kinds = {
        str(problem.get("type", problem))
        if isinstance(problem, dict)
        else str(problem)
        for problem in problems
    }

    if not problems:
        findings.append(
            "detect_tampering() reports nothing after an event was "
            "edited"
        )
    else:
        for expected in ("hash_mismatch", "bad_signature"):
            if not any(expected in kind for kind in kinds):
                findings.append(
                    f"detect_tampering() did not report {expected!r} "
                    "after an event was edited, so an operator cannot "
                    "tell corruption from forgery"
                )

    if findings:
        return violated(
            name,
            "recorded evidence can be altered without the record "
            "reporting it",
            findings=tuple(findings),
        )

    return holds(
        name,
        "an unsigned graph reports unverifiable, a signed graph "
        "verifies, and editing one event fails verification and is "
        "named by detect_tampering",
        probe_target="scratch EvidenceGraph",
        tamper_findings=sorted(kinds),
    )


def check_policy_non_widening(
    sdk: Optional[FirewallSDK] = None,
    *,
    policy_history: Optional[Sequence[Any]] = None,
) -> InvariantResult:
    """Every recorded policy edit narrowed authority or left it equal.

    ``policy_history`` is a sequence of ``(old_policy, new_policy)``
    pairs of :class:`~firewall.capability2.constraints.Capability2`, one
    per transformation actually applied. Pairs rather than a chronological
    list of versions: pairs are what
    :func:`~firewall.continuous_auth.predicates.policy_transformation_monotonicity_check`
    consumes, they carry no ordering assumption, and a deployment editing
    several unrelated policies needs no second representation to express
    that.

    With no history the result is ``UNVERIFIABLE``, and this is the whole
    design decision in this function. The tempting alternative -- run a
    known-narrowing pair as a canary and report ``HOLDS`` -- would be a
    claim about a synthetic pair dressed up as a claim about the
    deployment's policy edits. An unexercised property is not a satisfied
    property; a caller who has applied no policy transformations has
    nothing for this invariant to be true of.

    The predicate is reused rather than reimplemented so there is one
    definition of "narrower". ``sdk`` is accepted and unused: the SDK
    keeps no policy-version history to read a transformation out of, so
    the history must be supplied by whatever applied it.
    """

    name = "POLICY_NON_WIDENING"

    if policy_history is None:
        return unverifiable(
            name,
            "no policy transformation history was supplied, so there "
            "is no recorded policy edit to check; pass "
            "policy_history=[(old, new), ...] to exercise this "
            "invariant",
        )

    pairs = list(policy_history)

    if not pairs:
        return unverifiable(
            name,
            "the supplied policy history is empty, so no policy edit "
            "has been checked",
        )

    findings: list[str] = []
    malformed: list[str] = []
    checked = 0

    for index, entry in enumerate(pairs):
        try:
            old_policy, new_policy = entry
        except (TypeError, ValueError):
            malformed.append(
                f"history[{index}] is not an (old_policy, new_policy) "
                f"pair: {type(entry).__name__}"
            )
            continue

        try:
            result = policy_transformation_monotonicity_check(
                old_policy=old_policy,
                new_policy=new_policy,
            )
        except Exception as error:  # noqa: BLE001
            # A transformation the predicate cannot evaluate is not a
            # pass. It is an entry whose safety is unknown, and unknown
            # is not trusted.
            malformed.append(
                f"history[{index}] could not be evaluated: "
                f"{type(error).__name__}: {error}"
            )
            continue

        checked += 1

        if not result.monotonic:
            findings.append(
                f"history[{index}] widens authority: {result.reason} "
                f"{result.details}"
            )

    if findings:
        return violated(
            name,
            f"{len(findings)} of {len(pairs)} recorded policy "
            "transformations widened authority",
            findings=tuple(findings),
            malformed=malformed,
            checked=checked,
        )

    if malformed:
        return unverifiable(
            name,
            f"{len(malformed)} of {len(pairs)} history entries could "
            "not be evaluated, so the census is incomplete",
            findings=tuple(malformed),
            checked=checked,
        )

    return holds(
        name,
        f"all {checked} recorded policy transformations are narrowing "
        "or equal",
        checked=checked,
    )


def check_envelope_monotonicity(
    sdk: FirewallSDK,
) -> InvariantResult:
    """Every lineage edge's child envelope is contained in its parent's.

    CAPABILITY_MONOTONICITY already checks the edge with
    :func:`~firewall.continuous_auth.predicates.is_narrower_than`. This
    checks the same edges through a different lens: the envelope
    ``FirewallSDK.authority_envelope`` projects, which is the meet over
    the whole resolved chain rather than a pairwise comparison of two
    capabilities. The two can disagree, and where they do the envelope is
    the one a caller reads to decide what a grant may still do, so it
    needs its own claim.

    Containment, not strict containment. A child that repeats its
    parent's constraints has an *equal* envelope, which is a subset in
    both directions and is exactly what a redundant re-issue looks like.
    Requiring strictness would report that as a violation.

    ``bottom`` envelopes are counted separately and excluded from the
    census. Bottom is a subset of everything, so an estate whose every
    projection collapsed to bottom would satisfy this check while
    establishing nothing; the result is ``UNVERIFIABLE`` unless at least
    one edge had two non-bottom endpoints.
    """

    name = "ENVELOPE_MONOTONICITY"
    unavailable = _require_sdk(sdk, name)

    if unavailable is not None:
        return unavailable

    known = sdk.known_capabilities()
    records = sdk.delegation_lineage.snapshot()
    findings: list[str] = []
    substantive = 0
    degenerate = 0

    for record in records:
        child = known.get(record.child_fingerprint)
        parent = known.get(record.parent_fingerprint)

        if child is None or parent is None:
            missing = "child" if child is None else "parent"
            findings.append(
                f"lineage edge {record.child_fingerprint[:16]} -> "
                f"{record.parent_fingerprint[:16]} has an unresolvable "
                f"{missing}, so no envelope can be projected for it"
            )
            continue

        try:
            child_envelope = sdk.authority_envelope(child)
            parent_envelope = sdk.authority_envelope(parent)
        except Exception as error:  # noqa: BLE001
            # A projection that raises is not a pass. A caller that
            # cannot obtain the envelope cannot establish the bound, and
            # an unestablished bound is not a satisfied one.
            findings.append(
                f"projecting the envelope for edge "
                f"{record.child_fingerprint[:16]} -> "
                f"{record.parent_fingerprint[:16]} raised "
                f"{type(error).__name__}: {error}"
            )
            continue

        if not child_envelope.is_subset_of(parent_envelope):
            findings.append(
                f"{record.child_fingerprint[:16]} projects an envelope "
                f"that is not contained in its parent "
                f"{record.parent_fingerprint[:16]}: child="
                f"{child_envelope.describe()} parent="
                f"{parent_envelope.describe()}"
            )
            continue

        if child_envelope.bottom or parent_envelope.bottom:
            degenerate += 1
        else:
            substantive += 1

    if findings:
        return violated(
            name,
            "a lineage edge projects a child envelope that admits more "
            "than its parent's",
            findings=tuple(findings),
            edges_checked=substantive + degenerate,
        )

    if not substantive:
        return unverifiable(
            name,
            f"no lineage edge has two non-bottom envelopes "
            f"({len(records)} edges, {degenerate} with a bottom "
            "endpoint), and bottom is contained in everything, so "
            "containment is unexercised",
            edges=len(records),
            degenerate=degenerate,
        )

    return holds(
        name,
        f"all {substantive} lineage edges with non-bottom endpoints "
        f"project a child envelope contained in its parent's "
        f"({degenerate} further edges had a bottom endpoint and prove "
        "nothing)",
        edges_checked=substantive,
        degenerate=degenerate,
    )


#: Constraints used by the ENVELOPE_SOUNDNESS probe capabilities. One key,
#: for the same reason as ``_PROBE_CONSTRAINTS``: a capability carrying
#: keys the probe request omits would deny every probe for the wrong
#: reason and the positive control could never allow.
_SOUNDNESS_CONSTRAINTS = {"amount_max": 100}

#: Recorded in the ENVELOPE_SOUNDNESS result so a reader cannot mistake a
#: passing grid for a proof.
SOUNDNESS_SAMPLING_CAVEAT = (
    "sampled over a fixed probe grid, not proved over all inputs; and "
    "one-directional -- an envelope that excludes nothing establishes "
    "nothing about what the boundary will do"
)


def _soundness_probes(
    sdk: FirewallSDK,
    now: float,
) -> tuple[tuple[str, Capability, str, Optional[dict]], ...]:
    """The probe grid, positive control first.

    ``now`` positions the expired capability's window in the past and is
    used for nothing else; the reading the grid is *evaluated* at is taken
    by the caller after this returns, for the reason given there.

    Every probe uses a distinct action. ``RefusalState.check_action``
    matches on ``(agent, capability_fingerprint, action)`` and ignores the
    request, so two constraint probes sharing an action would have the
    second one short-circuited by the first one's memoized denial -- it
    would still be a denial, but not one this grid produced, and the
    result would be crediting a check that never ran.
    """

    baseline = sdk.issue(
        agent="soundness-agent",
        capability="payments.*",
        constraints=dict(_SOUNDNESS_CONSTRAINTS),
    )

    revoked = sdk.issue(
        agent="soundness-agent",
        capability="payments.*",
        constraints=dict(_SOUNDNESS_CONSTRAINTS),
    )
    sdk.revoke(revoked)

    bound = sdk.issue(
        agent="soundness-agent",
        capability="payments.*",
        constraints=dict(_SOUNDNESS_CONSTRAINTS),
        tool="payments.bound",
    )

    expired = sdk.issue(
        agent="soundness-agent",
        capability="payments.*",
        constraints=dict(_SOUNDNESS_CONSTRAINTS),
        issued_at=now - 7_200.0,
        expires_at=now - 3_600.0,
    )

    # Trusted at issue time -- ``issue`` refuses an untrusted issuer --
    # then withdrawn, which is the real sequence: trust is revoked after
    # capabilities have already been minted under it.
    sdk.trust_issuer("soundness-issuer")
    untrusted = sdk.issue(
        agent="soundness-agent",
        capability="payments.*",
        constraints=dict(_SOUNDNESS_CONSTRAINTS),
        issuer="soundness-issuer",
    )
    sdk.revoke_issuer("soundness-issuer")

    return (
        # Positive control. Must be allowed, and must not be excluded:
        # an envelope that excludes an allowed request is the violation
        # shape, so this probe is load-bearing in both directions.
        (
            "positive control",
            baseline,
            "payments.control",
            {"amount": 10},
        ),
        (
            "request exceeds the constraint ceiling",
            baseline,
            "payments.over",
            {"amount": 10_000},
        ),
        (
            "request omits a constrained key",
            baseline,
            "payments.missing",
            {},
        ),
        (
            "constrained key holds a non-numeric value",
            baseline,
            "payments.typed",
            {"amount": "ten"},
        ),
        (
            "action is outside the capability namespace",
            baseline,
            "wire.transfer",
            {"amount": 10},
        ),
        (
            "capability is revoked",
            revoked,
            "payments.revoked",
            {"amount": 10},
        ),
        (
            "action does not match the bound tool",
            bound,
            "payments.unbound",
            {"amount": 10},
        ),
        (
            "capability expired an hour ago",
            expired,
            "payments.expired",
            {"amount": 10},
        ),
        (
            "issuer trust was withdrawn after issuance",
            untrusted,
            "payments.untrusted",
            {"amount": 10},
        ),
    )


#: ``(label, attribute, read)`` for every dependency
#: :meth:`FirewallSDK.authority_envelope` consults. Each one could raise
#: out of the projection before v2.5, and this invariant *swallowed* that
#: into its ``unresolved`` census and still reported ``HOLDS`` -- the same
#: shape as FAIL_CLOSED's original gap, in a second invariant.
_ENVELOPE_UNREADABLE_PROBES: tuple[tuple[str, str, str], ...] = (
    ("revocation state", "revocation", "is_revoked"),
    ("issuer trust", "issuer_trust_store", "is_trusted"),
    ("delegation lineage", "delegation_lineage", "chain"),
)


def _envelope_unreadable_findings() -> tuple[list[str], int]:
    """Require an unreadable projection to be *bottom*, and denied.

    Both halves, because either alone is satisfiable while the property
    fails. A bottom envelope excludes everything, so soundness --
    ``excludes => the boundary denies`` -- makes it a claim about every
    request against that grant. That claim is only honest if the boundary
    really does refuse, which it does for exactly these reads and only
    since v2.5: before the gate fixes it *raised*, and a bottom envelope
    would then have been asserting a decision that was never made.

    So each probe requires the sabotaged instance to produce a bottom
    envelope *and* a denial, and it proves the legitimate request allows
    on that instance first. Without the control a scratch SDK that denied
    for an unrelated reason would satisfy the probe while the projection
    was never sabotaged at all.
    """

    findings: list[str] = []
    exercised = 0

    for label, attribute, read in _ENVELOPE_UNREADABLE_PROBES:
        sdk = FirewallSDK()
        sdk.generate_key("envelope-unreadable-key")

        capability = sdk.issue(
            agent="probe-agent",
            capability="payments.send",
            constraints=dict(_PROBE_CONSTRAINTS),
        )

        control, control_error = _probe_outcome(
            sdk,
            capability,
            "payments.send",
            {"amount": 10},
        )

        if control is not True:
            findings.append(
                f"{label}: the control request was not allowed before the "
                f"read was sabotaged (allowed={control!r}, "
                f"error={control_error!r}), so this probe would have "
                "passed without exercising the projection"
            )
            continue

        setattr(
            sdk,
            attribute,
            _UnreadableDependency(
                getattr(sdk, attribute),
                frozenset({read}),
            ),
        )

        try:
            envelope = sdk.authority_envelope(capability)
        except Exception as error:  # noqa: BLE001
            findings.append(
                f"{label}: projecting the envelope raised "
                f"{type(error).__name__} instead of returning the bottom "
                "envelope, so a caller asking what a grant still carries "
                "gets an exception where a refusal belongs"
            )
            continue

        exercised += 1

        if not envelope.bottom:
            findings.append(
                f"{label}: the projection could not read {attribute}."
                f"{read} and returned a non-bottom envelope "
                f"({envelope.describe()}), so an unestablished bound "
                "reads as an established one"
            )

        allowed, error_text = _probe_outcome(
            sdk,
            capability,
            "payments.send",
            {"amount": 10},
        )

        if allowed is not False:
            findings.append(
                f"{label}: the envelope excludes every request while the "
                f"boundary answered allowed={allowed!r} "
                f"(error={error_text!r}); a bottom envelope is only sound "
                "if the boundary refuses"
            )

    return findings, exercised


def check_envelope_soundness() -> InvariantResult:
    """What the envelope excludes, the boundary denies.

    The claim is one-directional and that is the whole design::

        envelope.excludes(action, request, now) is not None
            =>  authorize(capability, action, request) denies

    The converse is *not* claimed. The envelope decomposes a chain into
    independent per-dimension bounds, which drops the cross-dimension
    ``and``/``or``/``not`` structure a constraint expression can carry, so
    an envelope that excludes nothing is not a prediction of an allow.
    Reading ``None`` as "permitted" is the fail-open misuse this invariant
    exists to make visible, and :meth:`AuthorityEnvelope.excludes` says so
    in its own docstring.

    The violation shape is therefore precise: a request the envelope
    excluded that the boundary *allowed*. Nothing else here is a
    violation. In particular a request the envelope did not exclude and
    the boundary denied is ordinary incompleteness.

    Two families run. The grid above sweeps a healthy SDK, and
    :func:`_envelope_unreadable_findings` sabotages one projection read at
    a time and requires the bottom envelope *and* a denial. The second
    family exists because the first could not see the defect v2.5 found:
    an unreadable dependency made ``authority_envelope`` raise, the loop
    recorded that in ``unresolved``, and the invariant still reported
    ``HOLDS``.

    Probed against a scratch ``FirewallSDK`` for FAIL_CLOSED's reason: the
    grid is mostly denials, denials trip refusal state, and probing the
    caller's instance would change the posture of the system under test.

    The positive control runs first and must be allowed. A firewall that
    denied everything would satisfy every implication above, so without
    it a ``HOLDS`` here would be worthless.

    **What this does not establish.** Not completeness -- an envelope that
    excludes nothing predicts nothing, by design. Not exhaustiveness over
    constraint shapes: the grid is a sample, which
    ``SOUNDNESS_SAMPLING_CAVEAT`` states. Not the composed picture with
    live Aegis restrictions, which the envelope deliberately omits.
    """

    name = "ENVELOPE_SOUNDNESS"

    sdk = FirewallSDK()
    sdk.generate_key("envelope-soundness-key")

    try:
        probes = _soundness_probes(sdk, time.time())
    except Exception as error:  # noqa: BLE001
        return unverifiable(
            name,
            "the probe grid could not be constructed, so soundness was "
            f"not exercised: {type(error).__name__}: {error}",
        )

    # Read the clock *after* the grid exists, and the ordering is
    # load-bearing. ``issue`` stamps ``issued_at`` from the clock, so a
    # ``now`` captured before issuance is earlier than every capability's
    # validity window whenever the clock ticks mid-construction -- 15.6 ms
    # of granularity on Windows is easily crossed by five signatures. The
    # envelope then reported ``not_yet_valid`` for the positive control
    # while the boundary, reading its own later clock, allowed it: a
    # VIOLATED verdict accusing the envelope of overstating a bound it had
    # stated correctly. Time is the one dimension where the envelope and
    # the boundary read different clocks, so the invariant must not hand
    # the envelope a reading the boundary could never have seen. Reading
    # last makes ``issued_at <= now`` hold for every probe capability.
    #
    # The first sentence of that reasoning was not true when it was
    # written: ``issue`` defaulted ``issued_at`` to ``time.time()``
    # regardless of the clock the boundary reads, and the two agreed here
    # only because this SDK injects no clock. v2.5 made it true -- see
    # ``FirewallSDK._issuance_timestamp`` -- which is what turns the
    # ordering above from a workaround into a consequence.
    now = time.time()

    findings: list[str] = []
    excluded_count = 0
    not_excluded: list[str] = []
    unresolved: list[str] = []
    control_allowed: Optional[bool] = None

    for index, (label, capability, action, request) in enumerate(probes):
        try:
            envelope = sdk.authority_envelope(capability)
            exclusion = envelope.excludes(action, request, now)
        except Exception as error:  # noqa: BLE001
            unresolved.append(
                f"{label}: projecting the envelope raised "
                f"{type(error).__name__}: {error}"
            )
            continue

        allowed, error_text = _probe_outcome(
            sdk,
            capability,
            action,
            request,
        )

        if index == 0:
            control_allowed = allowed

        if error_text is not None:
            # A raise is FAIL_CLOSED's finding, not this one's: the
            # request was certainly not allowed. Recorded so the census
            # cannot silently shrink.
            unresolved.append(
                f"{label}: authorize raised {error_text}"
            )
            continue

        if exclusion is None:
            not_excluded.append(f"{label}: allowed={allowed}")
            continue

        excluded_count += 1

        if allowed is True:
            findings.append(
                f"{label}: the envelope excludes this request "
                f"({exclusion}) but the boundary allowed it "
                f"(action={action!r}, request={request!r})"
            )

    unreadable_findings, unreadable_exercised = (
        _envelope_unreadable_findings()
    )

    findings.extend(unreadable_findings)

    if findings:
        return violated(
            name,
            "the boundary allowed a request the envelope states is "
            "outside the grant, so the envelope overstates what it "
            "bounds",
            findings=tuple(findings),
            probes=len(probes),
            excluded=excluded_count,
            unreadable_probes=len(_ENVELOPE_UNREADABLE_PROBES),
        )

    if control_allowed is not True:
        return unverifiable(
            name,
            "the positive control was not allowed "
            f"(allowed={control_allowed!r}), so a grid of denials "
            "cannot distinguish envelope soundness from a boundary that "
            "denies everything",
            findings=tuple(unresolved),
            probes=len(probes),
        )

    if not excluded_count:
        return unverifiable(
            name,
            f"none of the {len(probes)} probes was excluded by its "
            "envelope, so the implication was never entered and "
            "soundness is unexercised",
            not_excluded=tuple(not_excluded),
            findings=tuple(unresolved),
        )

    if unreadable_exercised != len(_ENVELOPE_UNREADABLE_PROBES):
        return unverifiable(
            name,
            f"only {unreadable_exercised} of "
            f"{len(_ENVELOPE_UNREADABLE_PROBES)} unreadable-projection "
            "probes were exercised, so soundness under unavailable state "
            "is not established",
            findings=tuple(unreadable_findings),
        )

    return holds(
        name,
        f"all {excluded_count} probes the envelope excluded were denied "
        f"by the boundary, over a grid of {len(probes)} probes, and all "
        f"{unreadable_exercised} unreadable-projection probes were bottom "
        f"and denied; {SOUNDNESS_SAMPLING_CAVEAT}",
        probe_target="scratch FirewallSDK",
        probes=len(probes),
        excluded=excluded_count,
        unreadable_probes=unreadable_exercised,
        not_excluded=tuple(not_excluded),
        unresolved=tuple(unresolved),
        caveat=SOUNDNESS_SAMPLING_CAVEAT,
    )


class _DuckAllow:
    """An allow-shaped object that is not an ``AuthorizationResult``.

    ``canonical_allow_for`` must reject it. Its binding is structural
    rather than cryptographic, and the type check is the structure: if
    duck typing were enough, any object with three attributes could
    restore a grant's standing without an authorization ever happening.
    """

    def __init__(self, fingerprint: str) -> None:
        self.allowed = True
        self.reason = "authorized"
        self.trace = {"capability_id": fingerprint}


def _aegis_edge_findings() -> list[str]:
    """Sweep every ``AegisState`` pair against the machine's own rules."""

    findings: list[str] = []
    states = tuple(aegis_state.AegisState)

    for state in states:
        if state not in aegis_state.RESIDUAL_AUTHORITY:
            findings.append(
                f"RESIDUAL_AUTHORITY has no entry for {state.value}, so "
                "the widening comparison cannot be made for it"
            )

    if findings:
        # Every sweep below reads the residual ordering. With a gap in it
        # they would raise rather than report, and the gap is the finding.
        return findings

    for state in aegis_state.TERMINAL_STATES:
        if aegis_state.residual_authority(state) != 0:
            findings.append(
                f"terminal state {state.value} carries residual "
                f"authority {aegis_state.residual_authority(state)}"
            )

        for to_state in states:
            # Including the identity edge. A terminal state that could
            # "transition to itself" would give a caller a legal move to
            # make from it, and the next one need not be the identity.
            if aegis_state.transition_is_legal(state, to_state):
                findings.append(
                    f"{state.value} -> {to_state.value} is legal, but "
                    f"{state.value} is terminal; revocation and expiry "
                    "must be final"
                )

    for from_state in states:
        for to_state in states:
            if not aegis_state.transition_is_legal(
                from_state,
                to_state,
            ):
                continue

            widens = aegis_state.residual_authority(
                to_state
            ) > aegis_state.residual_authority(from_state)

            if widens and (
                from_state,
                to_state,
            ) not in aegis_state.EVIDENCED_EDGES:
                findings.append(
                    f"{from_state.value} -> {to_state.value} widens "
                    "residual authority on an edge that requires no "
                    "canonical allow"
                )

    for edge in aegis_state.EVIDENCED_EDGES:
        from_state, to_state = edge

        if not aegis_state.transition_is_legal(from_state, to_state):
            findings.append(
                f"evidenced edge {from_state.value} -> {to_state.value} "
                "is not legal, so it can never be traversed and a grant "
                "that reaches it can never regain standing"
            )

    for edge in aegis_state.LIFT_EDGES:
        from_state, to_state = edge

        if not aegis_state.transition_is_legal(from_state, to_state):
            findings.append(
                f"lift edge {from_state.value} -> {to_state.value} is "
                "not legal"
            )

        if aegis_state.residual_authority(
            to_state
        ) > aegis_state.residual_authority(from_state):
            findings.append(
                f"lift edge {from_state.value} -> {to_state.value} "
                "widens residual authority; lifting a restriction "
                "removes an obstacle, it does not restore standing"
            )

    return findings


def _aegis_evidence_findings() -> tuple[list[str], list[str], list[str]]:
    """``(findings, blockers, refusals)`` for the evidence predicate.

    ``blockers`` are failed positive controls: the predicate refusing a
    genuine allow, or the boundary refusing a legitimate request. Neither
    is a widening, so neither is a violation -- but both mean the negative
    probes below passed for a reason that has nothing to do with the
    property, so the result must be ``UNVERIFIABLE`` rather than green.

    ``refusals`` record hostile evidence that made the predicate *raise*
    instead of returning ``False``. A raise is still a refusal at the
    boundary -- ``_observe_aegis`` swallows it and the grant does not
    move -- so it is reported rather than flagged. A probe that ran but
    could only reach a weaker condition than intended is reported there
    too, so a reader is not credited with coverage the grid did not get.
    """

    findings: list[str] = []
    blockers: list[str] = []
    refusals: list[str] = []

    sdk = FirewallSDK()
    sdk.generate_key("aegis-transitions-key")

    capability = sdk.issue(
        agent="aegis-agent",
        capability="payments.send",
        constraints=dict(_PROBE_CONSTRAINTS),
    )
    fingerprint = sdk.fingerprint(capability)

    # The genuine allow. Obtained from the canonical boundary rather than
    # hand-built: the predicate's whole job is to recognise what
    # ``authorize()`` actually emits, and a hand-built positive control
    # would only prove it recognises what this function writes.
    try:
        allow: Optional[AuthorizationResult] = sdk.authorize(
            capability,
            action="payments.send",
            request={"amount": 10},
        )
    except Exception as error:  # noqa: BLE001
        blockers.append(
            "the boundary raised on a legitimate request: "
            f"{type(error).__name__}: {error}"
        )
        allow = None

    if allow is not None and allow.allowed is not True:
        blockers.append(
            "the boundary denied a legitimate request "
            f"({allow.reason}), so the evidence predicate cannot be "
            "shown to accept a genuine allow"
        )
        allow = None

    if allow is not None and not aegis_state.canonical_allow_for(
        fingerprint,
        allow,
    ):
        findings.append(
            "canonical_allow_for rejected a genuine allow from "
            "FirewallSDK.authorize(), so REVALIDATING -> ACTIVE is "
            "unreachable and a revalidating grant can never regain "
            "standing"
        )

    # A second, unrelated capability's *genuine* allow. This is the replay
    # attack in its real form -- a valid, current allow that simply
    # belongs to someone else -- and it exercises the predicate's trace
    # comparison with a trace the boundary wrote rather than one this
    # module did.
    other_allow: Optional[Any] = None

    try:
        other_capability = sdk.issue(
            agent="aegis-other-agent",
            capability="payments.send",
            constraints=dict(_PROBE_CONSTRAINTS),
        )
        candidate = sdk.authorize(
            other_capability,
            action="payments.send",
            request={"amount": 10},
        )
    except Exception as error:  # noqa: BLE001
        blockers.append(
            "a second capability could not be authorized, so the "
            "cross-capability replay probe did not run: "
            f"{type(error).__name__}: {error}"
        )
    else:
        if candidate.allowed is not True:
            blockers.append(
                "the boundary denied the second capability "
                f"({candidate.reason}), so the cross-capability replay "
                "probe did not run"
            )
        else:
            other_allow = candidate

    # A *genuine* denial for this same capability, from the same boundary.
    # Its trace names this capability, so refusing it can only be the
    # ``allowed is not True`` condition doing the work.
    denial: Optional[Any] = None

    try:
        candidate = sdk.authorize(
            capability,
            action="payments.send",
            request={"amount": 10_000},
        )
    except Exception as error:  # noqa: BLE001
        blockers.append(
            "the boundary raised rather than denying an over-ceiling "
            f"request: {type(error).__name__}: {error}"
        )
    else:
        if candidate.allowed is not False:
            blockers.append(
                "the boundary allowed a request over the constraint "
                "ceiling, so the genuine-denial probe did not run"
            )
        else:
            denial = candidate
            trace = getattr(candidate, "trace", None)

            if (
                not isinstance(trace, Mapping)
                or trace.get("capability_id") != fingerprint
            ):
                # Reported, not flagged: the probe still runs, but it is
                # then refused for the trace rather than for the denial,
                # and claiming otherwise would credit a condition that
                # was never reached.
                refusals.append(
                    "the genuine denial's trace does not name this "
                    "capability, so it probes the trace condition "
                    "rather than the allow condition"
                )

    # Every hostile shape is either a non-verdict object or a verdict this
    # module obtained from ``FirewallSDK.authorize()``. Nothing here
    # constructs an ``AuthorizationResult``: AUTHORIZATION_UNIQUENESS
    # forbids it outside the boundary, and the invariant suite is not
    # exempt from the invariants it ships. The field-level hostile shapes
    # a boundary cannot emit -- an allow with no trace, a non-mapping
    # trace, a non-canonical reason -- are fabricated in the test suite
    # instead, where building an adversarial input is the point.
    hostile: list[tuple[str, Any]] = [
        ("None", None),
        ("True", True),
        ("the integer 1", 1),
        ("the string 'authorized'", "authorized"),
        (
            "a duck-typed allow look-alike",
            _DuckAllow(fingerprint),
        ),
    ]

    if other_allow is not None:
        hostile.append(
            (
                "a genuine allow issued for another capability",
                other_allow,
            )
        )

    if denial is not None:
        hostile.append(
            ("a genuine denial for this capability", denial)
        )

    for label, evidence in hostile:
        try:
            accepted = aegis_state.canonical_allow_for(
                fingerprint,
                evidence,
            )
        except Exception as error:  # noqa: BLE001
            refusals.append(
                f"{label}: raised {type(error).__name__}: {error}"
            )
            continue

        if accepted:
            findings.append(
                f"canonical_allow_for accepted {label} as a canonical "
                "allow, so standing can be restored without an "
                "authorization having happened"
            )

    grant = aegis_state.AegisGrant(
        fingerprint=fingerprint,
        agent_id="aegis-agent",
        capability="payments.send",
    )

    for state in aegis_state.TERMINAL_STATES:
        terminal = dataclasses.replace(grant, state=state)

        for to_state in tuple(aegis_state.AegisState):
            try:
                terminal.transition(to_state, "invariant probe")
            except aegis_state.IllegalTransition:
                continue
            except Exception as error:  # noqa: BLE001
                refusals.append(
                    f"{state.value} -> {to_state.value} raised "
                    f"{type(error).__name__} rather than "
                    f"IllegalTransition: {error}"
                )
                continue

            findings.append(
                f"a grant in {state.value} moved to {to_state.value}; "
                "a terminal state must be final"
            )

    revalidating = dataclasses.replace(
        grant,
        state=aegis_state.AegisState.REVALIDATING,
    )

    try:
        revalidating.transition(
            aegis_state.AegisState.ACTIVE,
            "no evidence supplied",
        )
    except aegis_state.IllegalTransition:
        pass
    except Exception as error:  # noqa: BLE001
        refusals.append(
            "REVALIDATING -> ACTIVE with no evidence raised "
            f"{type(error).__name__}: {error}"
        )
    else:
        findings.append(
            "REVALIDATING -> ACTIVE succeeded with no evidence, so a "
            "suspended or narrowed grant can regain full standing "
            "without an authorization"
        )

    try:
        revalidating.transition(
            aegis_state.AegisState.ACTIVE,
            "forged evidence",
            evidence=_DuckAllow(fingerprint),
        )
    except aegis_state.IllegalTransition:
        pass
    except Exception as error:  # noqa: BLE001
        refusals.append(
            "REVALIDATING -> ACTIVE with a duck-typed allow raised "
            f"{type(error).__name__}: {error}"
        )
    else:
        findings.append(
            "REVALIDATING -> ACTIVE accepted a duck-typed allow "
            "look-alike as evidence"
        )

    if allow is not None:
        # Positive control for the one edge that restores standing. If
        # this is refused the machine deadlocks, which is safe but broken,
        # so it is a blocker rather than a violation.
        try:
            restored = revalidating.transition(
                aegis_state.AegisState.ACTIVE,
                "revalidated against the canonical boundary",
                evidence=allow,
            )
        except Exception as error:  # noqa: BLE001
            blockers.append(
                "REVALIDATING -> ACTIVE was refused with a genuine "
                f"canonical allow: {type(error).__name__}: {error}"
            )
        else:
            if restored.state is not aegis_state.AegisState.ACTIVE:
                blockers.append(
                    "REVALIDATING -> ACTIVE returned a grant in "
                    f"{restored.state.value}"
                )

    return findings, blockers, refusals


def _aegis_auditor_findings() -> list[str]:
    """Is ``history_violations`` actually able to see a bad history?

    The live half of AEGIS_STATE_TRANSITIONS reads
    ``AegisController.history_findings()`` and reports ``HOLDS`` when it is
    empty. An auditor that returns nothing for *every* input would make
    that green forever, so the auditor is tested against a hand-forged
    history before its silence is believed.

    The forged grant is constructed directly rather than through
    :meth:`AegisGrant.transition`, which would refuse to record the edge.
    That is the point: the audit has to catch a history the transition
    code could not have produced, because a history written by some other
    path is exactly the case worth catching.
    """

    findings: list[str] = []
    states = aegis_state.AegisState

    resurrection = aegis_state.AegisGrant(
        fingerprint="a" * 64,
        agent_id="aegis-agent",
        capability="payments.send",
        state=states.ACTIVE,
        history=(
            aegis_state.Transition(
                from_state=states.ISSUED,
                to_state=states.SUSPENDED,
                at=1.0,
                reason="suspended",
            ),
            aegis_state.Transition(
                from_state=states.SUSPENDED,
                to_state=states.ACTIVE,
                at=2.0,
                reason="resurrected with no evidence",
            ),
        ),
    )

    if not aegis_state.history_violations(resurrection):
        findings.append(
            "history_violations reports nothing about a recorded "
            "SUSPENDED -> ACTIVE resurrection carrying no evidence, so "
            "the shipped history audit is blind and its silence on the "
            "live histories establishes nothing"
        )

    escape = aegis_state.AegisGrant(
        fingerprint="b" * 64,
        agent_id="aegis-agent",
        capability="payments.send",
        state=states.ACTIVE,
        history=(
            aegis_state.Transition(
                from_state=states.REVOKED,
                to_state=states.ACTIVE,
                at=1.0,
                reason="left a terminal state",
            ),
        ),
    )

    if not aegis_state.history_violations(escape):
        findings.append(
            "history_violations reports nothing about a recorded "
            "transition out of REVOKED"
        )

    # Positive control: an auditor that flagged everything would satisfy
    # both probes above while being equally useless.
    legal = aegis_state.AegisGrant(
        fingerprint="c" * 64,
        agent_id="aegis-agent",
        capability="payments.send",
        state=states.NARROWED,
        history=(
            aegis_state.Transition(
                from_state=states.ISSUED,
                to_state=states.NARROWED,
                at=1.0,
                reason="narrowed",
            ),
        ),
    )
    legal_findings = aegis_state.history_violations(legal)

    if legal_findings:
        findings.append(
            "history_violations reports "
            f"{legal_findings} about a legal narrowing history, so its "
            "findings cannot be read as evidence of a real problem"
        )

    return findings


def _aegis_decay_findings() -> list[str]:
    """Decay never returns authority, on real schedules."""

    findings: list[str] = []

    schedules = (
        aegis_decay.DecaySchedule(
            narrow_after=60.0,
            constraints={"amount_max": 1},
        ),
        aegis_decay.DecaySchedule(suspend_after=120.0),
        aegis_decay.DecaySchedule(
            narrow_after=60.0,
            suspend_after=120.0,
            constraints={"amount_max": 1},
        ),
        aegis_decay.DecaySchedule(
            narrow_after=30.0,
            patterns=("payments.read",),
        ),
    )

    # Increasing and valid. Monotonicity is a claim about elapsed time
    # moving forward, so it must be checked over samples that do.
    samples = (
        0.0,
        1.0,
        29.9,
        30.0,
        59.9,
        60.0,
        60.1,
        119.9,
        120.0,
        120.1,
        86_400.0,
    )

    for schedule in schedules:
        if not aegis_decay.stages_are_monotone(schedule, samples):
            findings.append(
                f"stage_at decreases over increasing elapsed time for "
                f"{schedule.describe()}, so waiting longer can return "
                "authority a decay stage already removed"
            )

        for stage in (
            schedule.stage_at(sample) for sample in samples
        ):
            if stage not in aegis_decay.DECAY_STAGE_SEVERITY:
                findings.append(
                    f"DECAY_STAGE_SEVERITY has no entry for "
                    f"{stage!r}"
                )

        # Invalid input is handled separately: it maps to the strongest
        # stage, which is deliberately *not* monotone in the argument and
        # would break the sweep above if mixed into it.
        for invalid in (
            True,
            False,
            "60",
            None,
            object(),
            float("nan"),
            float("inf"),
            -1.0,
        ):
            stage = schedule.stage_at(invalid)

            if stage is not schedule.strongest_stage:
                findings.append(
                    f"stage_at({invalid!r}) is {stage.value} rather "
                    f"than the strongest stage "
                    f"{schedule.strongest_stage.value}, so unreadable "
                    "elapsed time reads as less decay than the schedule "
                    "can prove"
                )

    return findings


def check_aegis_state_transitions(
    sdk: Optional[FirewallSDK] = None,
) -> InvariantResult:
    """No Aegis state transition returns authority without an allow.

    Two halves, and both are needed.

    The **algebra** runs unconditionally, because it is a property of the
    machine rather than of any deployment: every ``AegisState`` pair is
    swept, terminal states must admit no move at all, every legal edge
    that raises residual authority must be one of ``EVIDENCED_EDGES``, and
    the evidence predicate must accept a genuine
    ``FirewallSDK.authorize()`` allow while refusing every hostile
    look-alike in the grid -- including a *genuine* allow that belongs to
    another capability, which is the replay attack in its real form. The
    evidenced edges are *derived* from the module rather
    than hardcoded here, so adding a widening edge without an evidence
    requirement is a finding rather than a silent change to what this
    invariant checks. Decay schedules are swept for the same property in
    the time dimension, and ``history_violations`` is checked against a
    forged history so that its silence on the live ones means something.

    The **live** half audits what a deployment actually recorded, via
    ``AegisController.history_findings()``. That reads the histories as
    data; it does not re-run ``transition`` to decide whether they were
    legal, which would test the transition code against itself.

    What this does **not** establish: that any particular grant took the
    ``REVALIDATING -> ACTIVE`` edge. The count of evidenced traversals is
    reported, and it can be zero -- a deployment that never revalidated
    has nothing recorded to audit there. It is not made a precondition for
    ``HOLDS``, because that would report every ordinary production run as
    ``UNVERIFIABLE`` for having behaved normally.
    """

    name = "AEGIS_STATE_TRANSITIONS"

    findings = _aegis_edge_findings()
    findings.extend(_aegis_auditor_findings())
    findings.extend(_aegis_decay_findings())

    evidence_findings, blockers, refusals = _aegis_evidence_findings()
    findings.extend(evidence_findings)

    if findings:
        return violated(
            name,
            "the Aegis state machine admits a transition that returns "
            "authority without a canonical allow",
            findings=tuple(findings),
            refusals=tuple(refusals),
        )

    if blockers:
        return unverifiable(
            name,
            "a positive control failed, so the refusals above cannot be "
            "distinguished from a machine that refuses everything",
            findings=tuple(blockers),
            refusals=tuple(refusals),
        )

    edges = len(aegis_state.EVIDENCED_EDGES)

    if not isinstance(sdk, FirewallSDK):
        return unverifiable(
            name,
            "the state machine's algebra holds, but no FirewallSDK was "
            "supplied, so no recorded history was audited "
            f"(got {type(sdk).__name__})",
            algebra="holds",
            evidenced_edges=edges,
        )

    controller = sdk.aegis

    if controller is None:
        return unverifiable(
            name,
            "the state machine's algebra holds, but Aegis is not "
            "enabled on the supplied SDK, so no recorded history was "
            "audited",
            algebra="holds",
            evidenced_edges=edges,
        )

    grants = controller.grants()
    live = controller.history_findings()
    recorded = sum(len(grant.history) for grant in grants.values())
    traversed = sum(
        1
        for grant in grants.values()
        for item in grant.history
        if (item.from_state, item.to_state)
        in aegis_state.EVIDENCED_EDGES
    )

    if live:
        return violated(
            name,
            "a recorded Aegis history breaks the state machine's own "
            "rules",
            findings=tuple(live),
            grants=len(grants),
            transitions=recorded,
        )

    if not recorded:
        return unverifiable(
            name,
            "the state machine's algebra holds and Aegis is enabled, "
            f"but none of the {len(grants)} tracked grants has recorded "
            "a transition, so no real history was audited",
            algebra="holds",
            grants=len(grants),
            evidenced_edges=edges,
        )

    return holds(
        name,
        f"terminal states are final, the only widening edges are the "
        f"{edges} that require a canonical allow, the evidence predicate "
        "accepts nothing but a genuine authorize() allow, decay never "
        f"returns a removed stage, and all {recorded} transitions "
        f"recorded across {len(grants)} grants are legal -- of which "
        f"{traversed} traversed an evidenced edge",
        grants=len(grants),
        transitions=recorded,
        evidenced_traversals=traversed,
        refusals=tuple(refusals),
    )


def _probe_snapshot(
    *,
    degraded: tuple[str, ...] = (),
) -> SecurityContextSnapshot:
    """A benign security snapshot for the UNKNOWN probes.

    Built here because nothing else in the package constructs one outside
    the continuous-authorization engine, and the probes need two snapshots
    that are *equal* under ``state_hash()`` -- which is why ``timestamp``
    can be fixed: ``_HASH_EXCLUDED_FIELDS`` excludes it.
    """

    return SecurityContextSnapshot(
        timestamp=0.0,
        capability_fingerprint="d" * 64,
        agent_id="unknown-probe-agent",
        action="payments.send",
        request_hash="e" * 64,
        identity_status="active",
        identity_version=1,
        capability_revoked=False,
        capability_expired=False,
        delegation_chain_valid=True,
        delegation_depth=1,
        max_delegation_depth=None,
        posture="normal",
        trust_findings=0,
        risk_level="low",
        policy_version="v1",
        environment="{}",
        provenance_state="observed",
        incident_active=False,
        degraded_dependencies=degraded,
    )


#: ``classify`` inputs that describe an absence, and the least severe
#: response each may produce. A missing *after* snapshot means the state a
#: decision would be re-checked against could not be read at all, so it
#: must reach at least SUSPEND; a missing *before* leaves nothing to
#: compare against, which is enough to require another look.
_ABSENCE_FLOORS: tuple[tuple[str, str, str], ...] = (
    ("no snapshots at all", "neither", "suspend"),
    ("both snapshots None", "both_none", "suspend"),
    ("no snapshot after", "after_none", "suspend"),
    ("no snapshot before", "before_none", "revalidate"),
)


def _absence_findings(
    snapshot: SecurityContextSnapshot,
) -> list[str]:
    """Sweep every trigger against every shape of missing observation."""

    findings: list[str] = []
    floors = {
        "suspend": aegis_response.AdaptiveResponse.SUSPEND,
        "revalidate": aegis_response.AdaptiveResponse.REVALIDATE,
    }

    for trigger in RevalidationTrigger:
        for label, shape, floor_name in _ABSENCE_FLOORS:
            if shape == "neither":
                classification = aegis_response.classify(trigger)
            elif shape == "both_none":
                classification = aegis_response.classify(
                    trigger,
                    before=None,
                    after=None,
                )
            elif shape == "after_none":
                classification = aegis_response.classify(
                    trigger,
                    before=snapshot,
                    after=None,
                )
            else:
                classification = aegis_response.classify(
                    trigger,
                    before=None,
                    after=snapshot,
                )

            response = classification.response
            floor = floors[floor_name]

            if response is aegis_response.AdaptiveResponse.KEEP:
                findings.append(
                    f"classify({trigger.value}) with {label} is KEEP, "
                    "so a security state that could not be read keeps "
                    "authority untouched"
                )
                continue

            if (
                aegis_response.RESPONSE_SEVERITY[response]
                < aegis_response.RESPONSE_SEVERITY[floor]
            ):
                findings.append(
                    f"classify({trigger.value}) with {label} is "
                    f"{response.value}, less severe than "
                    f"{floor.value}"
                )

    return findings


def _revalidation_probe_sdk() -> FirewallSDK:
    """A scratch SDK with Aegis and continuous authorization wired.

    Its own instance for ENVELOPE_SOUNDNESS's reason: the grid below
    suspends and revokes things, and doing that to the caller's SDK would
    change the posture of the system under test. Periodic revalidation is
    off so that every revalidation measured is one this check asked for.
    """

    from firewall.aegis import AegisController
    from firewall.continuous_auth.monitor import MonitoringConfig

    controller = AegisController()
    sdk = FirewallSDK(
        aegis=controller,
        continuous_auth_config=MonitoringConfig(
            enable_periodic_revalidation=False,
        ),
    )
    sdk.generate_key("revalidation-consistency-key")

    return sdk


#: ``(label, change)`` for each security-state change the grid applies
#: after a cached allow. ``change`` takes ``(sdk, controller, capability,
#: fingerprint)`` and mutates state through public API only.
#:
#: The first entry must be the positive control: no change, and the
#: decision must still revalidate as allowed. Without it every claim below
#: is satisfied by an engine that reports a denial unconditionally, and a
#: ``HOLDS`` here would establish nothing.
_REVALIDATION_PROBES: tuple[tuple[str, Any], ...] = (
    (
        "positive control: nothing changed",
        lambda sdk, controller, capability, fingerprint: None,
    ),
    (
        "aegis suspension",
        lambda sdk, controller, capability, fingerprint: controller.suspend(
            fingerprint,
            key="invariant-suspend",
            reason="REVALIDATION_CONSISTENCY probe",
        ),
    ),
    (
        "aegis narrowing that excludes the request",
        lambda sdk, controller, capability, fingerprint: controller.narrow(
            fingerprint,
            key="invariant-narrow",
            constraints={"amount_max": 1},
            reason="REVALIDATION_CONSISTENCY probe",
        ),
    ),
    (
        "capability revocation",
        lambda sdk, controller, capability, fingerprint: sdk.revoke(
            capability,
            reason="REVALIDATION_CONSISTENCY probe",
        ),
    ),
    (
        "issuer revocation",
        lambda sdk, controller, capability, fingerprint: sdk.revoke_issuer(
            capability.issuer,
        ),
    ),
    (
        # The change no injected component is needed to cause: an ordinary
        # over-ceiling request. ``_apply_denial`` records a refusal for every
        # ``constraint_denied``, which latches ``_gate_refusal`` against this
        # agent, capability and action -- so the *next* authorization of the
        # in-range request is denied ``refusal_state`` even though the request
        # itself never changed. Before v2.5's ``_probe_refusal``, the snapshot
        # could not see that, and this probe reported a stale allow.
        "latched refusal from an over-ceiling request",
        lambda sdk, controller, capability, fingerprint: sdk.authorize(
            capability,
            _REVALIDATION_ACTION,
            {"amount": 10_000},
        ),
    ),
)

#: The action and request the grid authorizes, sized to sit inside the
#: capability's constraints so the control is an allow and every denial is
#: attributable to the change under test.
_REVALIDATION_ACTION = "payments.send"
_REVALIDATION_REQUEST = {"amount": 10}


def _revalidation_divergence(
    label: str,
    change: Any,
) -> tuple[Optional[str], Optional[str], Optional[bool]]:
    """Apply one change and compare the two surfaces.

    Returns ``(finding, unresolved, allowed)``. At most one of the first
    two is set. ``allowed`` is what revalidation reported, for the
    positive control's benefit.
    """

    try:
        sdk = _revalidation_probe_sdk()
    except Exception as error:  # noqa: BLE001
        return (
            None,
            f"{label}: the probe SDK could not be built: "
            f"{type(error).__name__}: {error}",
            None,
        )

    try:
        capability = sdk.issue(
            agent="revalidation-probe-agent",
            capability="payments.*",
            constraints={"amount_max": 100},
        )
        fingerprint = sdk.fingerprint(capability)
        sdk.aegis.register(
            fingerprint,
            agent_id=capability.agent_id,
            capability=capability.capability,
        )

        first = sdk.authorize_continuous(
            capability,
            _REVALIDATION_ACTION,
            _REVALIDATION_REQUEST,
        )

        if not first.allowed:
            return (
                None,
                f"{label}: the decision to be revalidated was not allowed "
                f"({first.reason}), so no cached allow was under test",
                None,
            )

        change(sdk, sdk.aegis, capability, fingerprint)

        canonical = sdk.authorize(
            capability,
            _REVALIDATION_ACTION,
            _REVALIDATION_REQUEST,
        )
        report = sdk.revalidate(
            capability,
            _REVALIDATION_ACTION,
            _REVALIDATION_REQUEST,
        )
    except Exception as error:  # noqa: BLE001
        return (
            None,
            f"{label}: the probe raised {type(error).__name__}: {error}",
            None,
        )
    finally:
        try:
            sdk.close()
        except Exception:  # noqa: BLE001 - teardown is not a finding
            pass

    if report.revalidated_allowed and not canonical.allowed:
        return (
            f"{label}: revalidate() reported allowed while authorize() "
            f"denied {canonical.reason!r} "
            f"(state_changed={report.state_changed}, "
            f"authority_revoked={report.authority_revoked}, "
            f"reason={report.reason!r})",
            None,
            report.revalidated_allowed,
        )

    return None, None, report.revalidated_allowed


def check_revalidation_consistency() -> InvariantResult:
    """Revalidation never reports an authority the boundary denies.

    The claim is one-directional, and the direction is the whole point::

        revalidate().revalidated_allowed
            =>  FirewallSDK.authorize() allows

    The converse is not claimed. The engine subtracts from a canonical
    verdict when a configured security dependency cannot be read -- see
    ``ContinuousAuthorizationEngine.effective_verdict`` -- so revalidation
    reporting a denial where the boundary allows is correct behaviour and
    not a finding here. More restrictive is always permitted; less
    restrictive never is.

    This invariant exists because nothing else could see the v2.5 defect it
    now covers. ``revalidate()`` constructs no ``AuthorizationResult``; it
    reports a ``bool`` on a ``RevalidationResult``. AUTHORIZATION_UNIQUENESS
    and MODEL_NON_AUTHORITY census *verdict construction*, so a stale
    ``revalidated_allowed=True`` is invisible to both, and all fifteen
    invariants stayed green while an Aegis suspension left the continuous
    authorization surface reporting an allow the boundary refused. The
    mechanism was a snapshot that did not cover the restriction store:
    ``state_hash()`` could not move, so the unchanged-state fast path
    answered from the cached verdict.

    The grid's last probe is the same mechanism on a second gate input,
    found while checking this invariant's own coverage: a latched refusal
    also moved none of the snapshot's fields, and reaching it needed no
    injected component at all -- one over-ceiling request through
    ``authorize()`` records the refusal itself. Covered by
    ``_probe_refusal``.

    Probed over :data:`_REVALIDATION_PROBES`, each on a fresh scratch SDK,
    each change applied through public API only. The positive control runs
    first and must be allowed.

    **What this does not establish.** Not exhaustiveness: the grid samples
    six state changes and a seventh shape -- an unreadable restriction store
    -- is exercised in ``tests/test_v2_5_stale_revalidation.py`` rather
    than here, because it needs a hostile injected dependency. Not the
    caller's deployment: this builds its own SDK, so it checks the code
    rather than a running estate, the same limitation ENVELOPE_SOUNDNESS
    and FAIL_CLOSED carry. Not concurrency: every probe here is
    sequential, and a restriction landing mid-revalidation is
    ``_gate_transaction``'s commit-time re-check to answer for, not this
    check's. Not the monitor: the periodic sweep is disabled in the probe
    SDK, so what is checked is ``revalidate()``, not the schedule that
    calls it.
    """

    name = "REVALIDATION_CONSISTENCY"

    findings: list[str] = []
    unresolved: list[str] = []
    control_allowed: Optional[bool] = None

    for index, (label, change) in enumerate(_REVALIDATION_PROBES):
        finding, problem, allowed = _revalidation_divergence(label, change)

        if index == 0:
            control_allowed = allowed

        if finding is not None:
            findings.append(finding)

        if problem is not None:
            unresolved.append(problem)

    if findings:
        return violated(
            name,
            f"{len(findings)} of {len(_REVALIDATION_PROBES)} probes had "
            "revalidation report an authority the canonical boundary "
            "denied",
            findings=tuple(findings),
        )

    if unresolved:
        return unverifiable(
            name,
            f"{len(unresolved)} of {len(_REVALIDATION_PROBES)} probes "
            "could not be evaluated, so consistency was not established "
            "for them",
            findings=tuple(unresolved),
        )

    if control_allowed is not True:
        return unverifiable(
            name,
            "the positive control did not revalidate as allowed, so the "
            "grid establishes nothing: every probe would agree with a "
            "boundary that denied unconditionally",
        )

    return holds(
        name,
        f"across {len(_REVALIDATION_PROBES)} security-state changes, "
        "revalidation reported an allow only where the canonical boundary "
        "allowed, and an unchanged state still revalidated as allowed",
        probes=len(_REVALIDATION_PROBES),
    )


def check_unknown_non_authorization() -> InvariantResult:

    """Nothing Aegis cannot establish is treated as permission.

    Exhaustive rather than sampled: every claim below is swept over the
    whole of a finite enum -- all fifteen revalidation triggers, all five
    responses, all five recommendations, all five impacts, all three decay
    stages -- so there is no input this check quietly does not cover.

    Four families of claim:

    1. **The mappings are total.** Every enum member has an entry, checked
       through the ``MISSING_*`` tuples each module publishes for the
       purpose. A missing entry would fall through to a default, and a
       default that happened to be permissive is the whole failure mode.
    2. **The unknown case is not the benign case.** An unrecognised
       trigger must not classify as ``KEEP``, and the two impacts that
       mean "could not size this" -- ``UNANALYZABLE`` and ``UNKNOWN`` --
       must not recommend ``ALLOW`` and must not be in ``SIZED_IMPACTS``.
    3. **The lattice identities are guarded.** ``KEEP`` and ``ALLOW`` are
       join identities, so they are what an empty analysis returns. Every
       shape of missing observation is swept to confirm a real classifier
       call cannot land on one: a missing *after* snapshot must reach
       ``SUSPEND``, and a preflight with nothing established must not
       recommend ``ALLOW``. A positive control confirms ``KEEP`` is still
       reachable when everything *is* observed -- without it these probes
       would pass against a classifier that never returns ``KEEP`` at
       all, and the guard would be vacuous.
    4. **Analysis cannot be mistaken for a verdict.** ``bool()`` on each
       of the five analysis types must raise. A truthy analysis object is
       one ``if`` away from being read as an allow.

    This says nothing about what the boundary decides. It is a claim about
    the analysis layer's defaults only: ENVELOPE_SOUNDNESS and FAIL_CLOSED
    are where the boundary's own behaviour is checked.
    """

    name = "UNKNOWN_NON_AUTHORIZATION"

    findings: list[str] = []
    blockers: list[str] = []
    response = aegis_response

    if response.MISSING_TRIGGER_MAPPINGS:
        findings.append(
            "TRIGGER_RESPONSE has no entry for "
            f"{list(response.MISSING_TRIGGER_MAPPINGS)}, so those "
            "triggers fall through to a default"
        )

    if MISSING_IMPACT_RECOMMENDATIONS:
        findings.append(
            "IMPACT_RECOMMENDATION has no entry for "
            f"{list(MISSING_IMPACT_RECOMMENDATIONS)}"
        )

    severity_tables = (
        (
            "RESPONSE_SEVERITY",
            response.AdaptiveResponse,
            response.RESPONSE_SEVERITY,
        ),
        (
            "RECOMMENDATION_SEVERITY",
            Recommendation,
            RECOMMENDATION_SEVERITY,
        ),
        (
            "DECAY_STAGE_SEVERITY",
            aegis_decay.DecayStage,
            aegis_decay.DECAY_STAGE_SEVERITY,
        ),
    )

    for label, enum, table in severity_tables:
        for member in enum:
            if member not in table:
                findings.append(
                    f"{label} has no entry for {member.value}, so it "
                    "cannot be ordered against the others"
                )

    unknown_response = response.UNKNOWN_TRIGGER_RESPONSE

    if unknown_response is response.AdaptiveResponse.KEEP:
        findings.append(
            "UNKNOWN_TRIGGER_RESPONSE is KEEP, so a trigger the table "
            "does not recognise changes nothing"
        )
    elif response.RESPONSE_SEVERITY[
        unknown_response
    ] < response.RESPONSE_SEVERITY[
        response.AdaptiveResponse.REVALIDATE
    ]:
        findings.append(
            f"UNKNOWN_TRIGGER_RESPONSE is {unknown_response.value}, "
            "less severe than REVALIDATE"
        )

    for impact in (
        Impact.UNANALYZABLE,
        Impact.UNKNOWN,
    ):
        recommendation = IMPACT_RECOMMENDATION.get(impact)

        if recommendation is Recommendation.ALLOW:
            findings.append(
                f"impact {impact.value} recommends ALLOW, so a blast "
                "radius that could not be sized reads as a small one"
            )

        if impact in SIZED_IMPACTS:
            findings.append(
                f"impact {impact.value} is in SIZED_IMPACTS, so an "
                "unsized estate can satisfy the ALLOW precondition"
            )

    snapshot = _probe_snapshot()
    findings.extend(_absence_findings(snapshot))

    # Positive control for the KEEP guard. The same snapshot on both sides
    # is genuinely unchanged -- state_hash() excludes timestamp -- so a
    # classifier that cannot return KEEP here cannot return it at all, and
    # every "is not KEEP" probe above would be passing for free.
    control = response.classify(
        RevalidationTrigger.POLICY_CHANGED,
        before=snapshot,
        after=snapshot,
    )

    if control.response is not response.AdaptiveResponse.KEEP:
        blockers.append(
            "classify(policy_changed) over two identical snapshots is "
            f"{control.response.value}, not KEEP, so the KEEP guard "
            "cannot be shown to be doing any work"
        )

    degraded_control = response.classify(
        RevalidationTrigger.POLICY_CHANGED,
        before=_probe_snapshot(degraded=("risk",)),
        after=_probe_snapshot(degraded=("risk",)),
    )

    if degraded_control.response is response.AdaptiveResponse.KEEP:
        findings.append(
            "classify over two snapshots that both report a degraded "
            "dependency is KEEP, so being blind to a configured "
            "security dependency reads as nothing having changed"
        )

    unrecognised = response.classify(
        "not-a-trigger",
        before=snapshot,
        after=snapshot,
    )

    if unrecognised.response is response.AdaptiveResponse.KEEP:
        findings.append(
            "classify with an unrecognised trigger string is KEEP, so "
            "an unknown reason for re-examining a grant changes nothing"
        )

    # ALLOW reachability, through the public pipeline rather than its
    # private precondition helper: a caller can only get a recommendation
    # this way, so this is the path that has to hold.
    blind = run_preflight("payments.send", {"amount": 10})

    if blind.recommendation is Recommendation.ALLOW:
        findings.append(
            "preflight with no envelope, no blast radius and no "
            "evidence recommends ALLOW, so an analysis that established "
            "nothing reads as a clean one"
        )

    if blind.impact in SIZED_IMPACTS:
        findings.append(
            f"preflight with no blast radius reports impact "
            f"{blind.impact.value}, which is a sized impact; nothing "
            "was measured"
        )

    bottom = aegis_envelope.bottom_envelope("invariant probe")

    if not bottom.bottom:
        findings.append(
            "bottom_envelope() does not report itself as bottom"
        )

    now = time.time()
    exclusion_probes: tuple[tuple[str, tuple[Any, ...]], ...] = (
        ("no action, request or clock", (None, None, None)),
        ("an action only", ("payments.send", None, None)),
        ("a request only", (None, {"amount": 1}, None)),
        (
            "an action, a request and a clock",
            ("payments.send", {"amount": 1}, now),
        ),
        ("an unusable clock", ("payments.send", {"amount": 1}, "now")),
    )

    for label, arguments in exclusion_probes:
        if bottom.excludes(*arguments) is None:
            findings.append(
                f"a bottom envelope excludes nothing given {label}, so "
                "a chain that could not be resolved reads as one that "
                "permits the request"
            )

    analyses: tuple[tuple[str, Any], ...] = (
        ("AuthorityEnvelope", bottom),
        (
            "BlastRadius",
            aegis_blast.BlastRadius(fingerprint="d" * 64),
        ),
        (
            "AegisGrant",
            aegis_state.AegisGrant(
                fingerprint="d" * 64,
                agent_id="unknown-probe-agent",
                capability="payments.send",
            ),
        ),
        ("Classification", control),
        ("Preflight", blind),
    )

    for label, analysis in analyses:
        try:
            truth = bool(analysis)
        except TypeError:
            continue
        except Exception as error:  # noqa: BLE001
            findings.append(
                f"bool({label}) raised {type(error).__name__} rather "
                f"than TypeError: {error}"
            )
            continue

        findings.append(
            f"bool({label}) returned {truth!r}; an analysis object that "
            "answers a truth test can stand in for a decision in an "
            "`if` and be read as an allow"
        )

    if findings:
        return violated(
            name,
            "the analysis layer treats something it could not establish "
            "as benign",
            findings=tuple(findings),
        )

    if blockers:
        return unverifiable(
            name,
            "a positive control failed, so the probes above cannot be "
            "distinguished from an analysis layer that objects to "
            "everything",
            findings=tuple(blockers),
        )

    return holds(
        name,
        f"across all {len(tuple(RevalidationTrigger))} triggers and "
        f"{len(_ABSENCE_FLOORS)} shapes of missing observation no "
        "classification is KEEP while KEEP stays reachable when "
        "everything is observed; the unsized impacts recommend nothing "
        "permissive; a bottom envelope excludes every probe; and none "
        f"of the {len(analyses)} analysis types answers a truth test",
        triggers=len(tuple(RevalidationTrigger)),
        absence_shapes=len(_ABSENCE_FLOORS),
        analysis_types=len(analyses),
    )
