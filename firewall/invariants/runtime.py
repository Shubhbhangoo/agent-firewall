"""Runtime (live-state) checks for the v2.2-v3.4 security invariants.

Sixteen of the twenty-five invariants are properties of a *running* system:
whether the delegation edges that actually exist narrow, whether a
revocation actually propagated, whether the authorization path denies
rather than raises on hostile input, whether a simulation left the
control plane untouched, whether the envelope a chain projects is
contained in its parent's, whether every exclusion the envelope states
is one the boundary actually enforces, whether a revalidation ever
reports an authority the boundary denies, whether the Aegis histories that
were recorded, recorded executions, and recorded verification claims
are legal, and whether every anchor read on a progression path is one the
world confirmed. Those cannot be read off the source, so they are checked
here against a live :class:`~firewall.sdk.FirewallSDK`.

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

import ast
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
from firewall.anchor import (
    ANCHOR_FINDING_KINDS,
    AnchorJournal,
    AnchorKind,
)
from firewall.authorization import AuthorizationResult
from firewall.authority_epoch import (
    EPOCH_BRACKET_HELPERS,
    EPOCH_MEASUREMENT_BRACKETS,
    WIDENING_WRITES,
    AuthorityEpoch,
    epoch_of,
)
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
from firewall.invariants import source, static
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
from firewall.temporal import (
    TEMPORAL_ANOMALY_PREFIX,
    TEMPORAL_WINDOW_CLOSED,
    TEMPORAL_WINDOW_SITES,
    TemporalGuard,
    temporal_of,
)
from firewall.external_attestation import AttestationOutcome
from firewall.execution_lease import ExecutionState
from firewall.lineage import (
    FINDING_KINDS,
    ExecutionLineage,
    LineageJournal,
    LineageOutcome,
    LineageStage,
    binding_digest,
    completeness_problems,
)
from firewall.state_commit import (
    STATE_COMMIT_ANCHOR,
    STATE_COMMIT_HELPER,
    STATE_COMMIT_WRITES,
    StateCommitJournal,
    state_commit_of,
)


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


_EPOCH_NAME = "AUTHORITY_EPOCH_COVERAGE"


#: Memo for lookups derived purely from a parsed module.
#:
#: An ``ast.Module`` is not hashable, so the key is ``id(tree)`` guarded by an
#: identity check, and the tree itself is held in the value -- which is what
#: keeps the id valid for the life of the process. A recycled id is therefore a
#: *miss* rather than a wrong answer.
#:
#: This exists because every census re-derived the same per-module maps: one
#: ``assert_all`` walks each module twenty-five times, once per invariant, and
#: the two owner maps below were the largest single share of that. They are
#: functions of the tree and of nothing else -- not of any declaration a test
#: may monkeypatch -- so caching them cannot change an answer. Contrast the
#: *census* functions themselves, which read monkeypatchable declaration sets
#: and are deliberately not cached.
_TREE_MEMO: dict[str, dict[int, tuple[ast.AST, Any]]] = {}

#: "No memo entry", distinct from a cached but empty mapping.
_MEMO_MISS: Any = object()


def _tree_memo_get(slot: str, tree: ast.AST) -> Any:
    cache = _TREE_MEMO.get(slot)

    if cache is None:
        return _MEMO_MISS

    hit = cache.get(id(tree))

    if hit is not None and hit[0] is tree:
        return hit[1]

    return _MEMO_MISS


def _tree_memo_put(slot: str, tree: ast.AST, value: Any) -> None:
    _TREE_MEMO.setdefault(slot, {})[id(tree)] = (tree, value)


def _qualified_functions(
    tree: ast.AST,
) -> dict[int, str]:
    """Map every call node's ``id`` to its enclosing ``Class.method`` name.

    :func:`firewall.invariants.source.call_owners` returns bare function
    names, which is enough for the checks that ask *whether* a call is
    inside a function. It is not enough here: the census names methods,
    and two classes in one module may both define ``clear``. So this
    walks the tree itself and carries the dotted prefix down.

    A call at module level is absent from the mapping rather than mapped
    to a sentinel, matching ``call_owners``.

    Memoised per tree -- see :data:`_TREE_MEMO`. The walk is the cost, and
    every census wants the same answer for the same module.
    """

    cached = _tree_memo_get("qualified_functions", tree)

    if cached is not _MEMO_MISS:
        return cached

    owners: dict[int, str] = {}

    def descend(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.Call) and prefix:
                owners[id(child)] = prefix

            if isinstance(child, ast.ClassDef):
                descend(
                    child,
                    f"{prefix}.{child.name}" if prefix else child.name,
                )
            elif isinstance(
                child,
                (ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                descend(
                    child,
                    f"{prefix}.{child.name}" if prefix else child.name,
                )
            else:
                descend(child, prefix)

    descend(tree, "")

    _tree_memo_put("qualified_functions", tree, owners)

    return owners


def _census_owner(owner: str) -> str:
    """Longest census-shaped prefix of a qualified owner name.

    A bracket written inside a closure is attributed to the closure by
    :func:`_qualified_functions`, so ``SecurityContext.reset.inner``
    has to count as ``SecurityContext.reset``. Reducing to the prefix
    keeps the census readable -- it names methods, not the incidental
    closures inside them -- without letting a bracket hide in one.

    Both censuses are consulted, because the reduction is about closures,
    not about which list the enclosing function belongs to. A measurement
    bracket written inside a thread body is still the benchmark's.
    """

    parts = owner.split(".")
    named = {name for _, name in WIDENING_WRITES}
    named |= {name for _, name in EPOCH_MEASUREMENT_BRACKETS}

    for size in range(len(parts), 0, -1):
        candidate = ".".join(parts[:size])

        if candidate in named:
            return candidate

    return owner


def _epoch_brackets(
    module: str,
    tree: ast.Module,
) -> set[str]:
    """Qualified names in ``tree`` that open an epoch interval.

    Recognised syntactically: any call whose rightmost name is in
    :data:`~firewall.authority_epoch.EPOCH_BRACKET_HELPERS`. That is
    deliberately loose -- a call to some unrelated ``widening()`` would
    be counted -- because the two failure directions are asymmetric. A
    false positive here makes the census *require* an entry, which a
    reviewer resolves by looking; a false negative would let a real
    widening path go unbracketed and report a pass.
    """

    owners = _qualified_functions(tree)
    found: set[str] = set()

    for call in source.walk_calls(tree):
        name = source.called_name(call)

        if name not in EPOCH_BRACKET_HELPERS:
            continue

        owner = owners.get(id(call))

        if owner is None:
            found.add(f"<module level in {module}>")
            continue

        found.add(_census_owner(owner))

    return found


def _epoch_source_findings() -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Both directions of the census check, plus any parse failures.

    Returns ``(findings, notes)``. A module the census names that does
    not exist is a finding, not a skip: a census entry pointing at a
    deleted file states a coverage claim about nothing.
    """

    root = source.package_root()

    if root is None:
        return (
            ("the firewall package source could not be located",),
            (),
        )

    declared: dict[str, set[str]] = {}

    for module, function in WIDENING_WRITES:
        declared.setdefault(module, set()).add(function)

    findings: list[str] = []
    notes: list[str] = []
    bracketed: dict[str, set[str]] = {}
    present: set[str] = set()

    for path in source.source_modules(root):
        module = source.relative_name(path, root)
        present.add(module)

        try:
            tree = source.parse_module(path)
        except source.ParseFailure as error:
            findings.append(f"{module}: could not be parsed: {error}")
            continue

        found = _epoch_brackets(module, tree)

        if found:
            bracketed[module] = found

    for module, functions in sorted(declared.items()):
        if module not in present:
            findings.append(
                f"{module}: named by the widening census but absent "
                "from the package"
            )
            continue

        found = bracketed.get(module, set())

        for function in sorted(functions):
            if function not in found:
                findings.append(
                    f"{module}:{function} is declared a widening write "
                    "but opens no epoch interval"
                )

    # The measurement census gets the same treatment, and for the same
    # reason: an exemption nobody has to maintain is how a real widening
    # write eventually inherits one. A stale entry here is a finding, not
    # a harmless leftover.
    for module, function in sorted(EPOCH_MEASUREMENT_BRACKETS):
        if module not in present:
            findings.append(
                f"{module}: named as a measurement bracket but absent "
                "from the package"
            )
            continue

        if function not in bracketed.get(module, set()):
            findings.append(
                f"{module}:{function} is exempted as a measurement "
                "bracket but opens no epoch interval"
            )

    for module, found in sorted(bracketed.items()):
        for owner in sorted(found):
            if (module, owner) in WIDENING_WRITES:
                continue

            if (module, owner) in EPOCH_MEASUREMENT_BRACKETS:
                continue

            if module == "firewall/authority_epoch.py":
                # The mechanism's own definitions and its ``widen``
                # fallback. Bracketing is what this module is for.
                continue

            findings.append(
                f"{module}:{owner} opens an epoch interval but is not "
                "in the widening census"
            )

    notes.append(
        f"{len(WIDENING_WRITES)} declared widening writes across "
        f"{len(declared)} modules"
    )
    notes.append(
        f"{len(EPOCH_MEASUREMENT_BRACKETS)} measurement bracket(s) "
        "exempted, each verified to still bracket"
    )

    return tuple(findings), tuple(notes)


def check_authority_epoch_coverage(
    sdk: Optional[Any] = None,
) -> InvariantResult:
    """Every widening write is observable at the boundary's commit point.

    Two halves, and the result is the weaker of them.

    **Source.** Every write named in
    :data:`~firewall.authority_epoch.WIDENING_WRITES` opens an epoch
    interval, and every epoch interval in the package is opened by a
    write the census names. The second direction is what keeps the claim
    true over time: bracketing a newly added widening path is not enough
    to pass, because the census literal is where "these are all of them"
    is asserted.

    **Live.** Every store the supplied SDK wires is bound to *that
    SDK's* epoch. Construction already refuses to complete when a store
    cannot be bound, so this half is aimed at the case construction
    cannot see: a store replaced afterwards, or bound to a different
    epoch than the one :meth:`FirewallSDK.authorize` samples.

    Without an SDK the live half is ``UNVERIFIABLE`` rather than passing,
    so a report over a source checkout says so.
    """

    findings, notes = _epoch_source_findings()

    if findings:
        return violated(
            _EPOCH_NAME,
            f"{len(findings)} widening write(s) are not covered by an "
            "epoch interval, so a concurrent widening could land inside "
            "an authorization unobserved",
            findings=findings,
            declared=len(WIDENING_WRITES),
        )

    problem = _require_sdk(sdk, _EPOCH_NAME)

    if problem is not None:
        return unverifiable(
            _EPOCH_NAME,
            "the source census holds in both directions, but no "
            "FirewallSDK was supplied, so the live bindings could not "
            "be inspected",
            declared=len(WIDENING_WRITES),
            source_notes=notes,
        )

    epoch = getattr(sdk, "authority_epoch", None)

    if not isinstance(epoch, AuthorityEpoch):
        return violated(
            _EPOCH_NAME,
            "the SDK exposes no AuthorityEpoch, so the boundary has "
            "nothing to compare at its commit point",
            findings=(f"authority_epoch is {type(epoch).__name__}",),
        )

    stores = sdk._authority_epoch_stores()
    unbound: list[str] = []

    for label, component in sorted(stores.items()):
        if component is None:
            continue

        if epoch_of(component) is not epoch:
            unbound.append(
                f"{label} is not bound to this SDK's authority epoch"
            )

    if unbound:
        return violated(
            _EPOCH_NAME,
            f"{len(unbound)} of the SDK's authority stores would widen "
            "without the boundary observing it",
            findings=tuple(unbound),
            stores=len(stores),
        )

    wired = sum(1 for value in stores.values() if value is not None)

    return holds(
        _EPOCH_NAME,
        f"all {len(WIDENING_WRITES)} declared widening writes open an "
        f"epoch interval, no other call does, and all {wired} store(s) "
        "this SDK wires are bound to the epoch its boundary samples",
        declared=len(WIDENING_WRITES),
        wired_stores=wired,
        declared_stores=len(stores),
    )




# =====================================================================
# EXECUTION_AUTHORITY_CONTINUITY (v2.7)
# =====================================================================
#
# v2.7's claim: an execution cannot progress
# ``AUTHORIZED -> LEASE_ISSUED -> RESERVED -> STARTED -> COMPLETED`` unless
# the authority basis remains valid, and no record may claim a clean
# ``COMPLETED`` when the basis cannot be established at completion. The
# check has three halves:

from firewall.execution_lease import (
    ALLOWED_TRANSITIONS,
    TERMINAL_STATES,
    ExecutionState,
    is_terminal,
    transition_allowed,
)

_EXECUTION_NAME = "EXECUTION_AUTHORITY_CONTINUITY"

#: The state-machine edges the SDK may drive on the execution lease store.
#:
#: Every function in this set is an SDK enforcement method whose
#: transitions are preceded by the deny-only continuity validation. The
#: set is a census in the same sense as :data:`WIDENING_WRITES`: it is
#: where the sentence "these are the only execution paths" is recorded,
#: and a reviewer has to touch this literal to add a new one.
EXECUTION_STORE_MUTATOR_OWNERS = frozenset(
    {
        ("firewall/sdk.py", "FirewallSDK.authorize_execution"),
        ("firewall/sdk.py", "FirewallSDK.reserve_execution"),
        ("firewall/sdk.py", "FirewallSDK.start_execution"),
        ("firewall/sdk.py", "FirewallSDK.complete_execution"),
        ("firewall/sdk.py", "FirewallSDK.abort_execution"),
        ("firewall/sdk.py", "FirewallSDK.expire_lapsed_executions"),
        # Terminalizes a lease after the continuity validation refused a
        # progression; moves records only into DENIED/REVOKED/EXPIRED.
        ("firewall/sdk.py", "FirewallSDK._burn"),
    }
)

#: The store mutators whose call sites the census constrains.
EXECUTION_STORE_MUTATOR_CALLS = frozenset(
    {
        "issue",
        "transition",
        "expire_lapsed",
        "bind_execution",
    }
)

_OWNER_NAMES = frozenset(name for _, name in EXECUTION_STORE_MUTATOR_OWNERS)


def _execution_census_owner(owner: str) -> str:
    """Longest census-shaped prefix of a qualified owner name.

    Same closure rule as :func:`_census_owner`: a call inside a nested
    helper is still the enforcement method's.
    """

    parts = owner.split(".")

    for size in range(len(parts), 0, -1):
        candidate = ".".join(parts[:size])

        if candidate in _OWNER_NAMES:
            return candidate

    return owner


def _execution_store_source_findings() -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Both directions of the call-site census, plus parse failures.

    Scans every ``firewall`` module for a call whose attribute chain names
    an execution lease store (``...execution_leases.<mutator>(...)``) and
    requires the enclosing function to be one of the declared enforcement
    methods -- or the mechanism module itself. Direction two is the one
    that matters over time: a second execution path added anywhere else
    in the package fails here even if it is perfectly bracketed.
    """

    root = source.package_root()

    if root is None:
        return (
            ("the firewall package source could not be located",),
            (),
        )

    findings: list[str] = []
    notes: list[str] = []
    found: dict[str, set[str]] = {}
    present: set[str] = set()

    for path in source.source_modules(root):
        module = source.relative_name(path, root)
        present.add(module)

        try:
            tree = source.parse_module(path)
        except source.ParseFailure as error:
            findings.append(f"{module}: could not be parsed: {error}")
            continue

        owners = _qualified_functions(tree)

        for call in source.walk_calls(tree):
            func = call.func

            if not isinstance(func, ast.Attribute):
                continue

            if func.attr not in EXECUTION_STORE_MUTATOR_CALLS:
                continue

            if not _attribute_chain_has(func.value, "execution_leases"):
                continue

            owner = owners.get(id(call))

            if owner is None:
                findings.append(
                    f"{module}: <module level> calls "
                    f"{func.attr} on an execution lease store"
                )
                continue

            found.setdefault(module, set()).add(
                _execution_census_owner(owner)
            )

    for module, functions in sorted(EXECUTION_STORE_MUTATOR_OWNERS):
        if module not in present:
            findings.append(
                f"{module}: named by the execution-store census but "
                "absent from the package"
            )
            continue

        for function in sorted({functions}):
            if function not in found.get(module, set()):
                findings.append(
                    f"{module}:{function} is declared an execution "
                    "lease store caller but calls no execution store "
                    "mutator"
                )

    for module, functions in sorted(found.items()):
        for owner in sorted(functions):
            if (module, owner) in EXECUTION_STORE_MUTATOR_OWNERS:
                continue

            if module == "firewall/execution_lease.py":
                # The mechanism's own internals (its lock, its CAS, its
                # expiry sweep) drive the store by definition.
                continue

            findings.append(
                f"{module}:{owner} drives the execution lease store but "
                "is not a declared execution enforcement path"
            )

    notes.append(
        f"{len(EXECUTION_STORE_MUTATOR_OWNERS)} declared execution "
        "store callers, each verified to call a mutator"
    )

    return tuple(findings), tuple(notes)


def _attribute_chain_has(
    node: ast.AST,
    token: str,
) -> bool:
    """Whether an attribute chain (``self.execution_leases``) names token."""

    while isinstance(node, ast.Attribute):
        if node.attr == token:
            return True
        node = node.value

    return False


def _state_machine_findings() -> tuple[str, ...]:
    """Algebra of the execution state machine.

    Checked against the code, not against a deployment: terminal phases
    must have no outgoing edge, every declared edge must name a real
    phase, and the forbidden resurrections (``COMPLETED -> STARTED``,
    ``REVOKED -> STARTED``, ``EXPIRED -> STARTED``) must be refused by
    both the table and the total predicate.
    """

    findings: list[str] = []

    for state in ExecutionState:
        edges = ALLOWED_TRANSITIONS.get(state)

        if is_terminal(state):
            if edges is not None and edges:
                findings.append(
                    f"{state.value} is terminal but declares outgoing "
                    "edges"
                )
            continue

        if edges is None:
            findings.append(
                f"{state.value} is not terminal but declares no "
                "outgoing edges"
            )
            continue

        for target in edges:
            if not isinstance(target, ExecutionState):
                findings.append(
                    f"{state.value} declares a non-phase target "
                    f"{target!r}"
                )
                continue
            if not transition_allowed(state, target):
                findings.append(
                    f"{state.value} -> {target.value} is declared but "
                    "transition_allowed refuses it"
                )

    for forbidden_from, forbidden_to in (
        (ExecutionState.COMPLETED, ExecutionState.STARTED),
        (ExecutionState.REVOKED, ExecutionState.STARTED),
        (ExecutionState.EXPIRED, ExecutionState.STARTED),
        (ExecutionState.DENIED, ExecutionState.STARTED),
        (ExecutionState.ABORTED, ExecutionState.STARTED),
    ):
        if transition_allowed(forbidden_from, forbidden_to):
            findings.append(
                f"{forbidden_from.value} -> {forbidden_to.value} must "
                "never be legal"
            )

    declared_terminal = {
        state for state in ExecutionState if is_terminal(state)
    }
    if declared_terminal != TERMINAL_STATES:
        findings.append(
            "is_terminal and TERMINAL_STATES disagree on which phases "
            "are terminal"
        )

    return tuple(findings)


def _record_findings(record: Any) -> tuple[str, ...]:
    """Record-level hygiene for one execution lease.

    A record is the store's authority on what happened. Every history
    edge must be a legal transition, the record's current phase must be
    where its history stopped, and a clean ``COMPLETED`` must carry the
    three per-phase validity flags and ``executed=True``. A terminal
    failure that followed a ``STARTED`` execution must say the action ran
    (``executed=True``); a terminal failure before any start must not.
    """

    findings: list[str] = []
    label = getattr(record, "lease_id", None)
    label = f"{label[:8]}..." if isinstance(label, str) else "?"

    history = getattr(record, "history", ())
    state = getattr(record, "state", None)

    started = False

    for index, (from_state, to_state, _, _) in enumerate(history):
        if not transition_allowed(from_state, to_state):
            findings.append(
                f"lease {label}: history step {index} records illegal "
                f"transition {from_state.value} -> {to_state.value}"
            )
        if from_state is ExecutionState.STARTED:
            started = True

    if history:
        last_to = history[-1][1]
        if state is not None and last_to != state:
            findings.append(
                f"lease {label}: history ends at {last_to.value} but "
                f"the record claims {state.value}"
            )

    if state is ExecutionState.COMPLETED:
        for flag in (
            "reserve_authority_valid",
            "start_authority_valid",
            "complete_authority_valid",
        ):
            if getattr(record, flag, None) is not True:
                findings.append(
                    f"lease {label}: COMPLETED with {flag} "
                    f"{getattr(record, flag, None)!r}; a clean completion "
                    "requires every authority check to have held"
                )
        if getattr(record, "executed", False) is not True:
            findings.append(
                f"lease {label}: COMPLETED with executed=False; a "
                "completed execution must record that it ran"
            )

    if state is ExecutionState.STARTED:
        if getattr(record, "reserve_authority_valid", None) is not True:
            findings.append(
                f"lease {label}: STARTED without a valid reservation"
            )
        if getattr(record, "start_authority_valid", None) is not True:
            findings.append(
                f"lease {label}: STARTED without start_authority_valid"
            )

    if state is ExecutionState.RESERVED:
        if getattr(record, "reserve_authority_valid", None) is not True:
            findings.append(
                f"lease {label}: RESERVED without reserve_authority_valid"
            )

    if state in (
        ExecutionState.ABORTED,
        ExecutionState.DENIED,
        ExecutionState.EXPIRED,
        ExecutionState.REVOKED,
    ):
        if getattr(record, "complete_authority_valid", None) is True:
            findings.append(
                f"lease {label}: terminal in {state.value} yet claims a "
                "valid completion"
            )

        executed = getattr(record, "executed", False) is True

        if started and not executed:
            findings.append(
                f"lease {label}: STARTED then stopped in {state.value} "
                "without recording executed=True; an action that may "
                "have run must be reported as having run"
            )
        if executed and not started:
            findings.append(
                f"lease {label}: records executed=True but never "
                "STARTED; an action that never ran cannot be reported "
                "as having run"
            )

    return tuple(findings)


def check_execution_authority_continuity(
    sdk: Optional[Any],
) -> InvariantResult:
    """An execution cannot progress, or be reported clean, without authority.

    Three halves, and the result is the weakest of them.

    **Source census.** Only the declared enforcement methods on the SDK
    drive the execution lease store, and each of them does. A second
    execution path added anywhere in the package fails here even if it
    looks safe -- the census literal is where "these are all of them" is
    recorded.

    **State-machine algebra.** Terminal phases have no outgoing edges,
    the forbidden resurrections (``COMPLETED/REVOKED/EXPIRED ->
    STARTED``) are illegal, and ``is_terminal`` agrees with
    ``TERMINAL_STATES``.

    **Live records.** Every stored record follows the machine, ends where
    its history stops, and only reports what its flags support: a clean
    ``COMPLETED`` carries all three authority-valid flags and
    ``executed=True``, a ``STARTED``/``RESERVED`` record carries the flag
    its progression earned, and a terminal failure after ``STARTED``
    records that the action ran.
    """

    source_findings, source_notes = _execution_store_source_findings()

    if source_findings:
        return violated(
            _EXECUTION_NAME,
            "an execution path exists that the continuity census does "
            "not declare, or a declared path drives no execution store "
            "mutator",
            findings=source_findings,
        )

    algebra = _state_machine_findings()

    if algebra:
        return violated(
            _EXECUTION_NAME,
            "the execution state machine permits a transition it must "
            "not, or disagrees about which phases are terminal",
            findings=algebra,
        )

    problem = _require_sdk(sdk, _EXECUTION_NAME)

    if problem is not None:
        return unverifiable(
            _EXECUTION_NAME,
            "the source census and the state-machine algebra hold, but "
            "no FirewallSDK was supplied, so recorded executions could "
            "not be inspected",
            source_notes=source_notes,
        )

    records = getattr(sdk, "execution_leases", None)

    if records is None:
        return violated(
            _EXECUTION_NAME,
            "the SDK exposes no execution lease store, so no execution "
            "can be audited",
            findings=("execution_leases is None",),
        )

    try:
        stored = records.records()
    except Exception as error:  # noqa: BLE001 - unreadable is a finding
        return unverifiable(
            _EXECUTION_NAME,
            "the execution lease store could not be read: "
            f"{type(error).__name__}",
        )

    if not stored:
        return unverifiable(
            _EXECUTION_NAME,
            "the source census and the state-machine algebra hold, but "
            "no execution has been recorded, so recorded continuity "
            "could not be inspected",
            source_notes=source_notes,
        )

    record_findings: list[str] = []

    for record in stored:
        record_findings.extend(_record_findings(record))

    if record_findings:
        return violated(
            _EXECUTION_NAME,
            f"{len(record_findings)} execution record(s) claim a "
            "progression their authority basis did not support",
            findings=tuple(record_findings),
            records=len(stored),
        )

    return holds(
        _EXECUTION_NAME,
        f"the execution state machine is legal, {len(stored)} recorded "
        "execution(s) follow it and only report what their authority "
        "flags support, and no execution path drives the lease store "
        "outside the declared enforcement methods",
        records=len(stored),
        source_notes=source_notes,
    )


# =====================================================================
# SIDE_EFFECT_COMMIT_INTEGRITY (v2.8)
# =====================================================================
#
# v2.8's claim: Agent Firewall's representation of an external side
# effect never claims more certainty, authority or completion than the
# protocol actually established. A side effect must never be
# represented as successfully completed unless the firewall can
# establish what execution authority existed, what side-effect attempt
# occurred, and what completion evidence was observed. The check has
# three halves: a source census over who may drive the side-effect
# journal (both directions), the side-effect state-machine algebra,
# and the hygiene of every recorded row crossed against the lease
# journal.
#
from firewall.effect import (
    ALLOWED_EFFECT_TRANSITIONS,
    EffectOutcome,
    EffectState,
    TERMINAL_EFFECT_STATES,
    effect_transition_allowed,
    is_terminal_effect,
)

_EFFECT_NAME = "SIDE_EFFECT_COMMIT_INTEGRITY"

#: The SDK enforcement methods that may drive the side-effect journal.
#:
#: Every function in this set is an SDK protocol method whose journal
#: transitions are preceded by the deny-only lease continuity validation.
#: The set is a census in the same sense as
#: ``EXECUTION_STORE_MUTATOR_OWNERS``: it is where the sentence "these
#: are the only side-effect paths" is recorded, and a reviewer has to
#: touch this literal to add a new one.
EFFECT_STORE_MUTATOR_OWNERS = frozenset(
    {
        ("firewall/sdk.py", "FirewallSDK.prepare_effect"),
        ("firewall/sdk.py", "FirewallSDK.attempt_effect"),
        ("firewall/sdk.py", "FirewallSDK.record_effect_receipt"),
        ("firewall/sdk.py", "FirewallSDK.reconcile_effect"),
        ("firewall/sdk.py", "FirewallSDK.expire_lapsed_effects"),
    }
)

#: The journal mutators whose call sites the census constrains.
EFFECT_STORE_MUTATOR_CALLS = frozenset(
    {"create", "transition", "expire_lapsed"}
)

_EFFECT_OWNER_NAMES = frozenset(
    name for _, name in EFFECT_STORE_MUTATOR_OWNERS
)


def _effect_census_owner(owner: str) -> str:
    """Longest census-shaped prefix of a qualified owner name.

    Same closure rule as :func:`_execution_census_owner`.
    """

    parts = owner.split(".")

    for size in range(len(parts), 0, -1):
        candidate = ".".join(parts[:size])

        if candidate in _EFFECT_OWNER_NAMES:
            return candidate

    return owner


def _effect_store_source_findings() -> (
    tuple[tuple[str, ...], tuple[str, ...]]
):
    """Both directions of the side-effect journal call-site census.

    Scans every ``firewall`` module for a call whose attribute chain
    names the side-effect journal (``...effects.<mutator>(...)``) and
    requires the enclosing function to be one of the declared protocol
    methods -- or the mechanism module itself. Direction two is the one
    that matters over time: a second side-effect path added anywhere else
    in the package fails here even if it looks perfectly safe. A future
    developer who writes ``external_execute(...)`` and reaches the journal
    to record an attempt outside the protocol fails the gate.
    """

    root = source.package_root()

    if root is None:
        return (
            ("the firewall package source could not be located",),
            (),
        )

    findings: list[str] = []
    notes: list[str] = []
    found: dict[str, set[str]] = {}
    present: set[str] = set()

    for path in source.source_modules(root):
        module = source.relative_name(path, root)
        present.add(module)

        try:
            tree = source.parse_module(path)
        except source.ParseFailure as error:
            findings.append(f"{module}: could not be parsed: {error}")
            continue

        owners = _qualified_functions(tree)

        for call in source.walk_calls(tree):
            func = call.func

            if not isinstance(func, ast.Attribute):
                continue

            if func.attr not in EFFECT_STORE_MUTATOR_CALLS:
                continue

            if not _attribute_chain_has(func.value, "effects"):
                continue

            owner = owners.get(id(call))

            if owner is None:
                findings.append(
                    f"{module}: <module level> calls {func.attr} on a "
                    "side-effect journal"
                )
                continue

            found.setdefault(module, set()).add(
                _effect_census_owner(owner)
            )

    for module, function in sorted(EFFECT_STORE_MUTATOR_OWNERS):
        if module not in present:
            findings.append(
                f"{module}: named by the side-effect census but absent "
                "from the package"
            )
            continue

        if function not in found.get(module, set()):
            findings.append(
                f"{module}:{function} is declared a side-effect journal "
                "caller but calls no journal mutator"
            )

    for module, functions in sorted(found.items()):
        for owner in sorted(functions):
            if (module, owner) in EFFECT_STORE_MUTATOR_OWNERS:
                continue

            if module == "firewall/effect.py":
                # The mechanism's own internals (its lock, its CAS, its
                # expiry sweep) drive the journal by definition.
                continue

            findings.append(
                f"{module}:{owner} drives the side-effect journal but is "
                "not a declared side-effect protocol path"
            )

    notes.append(
        f"{len(EFFECT_STORE_MUTATOR_OWNERS)} declared side-effect "
        "journal callers, each verified to call a mutator"
    )

    return tuple(findings), tuple(notes)


def _effect_state_machine_findings() -> tuple[str, ...]:
    """Algebra of the side-effect state machine.

    Terminal outcomes must be irreversible (no outgoing edges), every
    declared edge must name a real phase, and the legal-edge predicate
    must agree with the table. ``UNKNOWN`` is deliberately *not* terminal
    in the machine: the one self-edge reserved for evidence-carrying
    reconciliation is legal, and nothing else may leave ``UNKNOWN``.
    """

    findings: list[str] = []

    for state in EffectState:
        edges = ALLOWED_EFFECT_TRANSITIONS.get(state)

        if is_terminal_effect(state):
            if edges is not None and edges:
                findings.append(
                    f"{state.value} is a terminal outcome but declares "
                    "outgoing edges, so a resolved side effect could be "
                    "reopened"
                )
            continue

        if edges is None:
            findings.append(
                f"{state.value} is not terminal but declares no outgoing "
                "edges"
            )
            continue

        for target in edges:
            if not isinstance(target, EffectState):
                findings.append(
                    f"{state.value} declares a non-phase target {target!r}"
                )
                continue
            if not effect_transition_allowed(state, target):
                findings.append(
                    f"{state.value} -> {target.value} is declared but "
                    "effect_transition_allowed refuses it"
                )

    # The irreversibility claims, spelled out.
    for terminal in TERMINAL_EFFECT_STATES:
        for target in EffectState:
            if effect_transition_allowed(terminal, target):
                findings.append(
                    f"{terminal.value} -> {target.value} must never be "
                    "legal: a confirmed outcome is irreversible"
                )

    # UNKNOWN's only outgoing edges are explicit resolutions plus the
    # re-stamp. Anything else added to UNKNOWN's edge set would let an
    # unresolved effect advance automatically.
    for target in ALLOWED_EFFECT_TRANSITIONS.get(
        EffectState.UNKNOWN, frozenset()
    ):
        if target not in (
            EffectState.UNKNOWN,
            EffectState.SUCCEEDED,
            EffectState.FAILED,
        ):
            findings.append(
                f"UNKNOWN -> {target.value} is legal; an unresolved side "
                "effect may only be resolved by an explicit "
                "reconciliation"
            )

    declared_terminal = {
        state
        for state in EffectState
        if is_terminal_effect(state)
    }
    if declared_terminal != TERMINAL_EFFECT_STATES:
        findings.append(
            "is_terminal_effect and TERMINAL_EFFECT_STATES disagree on "
            "which outcomes are terminal"
        )

    return tuple(findings)


def _effect_record_findings(row: Any) -> tuple[str, ...]:
    """Record-level hygiene for one side-effect journal row.

    A row is the journal's authority on one external side effect. Every
    history edge must be legal, the row's current state must be where its
    history stopped, a state may never claim an outcome its evidence does
    not support (``UNKNOWN != SUCCESS``), and a confirmed outcome may be
    entered exactly once -- a replayed receipt would show up as a second
    transition into the same terminal state.
    """

    findings: list[str] = []
    label = getattr(row, "effect_id", None)
    label = f"{label[:8]}..." if isinstance(label, str) else "?"

    history = getattr(row, "history", ())
    state = getattr(row, "state", None)
    terminal_entries = 0

    for index, (from_state, to_state, _, _) in enumerate(history):
        if not effect_transition_allowed(from_state, to_state):
            findings.append(
                f"effect {label}: history step {index} records illegal "
                f"transition {from_state.value} -> {to_state.value}"
            )
        if to_state in TERMINAL_EFFECT_STATES:
            terminal_entries += 1

    if terminal_entries > 1:
        findings.append(
            f"effect {label}: history enters a confirmed outcome "
            f"{terminal_entries} times; a replayed receipt must not "
            "produce a second completion"
        )

    if history:
        last_to = history[-1][1]
        if state is not None and last_to != state:
            findings.append(
                f"effect {label}: history ends at {last_to.value} but "
                f"the record claims {state.value}"
            )

    if state is EffectState.SUCCEEDED:
        if getattr(row, "observed_outcome", None) is not EffectOutcome.SUCCEEDED:
            findings.append(
                f"effect {label}: SUCCEEDED without a recorded success "
                "observation -- an outcome must not claim more certainty "
                "than its evidence established"
            )
        if getattr(row, "evidence_kind", None) is None:
            findings.append(
                f"effect {label}: SUCCEEDED without any evidence kind; "
                "the record cannot say who observed the completion"
            )

    if state is EffectState.FAILED:
        if getattr(row, "observed_outcome", None) is not EffectOutcome.FAILED:
            findings.append(
                f"effect {label}: FAILED without a recorded failure "
                "observation"
            )

    if state is EffectState.UNKNOWN:
        if getattr(row, "observed_outcome", None) is not EffectOutcome.UNKNOWN:
            findings.append(
                f"effect {label}: state UNKNOWN with "
                f"observed_outcome={getattr(row, 'observed_outcome', None)!r}; "
                "UNKNOWN must never be recorded as success or failure"
            )
        if getattr(row, "evidence_kind", None) is None:
            findings.append(
                f"effect {label}: UNKNOWN without an evidence kind naming "
                "who reported the uncertainty"
            )

    if state is EffectState.ATTEMPT_STARTED:
        if getattr(row, "attempt_id", None) is None:
            findings.append(
                f"effect {label}: ATTEMPT_STARTED without an attempt "
                "identifier"
            )
        if getattr(row, "observed_outcome", None) is not None:
            findings.append(
                f"effect {label}: ATTEMPT_STARTED records an observation; "
                "nothing was observed yet"
            )

    if state is EffectState.INTENT_RECORDED:
        if getattr(row, "attempt_id", None) is not None:
            findings.append(
                f"effect {label}: INTENT_RECORDED with an attempt "
                "identifier; nothing was attempted yet"
            )
        if getattr(row, "observed_outcome", None) is not None:
            findings.append(
                f"effect {label}: INTENT_RECORDED records an observation; "
                "nothing was observed yet"
            )

    if state not in TERMINAL_EFFECT_STATES and state is not EffectState.UNKNOWN:
        # A row that can still progress may not claim a terminal reason.
        if getattr(row, "terminal_reason", ""):
            findings.append(
                f"effect {label}: {state.value} carries a terminal "
                "reason but is not a confirmed outcome"
            )

    return tuple(findings)


def _effect_lease_cross_findings(sdk: FirewallSDK) -> tuple[str, ...]:
    """Cross-journal checks: a row never claims another execution's evidence.

    For every recorded side-effect row:

    * the lease it names must exist (a row bound to nothing would be a
      record of an effect no execution authorised);
    * the row's execution identity must be the lease's execution identity
      (a receipt can never belong to another execution);
    * a lease recorded COMPLETED that carries a side-effect row must show
      the effect SUCCEEDED with a success observation under currently
      valid authority -- the completed execution has the completion
      evidence the protocol requires, and nothing can be recorded as a
      clean completion over an unresolved side effect.
    """

    findings: list[str] = []

    try:
        rows = sdk.effects.records()
    except Exception as error:  # noqa: BLE001 - unreadable is a finding
        return (
            "the side-effect journal could not be read: "
            f"{type(error).__name__}",
        )

    for row in rows:
        label = f"{row.effect_id[:8]}..."

        try:
            lease = sdk.execution_leases.get(row.lease_id)
        except Exception as error:  # noqa: BLE001
            findings.append(
                f"effect {label}: its lease could not be read: "
                f"{type(error).__name__}"
            )
            continue

        if lease is None:
            findings.append(
                f"effect {label}: bound to lease {row.lease_id[:8]}... "
                "which does not exist; an effect without an authorised "
                "execution must not be represented as committed"
            )
            continue

        if (
            lease.execution_id is not None
            and row.execution_id != lease.execution_id
        ):
            findings.append(
                f"effect {label}: execution {row.execution_id!r} does not "
                f"match its lease's {lease.execution_id!r}; a receipt "
                "must not belong to another execution"
            )

        if lease.state is EffectState and False:  # pragma: no cover
            findings.append("unreachable")

        if (
            lease.state is not None
            and getattr(lease.state, "value", None) == "completed"
            and row.state is EffectState.SUCCEEDED
        ):
            if row.observed_outcome is not EffectOutcome.SUCCEEDED:
                findings.append(
                    f"effect {label}: the lease is COMPLETED but the "
                    "effect row claims no success observation"
                )
            if row.receipt_authority_valid is not True:
                findings.append(
                    f"effect {label}: the lease is COMPLETED but the "
                    "effect's receipt was not recorded under valid "
                    "authority; a clean completion requires the authority "
                    "basis to have held when the outcome was observed"
                )

    return tuple(findings)


def check_side_effect_commit_integrity(
    sdk: Optional[Any],
) -> InvariantResult:
    """A side effect is never committed without authority, evidence and
    an execution -- and is never recorded with more certainty than the
    protocol established.

    Three halves, and the result is the weakest of them.

    **Source census.** Only the declared protocol methods on the SDK
    drive the side-effect journal, and each of them does. A second
    side-effect path added anywhere in the package fails here even if it
    looks safe -- the census literal is where "these are all of them" is
    recorded.

    **State-machine algebra.** Confirmed outcomes are irreversible,
    ``UNKNOWN`` may only be resolved by an explicit reconciliation, and
    ``is_terminal_effect`` agrees with ``TERMINAL_EFFECT_STATES``.

    **Live records.** Every recorded row follows the machine, ends where
    its history stops, claims only what its evidence supports (so
    ``UNKNOWN != SUCCESS`` is true of every stored row), enters a
    confirmed outcome at most once (a replayed receipt cannot produce a
    second completion), and never claims another execution's evidence. A
    lease recorded COMPLETED over an adopted side effect carries the
    effect's success observation under valid authority -- the completion
    evidence the protocol requires.
    """

    source_findings, source_notes = _effect_store_source_findings()

    if source_findings:
        return violated(
            _EFFECT_NAME,
            "a side-effect path exists that the commit-integrity census "
            "does not declare, or a declared path drives no journal "
            "mutator",
            findings=source_findings,
        )

    algebra = _effect_state_machine_findings()

    if algebra:
        return violated(
            _EFFECT_NAME,
            "the side-effect state machine permits a transition it must "
            "not, or disagrees about which outcomes are terminal",
            findings=algebra,
        )

    problem = _require_sdk(sdk, _EFFECT_NAME)

    if problem is not None:
        return unverifiable(
            _EFFECT_NAME,
            "the source census and the state-machine algebra hold, but "
            "no FirewallSDK was supplied, so recorded side effects could "
            "not be inspected",
            source_notes=source_notes,
        )

    try:
        rows = sdk.effects.records()
    except Exception as error:  # noqa: BLE001 - unreadable is a finding
        return unverifiable(
            _EFFECT_NAME,
            "the side-effect journal could not be read: "
            f"{type(error).__name__}",
        )

    if not rows:
        # The state-machine algebra and the census are properties of the
        # code; the record-level claims need a journal that was used.
        # Without any recorded side effect the record half is
        # unexercised, and an unexercised property is not a satisfied one.
        return unverifiable(
            _EFFECT_NAME,
            "the source census and the state-machine algebra hold, but "
            "no side effect has been recorded, so record-level commit "
            "integrity could not be inspected",
            source_notes=source_notes,
        )

    row_findings: list[str] = []

    for row in rows:
        row_findings.extend(_effect_record_findings(row))

    cross_findings = _effect_lease_cross_findings(sdk)

    if row_findings or cross_findings:
        return violated(
            _EFFECT_NAME,
            "a recorded side effect claims a certainty, authority or "
            "completion the protocol did not establish",
            findings=tuple(row_findings) + tuple(cross_findings),
            records=len(rows),
        )

    return holds(
        _EFFECT_NAME,
        f"the side-effect state machine is legal, {len(rows)} recorded "
        "side effect(s) claim only what their evidence supports, each is "
        "bound to the execution that authorised it, and no side-effect "
        "path drives the journal outside the declared protocol methods",
        records=len(rows),
        source_notes=source_notes,
    )
# =====================================================================
# EFFECT_VERIFICATION_SOUNDNESS (v2.9)
# =====================================================================
#
# v2.9's claim: verification is a distinct, independently journaled
# stage between OBSERVED and COMPLETED -- AUTHORIZED =/= EXECUTED =/=
# OBSERVED =/= VERIFIED =/= COMPLETED -- and it can neither grant
# authority nor resurrect withdrawn authority. The check has three
# halves, mirroring SIDE_EFFECT_COMMIT_INTEGRITY:
#
# * a source census in both directions over who may drive the
#   verification journal, and a second census over who may start the
#   verification path (``_verify_row_claim``);
# * record hygiene: every stored claim re-derives to its own id, its
#   snapshot digest matches its own snapshot, a VERIFIED claim speaks
#   about an observation recorded under valid authority and never about
#   provider-labelled evidence through the structural method;
# * cross-journal soundness: every claim names a real effect and the
#   attempt that observed it, and a COMPLETED execution over an adopted
#   side effect carries a current VERIFIED claim with no contradiction
#   recorded against the same evidence.
#
from firewall.effect_verification import (
    STRUCTURAL_METHOD,
    VerificationOutcome,
    canonical_snapshot_digest,
    verification_binding_digest,
)

_VERIFICATION_NAME = "EFFECT_VERIFICATION_SOUNDNESS"

#: The SDK methods that may drive the verification journal.
VERIFICATION_STORE_MUTATOR_OWNERS = frozenset(
    {
        ("firewall/sdk.py", "FirewallSDK._journal_verification"),
    }
)

#: The verification-journal mutators whose call sites the census
#: constrains.
VERIFICATION_STORE_MUTATOR_CALLS = frozenset({"record"})

#: The SDK methods that may start the verification path. A function that
#: calls ``_verify_row_claim`` is a verification path; only the declared
#: protocol methods may do so, so a second completion path added
#: anywhere in the package fails here even if it looks safe.
VERIFICATION_HELPER_CALLERS = frozenset(
    {
        ("firewall/sdk.py", "FirewallSDK.verify_effect"),
        ("firewall/sdk.py", "FirewallSDK.commit_effect"),
    }
)

_VERIFICATION_HELPER_CALL = "_verify_row_claim"

_VERIFICATION_OWNER_NAMES = frozenset(
    name for _, name in VERIFICATION_STORE_MUTATOR_OWNERS
)
_VERIFICATION_HELPER_NAMES = frozenset(
    name for _, name in VERIFICATION_HELPER_CALLERS
)


def _verification_census_owner(owner: str) -> str:
    """Longest census-shaped prefix of a qualified owner name."""

    parts = owner.split(".")

    for size in range(len(parts), 0, -1):
        candidate = ".".join(parts[:size])

        if candidate in _VERIFICATION_OWNER_NAMES:
            return candidate

    return owner


def _verification_store_source_findings() -> (
    tuple[tuple[str, ...], tuple[str, ...]]
):
    """Both directions of the verification-journal call-site census.

    Scans every ``firewall`` module for a call whose attribute chain
    names the verification journal (``...verifications.<mutator>(...)``)
    and requires the enclosing function to be the one declared protocol
    journal method -- or the mechanism module itself.
    """

    root = source.package_root()

    if root is None:
        return (
            ("the firewall package source could not be located",),
            (),
        )

    findings: list[str] = []
    notes: list[str] = []
    found: dict[str, set[str]] = {}
    present: set[str] = set()

    for path in source.source_modules(root):
        module = source.relative_name(path, root)
        present.add(module)

        try:
            tree = source.parse_module(path)
        except source.ParseFailure as error:
            findings.append(f"{module}: could not be parsed: {error}")
            continue

        owners = _qualified_functions(tree)

        for call in source.walk_calls(tree):
            func = call.func

            if not isinstance(func, ast.Attribute):
                continue

            if func.attr not in VERIFICATION_STORE_MUTATOR_CALLS:
                continue

            if not _attribute_chain_has(func.value, "verifications"):
                continue

            owner = owners.get(id(call))

            if owner is None:
                findings.append(
                    f"{module}: <module level> calls {func.attr} on a "
                    "verification journal"
                )
                continue

            found.setdefault(module, set()).add(
                _verification_census_owner(owner)
            )

    for module, function in sorted(VERIFICATION_STORE_MUTATOR_OWNERS):
        if module not in present:
            findings.append(
                f"{module}: named by the verification census but absent "
                "from the package"
            )
            continue

        if function not in found.get(module, set()):
            findings.append(
                f"{module}:{function} is declared a verification journal "
                "caller but calls no journal mutator"
            )

    for module, functions in sorted(found.items()):
        for owner in sorted(functions):
            if (module, owner) in VERIFICATION_STORE_MUTATOR_OWNERS:
                continue

            if module == "firewall/effect_verification.py":
                # The mechanism's own internals drive the journal by
                # definition.
                continue

            findings.append(
                f"{module}:{owner} drives the verification journal but "
                "is not a declared verification path"
            )

    notes.append(
        f"{len(VERIFICATION_STORE_MUTATOR_OWNERS)} declared verification "
        "journal callers, each verified to call a mutator"
    )

    return tuple(findings), tuple(notes)


def _verification_helper_source_findings() -> tuple[str, ...]:
    """Who may start a verification: only the declared protocol methods.

    ``_verify_row_claim`` is the single entry point that writes a
    verification claim. A function anywhere in the package that calls it
    must be one of the declared callers (``verify_effect`` or
    ``commit_effect``) -- a second completion path that verifies
    "on the side" fails here.
    """

    root = source.package_root()

    if root is None:
        return ("the firewall package source could not be located",)

    findings: list[str] = []
    found: dict[str, set[str]] = {}
    present: set[str] = set()

    for path in source.source_modules(root):
        module = source.relative_name(path, root)
        present.add(module)

        try:
            tree = source.parse_module(path)
        except source.ParseFailure as error:
            findings.append(f"{module}: could not be parsed: {error}")
            continue

        owners = _qualified_functions(tree)

        for call in source.walk_calls(tree):
            func = call.func

            if not isinstance(func, ast.Attribute):
                continue

            if func.attr != _VERIFICATION_HELPER_CALL:
                continue

            if not (
                isinstance(func.value, ast.Name)
                and func.value.id == "self"
            ):
                continue

            owner = owners.get(id(call))

            if owner is None:
                findings.append(
                    f"{module}: <module level> starts a verification "
                    "claim"
                )
                continue

            found.setdefault(module, set()).add(
                _verification_census_owner(owner)
            )

    for module, function in sorted(VERIFICATION_HELPER_CALLERS):
        if module not in present:
            findings.append(
                f"{module}: named by the verification helper census but "
                "absent from the package"
            )
            continue

        if function not in found.get(module, set()):
            findings.append(
                f"{module}:{function} is declared a verification helper "
                "caller but calls no helper"
            )

    for module, functions in sorted(found.items()):
        for owner in sorted(functions):
            if (module, owner) in VERIFICATION_HELPER_CALLERS:
                continue
            findings.append(
                f"{module}:{owner} starts a verification claim but is "
                "not a declared verification protocol path"
            )

    return tuple(findings)


def _verification_record_findings(claim: Any) -> tuple[str, ...]:
    """Record-level hygiene for one verification claim.

    A claim is immutable and self-identifying: its stored id must
    re-derive from its binding fields (a forged or edited row disagrees
    with the id it claims), its snapshot digest must match its own
    snapshot, and what a VERIFIED verdict may say is bounded -- it speaks
    about an observation made under valid authority, and the structural
    method never confirms provider-labelled evidence.
    """

    findings: list[str] = []
    label = getattr(claim, "verification_id", None)
    label = f"{label[:8]}..." if isinstance(label, str) else "?"

    outcome = getattr(claim, "outcome", None)
    method = getattr(claim, "method", None)
    snapshot = getattr(claim, "snapshot", None) or {}
    snapshot_digest = getattr(claim, "snapshot_digest", None)

    rederived = verification_binding_digest(
        effect_id=getattr(claim, "effect_id", ""),
        attempt_id=getattr(claim, "attempt_id", ""),
        snapshot_digest=snapshot_digest or "",
        outcome=outcome,
        method=method,
    )

    if rederived != getattr(claim, "verification_id", None):
        findings.append(
            f"verification {label}: its id does not re-derive from its "
            "binding fields; the record is forged or edited"
        )

    try:
        recomputed = canonical_snapshot_digest(dict(snapshot))
    except Exception:  # noqa: BLE001 - unserialisable snapshot is corrupt
        findings.append(
            f"verification {label}: its snapshot has no stable digest"
        )
        recomputed = None

    if (
        recomputed is not None
        and snapshot_digest != recomputed
    ):
        findings.append(
            f"verification {label}: its snapshot digest does not match "
            "its own snapshot"
        )

    if outcome is VerificationOutcome.VERIFIED:
        if snapshot.get("observed_outcome") is None:
            findings.append(
                f"verification {label}: VERIFIED about a snapshot with "
                "no observed outcome"
            )
        if snapshot.get("receipt_authority_valid") is not True:
            findings.append(
                f"verification {label}: VERIFIED about an observation "
                "recorded under lost authority; verification must not "
                "resurrect a withdrawn execution"
            )
        if (
            snapshot.get("evidence_kind") == "provider_evidence"
            and method == STRUCTURAL_METHOD
        ):
            findings.append(
                f"verification {label}: the structural method records "
                "VERIFIED for provider evidence; a label is not proof"
            )
    elif outcome not in (
        VerificationOutcome.NOT_VERIFIED,
        VerificationOutcome.CONTRADICTED,
    ):
        findings.append(
            f"verification {label}: an outcome that is not a verdict"
        )

    if not isinstance(method, str) or not method:
        findings.append(
            f"verification {label}: no method named the check that "
            "produced the claim"
        )

    return tuple(findings)


def _verification_cross_findings(sdk: FirewallSDK) -> tuple[str, ...]:
    """Cross-journal soundness of every verification claim.

    For every stored claim: the effect it names must exist, and the
    claim's attempt must be the row's current attempt -- a claim never
    speaks for a different attempt. And for every COMPLETED execution
    that adopted the side-effect protocol, the effect row must carry a
    current VERIFIED claim with no contradiction on the same evidence --
    the completion gate's rule, re-derived from the records so a tampered
    or stale completion cannot hide.
    """

    findings: list[str] = []

    try:
        claims = sdk.verifications.records()
        rows = sdk.effects.records()
    except Exception as error:  # noqa: BLE001 - unreadable is a finding
        return (
            "the verification or side-effect journal could not be read: "
            f"{type(error).__name__}",
        )

    row_by_effect: dict[str, Any] = {}
    lease_by_id: dict[str, Any] = {}

    for row in rows:
        row_by_effect[row.effect_id] = row

    try:
        for lease in sdk.execution_leases.records():
            lease_by_id[lease.lease_id] = lease
    except Exception as error:  # noqa: BLE001
        return (
            "the execution lease store could not be read: "
            f"{type(error).__name__}",
        )

    for claim in claims:
        label = f"{claim.verification_id[:8]}..."
        row = row_by_effect.get(claim.effect_id)

        if row is None:
            findings.append(
                f"verification {label}: names effect "
                f"{claim.effect_id[:8]}... which has no side-effect row; "
                "a verified claim must speak about a recorded effect"
            )
            continue

        if row.attempt_id != claim.attempt_id:
            findings.append(
                f"verification {label}: names attempt "
                f"{claim.attempt_id[:8]}... but the effect row's current "
                f"attempt is {row.attempt_id[:8] if row.attempt_id else None}; "
                "a claim must not speak for another attempt"
            )

    for row in rows:
        lease = lease_by_id.get(row.lease_id)

        if lease is None:
            continue

        state_value = getattr(getattr(lease, "state", None), "value", None)

        if state_value != "completed":
            continue

        from firewall.effect import EffectState as _ES

        if row.state is not _ES.SUCCEEDED:
            continue

        try:
            current_digest = canonical_snapshot_digest(
                {
                    "state": row.state.value,
                    "observed_outcome": (
                        row.observed_outcome.value
                        if row.observed_outcome is not None
                        else None
                    ),
                    "observed_at": (
                        float(row.observed_at)
                        if row.observed_at is not None
                        else None
                    ),
                    "evidence_kind": (
                        row.evidence_kind.value
                        if row.evidence_kind is not None
                        else None
                    ),
                    "external_request_id": row.external_request_id,
                    "provider": row.provider,
                    "receipt_authority_valid": row.receipt_authority_valid,
                }
            )
        except Exception as error:  # noqa: BLE001
            findings.append(
                f"effect {row.effect_id[:8]}...: its evidence has no "
                f"stable snapshot ({type(error).__name__}); a completed "
                "execution cannot be shown verified"
            )
            continue

        current = [
            claim
            for claim in claims
            if (
                claim.effect_id == row.effect_id
                and claim.attempt_id == row.attempt_id
                and claim.snapshot_digest == current_digest
            )
        ]

        if not current:
            findings.append(
                f"effect {row.effect_id[:8]}...: the lease is COMPLETED "
                "but no verification claim speaks about the row's current "
                "evidence; an observed claim completed without being "
                "verified"
            )
        elif any(
            claim.outcome is VerificationOutcome.CONTRADICTED
            for claim in current
        ):
            findings.append(
                f"effect {row.effect_id[:8]}...: the lease is COMPLETED "
                "but a CONTRADICTED claim is recorded against the same "
                "evidence; contradictory evidence must not complete"
            )
        elif current[-1].outcome is not VerificationOutcome.VERIFIED:
            findings.append(
                f"effect {row.effect_id[:8]}...: the lease is COMPLETED "
                "but the latest claim on its current evidence is "
                f"{current[-1].outcome.value}, not verified"
            )

    return tuple(findings)


def check_effect_verification_soundness(
    sdk: Optional[Any],
) -> InvariantResult:
    """Verification is a distinct stage, cannot grant authority, and a
    COMPLETED execution over an adopted side effect is verified.

    Three halves, and the result is the weakest of them.

    **Source census.** Only the declared protocol methods drive the
    verification journal and only the declared methods start a
    verification claim. A second verification path added anywhere in the
    package fails here.

    **Record hygiene.** Every stored claim re-derives to its own id and
    agrees with its own snapshot; a VERIFIED claim speaks about an
    observation recorded under valid authority, and the structural
    method never confirms provider-labelled evidence.

    **Live records.** Every claim names a real effect and the attempt
    that observed it, and a lease recorded COMPLETED over an adopted
    side effect carries a current VERIFIED claim whose evidence has no
    recorded contradiction -- re-derived from the records, so a stale or
    tampered completion cannot hide.
    """

    source_findings, source_notes = _verification_store_source_findings()

    if source_findings:
        return violated(
            _VERIFICATION_NAME,
            "a verification path exists that the soundness census does "
            "not declare, or a declared path drives no journal mutator",
            findings=source_findings,
        )

    helper_findings = _verification_helper_source_findings()

    if helper_findings:
        return violated(
            _VERIFICATION_NAME,
            "a verification claim is started outside the declared "
            "protocol methods",
            findings=helper_findings,
        )

    problem = _require_sdk(sdk, _VERIFICATION_NAME)

    if problem is not None:
        return unverifiable(
            _VERIFICATION_NAME,
            "the source censuses hold, but no FirewallSDK was supplied, "
            "so recorded verification claims could not be inspected",
            source_notes=source_notes,
        )

    try:
        claims = sdk.verifications.records()
    except Exception as error:  # noqa: BLE001 - unreadable is a finding
        return unverifiable(
            _VERIFICATION_NAME,
            "the verification journal could not be read: "
            f"{type(error).__name__}",
        )

    if not claims:
        return unverifiable(
            _VERIFICATION_NAME,
            "the source censuses hold, but no effect has been verified, "
            "so record-level verification soundness could not be "
            "inspected",
            source_notes=source_notes,
        )

    claim_findings: list[str] = []

    for claim in claims:
        claim_findings.extend(_verification_record_findings(claim))

    cross_findings = _verification_cross_findings(sdk)

    if claim_findings or cross_findings:
        return violated(
            _VERIFICATION_NAME,
            "a recorded verification claim is forged, stale, bound to "
            "another effect or attempt, or a completed execution claims "
            "a verification its records do not support",
            findings=tuple(claim_findings) + tuple(cross_findings),
            records=len(claims),
        )

    return holds(
        _VERIFICATION_NAME,
        f"{len(claims)} recorded verification claim(s) re-derive to "
        "their own ids, speak about the effect and attempt they name, "
        "and no COMPLETED execution over an adopted side effect lacks a "
        "current VERIFIED claim with no recorded contradiction",
        records=len(claims),
        source_notes=source_notes,
    )



# =====================================================================
# SECURITY_STATE_COHERENCE (v3.0)
# =====================================================================
#
# v3.0's claim: an authorization decision never relies on a security
# state the firewall cannot prove is coherent. The epoch counts the
# *writes* that can widen authority; the state-commitment journal records
# the *state* those writes produce. Every legitimate in-domain store
# write opens a ``record_state_commit`` bracket that ends in a
# hash-chained commitment of the whole canonical digest, and the ALLOW
# path refuses (``state_incoherent``) whenever the live digest diverges
# from the chain head. The check has two halves:

_STATE_COMMIT_NAME = "SECURITY_STATE_COHERENCE"


def _state_commit_census_owner(owner: str) -> str:
    """Longest census-shaped prefix of a qualified owner name.

    The same closure-reduction rule as :func:`_census_owner`, reduced
    against the state-commit census instead of the epoch ones.
    """

    parts = owner.split(".")
    named = {name for _, name in STATE_COMMIT_WRITES}

    for size in range(len(parts), 0, -1):
        candidate = ".".join(parts[:size])

        if candidate in named:
            return candidate

    return owner


def _state_commit_brackets(
    module: str,
    tree: ast.Module,
) -> set[str]:
    """Qualified names in ``tree`` that open a state-commitment interval.

    Recognised syntactically: any call whose rightmost name is
    :data:`~firewall.state_commit.STATE_COMMIT_HELPER`. Deliberately loose
    for the same reason :func:`_epoch_brackets` is -- a false positive
    makes the census *require* an entry, while a false negative would let
    a real in-domain write go uncommitted and report a pass.
    """

    owners = _qualified_functions(tree)
    found: set[str] = set()

    for call in source.walk_calls(tree):
        name = source.called_name(call)

        if name != STATE_COMMIT_HELPER:
            continue

        owner = owners.get(id(call))

        if owner is None:
            found.add(f"<module level in {module}>")
            continue

        found.add(_state_commit_census_owner(owner))

    return found


def _state_commit_source_findings() -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Both directions of the state-commit census, plus parse failures.

    A function listed in :data:`STATE_COMMIT_WRITES` that opens no
    commitment bracket is a finding; a bracket outside the census is one
    too. The second direction is the one that keeps the claim true over
    time: a later change cannot quietly add an in-domain write and pass
    by bracketing it.
    """

    root = source.package_root()

    if root is None:
        return (
            ("the firewall package source could not be located",),
            (),
        )

    declared: dict[str, set[str]] = {}

    for module, function in STATE_COMMIT_WRITES:
        declared.setdefault(module, set()).add(function)

    findings: list[str] = []
    notes: list[str] = []
    bracketed: dict[str, set[str]] = {}
    present: set[str] = set()

    for path in source.source_modules(root):
        module = source.relative_name(path, root)
        present.add(module)

        try:
            tree = source.parse_module(path)
        except source.ParseFailure as error:
            findings.append(f"{module}: could not be parsed: {error}")
            continue

        found = _state_commit_brackets(module, tree)

        if found:
            bracketed[module] = found

    for module, functions in sorted(declared.items()):
        if module not in present:
            findings.append(
                f"{module}: named by the state-commit census but absent "
                "from the package"
            )
            continue

        found = bracketed.get(module, set())

        for function in sorted(functions):
            if function not in found:
                findings.append(
                    f"{module}:{function} is declared an in-domain write "
                    "but opens no state-commitment interval"
                )

    for module, found in sorted(bracketed.items()):
        for owner in sorted(found):
            if (module, owner) in STATE_COMMIT_WRITES:
                continue

            if module == "firewall/state_commit.py":
                # The mechanism's own module. Bracket-free by design.
                continue

            findings.append(
                f"{module}:{owner} opens a state-commitment interval "
                "but is not in the in-domain census"
            )

    notes.append(
        f"{len(STATE_COMMIT_WRITES)} declared in-domain writes across "
        f"{len(declared)} modules"
    )

    return tuple(findings), tuple(notes)


def check_security_state_coherence(
    sdk: Optional[Any] = None,
) -> InvariantResult:
    """Every in-domain write is committed, and the live state matches the
    chain head.

    **Source.** Every write named in
    :data:`~firewall.state_commit.STATE_COMMIT_WRITES` opens a
    ``record_state_commit`` interval, and every such interval in the
    package is opened by a write the census names. A store whose mutation
    can reach an ALLOW read without a commitment is a hole: its state
    could be changed, and the boundary would have no record of what it
    changed to.

    **Live.** The supplied SDK's chain must verify (append-only, linked,
    state-anchored), carry the canonical component set, and -- the load-
    bearing half -- its live digest must equal the chain head. A store
    edited without the declared write path, rolled back, or left torn by
    a crash moves the live digest off the head and this half reports it.
    Every in-domain store the SDK wires must also be *bound* to the
    journal, so a store replaced after construction cannot start writing
    uncommitted.

    Without an SDK the live half is ``UNVERIFIABLE`` rather than passing.
    """

    source_findings, source_notes = _state_commit_source_findings()

    if source_findings:
        return violated(
            _STATE_COMMIT_NAME,
            "an in-domain write is not covered by a state commitment, "
            "so the ALLOW path could rely on state the firewall cannot "
            "prove is coherent",
            findings=tuple(source_findings),
            declared=len(STATE_COMMIT_WRITES),
        )

    problem = _require_sdk(sdk, _STATE_COMMIT_NAME)

    if problem is not None:
        return unverifiable(
            _STATE_COMMIT_NAME,
            "the source census holds in both directions, but no "
            "FirewallSDK was supplied, so the live chain could not be "
            "inspected",
            declared=len(STATE_COMMIT_WRITES),
            source_notes=source_notes,
        )

    journal = getattr(sdk, "state_commit", None)

    if not isinstance(journal, StateCommitJournal):
        return violated(
            _STATE_COMMIT_NAME,
            "the SDK exposes no state-commit journal, so its ALLOW path "
            "cannot prove the security state coherent",
            findings=(
                f"state_commit is {type(journal).__name__}",
            ),
        )

    required = {
        "revocation",
        "issuer_trust",
        "delegation_lineage",
        "delegation_depth",
    }
    attached = set(journal.names())

    if not required.issubset(attached):
        return violated(
            _STATE_COMMIT_NAME,
            "the state-commit journal is not attached to every "
            "in-domain store the ALLOW path reads",
            findings=tuple(
                sorted(required - attached)
            ),
            attached=sorted(attached),
        )

    unbound: list[str] = []
    bound_components = (
        ("revocation", sdk.revocation),
        ("issuer_trust_store", sdk.issuer_trust_store),
        ("delegation_lineage", sdk.delegation_lineage),
    )

    for label, component in bound_components:
        if component is None:
            continue

        if state_commit_of(component) is not journal:
            unbound.append(
                f"{label} is not bound to this SDK's state-commit "
                "journal"
            )

    if state_commit_of(sdk) is not journal:
        unbound.append(
            "the SDK itself is not bound to its state-commit journal, "
            "so changing the delegation-depth ceiling would not commit"
        )

    if unbound:
        return violated(
            _STATE_COMMIT_NAME,
            "an in-domain store would mutate without its state being "
            "committed",
            findings=tuple(unbound),
        )

    chain_problems = journal.verify_chain()

    if chain_problems:
        return violated(
            _STATE_COMMIT_NAME,
            "the state-commitment chain is broken, so the head attests "
            "nothing",
            findings=tuple(chain_problems[:20]),
            records=journal.height() + 1,
        )

    records = journal.records()

    if (
        not records
        or records[0].parent_digest != STATE_COMMIT_ANCHOR
    ):
        return violated(
            _STATE_COMMIT_NAME,
            "the state-commitment chain has no anchored genesis, so "
            "there is nothing for the live state to prove itself "
            "against",
        )

    try:
        coherent, reason = journal.coherent()
    except Exception as exc:  # noqa: BLE001 - unreadable is incoherent
        return violated(
            _STATE_COMMIT_NAME,
            "the live security state could not be read, so coherence "
            "cannot be established",
            findings=(f"{type(exc).__name__}: {exc}",),
        )

    if not coherent:
        return violated(
            _STATE_COMMIT_NAME,
            "the live security state differs from the last committed "
            "state, so an allow would rely on state the firewall cannot "
            "prove is coherent",
            findings=(reason,),
            records=journal.height() + 1,
        )

    return holds(
        _STATE_COMMIT_NAME,
        f"all {len(STATE_COMMIT_WRITES)} declared in-domain writes open "
        f"a commitment interval, no other call does, and the live "
        f"canonical state of this SDK matches its chain head (height "
        f"{journal.height()}, {len(attached)} components, every store "
        "bound)",
        declared=len(STATE_COMMIT_WRITES),
        records=journal.height() + 1,
        components=sorted(attached),
        source_notes=source_notes,
    )

# =====================================================================
# EXTERNAL_STATE_ATTESTATION_SOUNDNESS (v3.1)
# =====================================================================
#
# v3.1's claim: attestation is a distinct, externally-sourced stage between
# VERIFIED and COMPLETED --
#
#   AUTHORIZED =/= EXECUTED =/= OBSERVED =/= VERIFIED
#              =/= ATTESTED =/= COMPLETED
#
# -- and it can neither grant authority nor resurrect withdrawn authority.
# The check has three halves, mirroring EFFECT_VERIFICATION_SOUNDNESS:
#
# * source censuses in both directions over who may drive the attestation
#   journal, who may register or revoke an external issuer key, and who may
#   start an attestation claim -- plus the load-bearing negative: no
#   function on the ALLOW path may reference attestation state at all, so
#   an authorization decision can never come to rest on evidence sourced
#   outside the firewall;
# * record hygiene: every stored claim re-derives to its own id, and an
#   ATTESTED verdict must name a verified signature, a supported algorithm,
#   a registered-style issuer and key, an envelope, a nonce, a conclusive
#   asserted outcome, a state digest and a correlation handle -- the things
#   that make it a statement by an external system rather than a note the
#   firewall wrote to itself;
# * cross-journal soundness: every claim names a real effect and the
#   attempt that observed it, the correlation handle it reports is the one
#   the receipt recorded, its nonce is claimed for that same envelope and
#   effect exactly once, and a completed execution over an attested effect
#   carries a current ATTESTED claim with no contradiction standing.

from firewall.external_attestation import (
    ATTESTATION_VERSION,
    CONCLUSIVE_OUTCOMES,
    STATEMENT_TYPE,
    SUPPORTED_ALGORITHMS,
    AttestationOutcome,
    attestation_binding_digest,
    freshness_failure,
    scope_mismatch,
)

_ATTESTATION_NAME = "EXTERNAL_STATE_ATTESTATION_SOUNDNESS"

#: The only module that may drive the attestation journal, and the calls
#: that constitute driving it. ``_journal_attestation`` is a single entry
#: point on purpose: the nonce ledger and the record are one property, so a
#: second site that recorded a claim without claiming its nonce would be a
#: replay hole even if each half looked safe on its own.
ATTESTATION_STORE_MUTATOR_OWNERS = frozenset(
    {
        ("firewall/sdk.py", "FirewallSDK._journal_attestation"),
    }
)

ATTESTATION_STORE_MUTATOR_CALLS = frozenset({"record", "claim_nonce"})

#: The attribute chain that names the attestation journal.
ATTESTATION_STORE_TOKEN = "attestations"

#: The only methods that may register or revoke an external issuer key.
#:
#: This census is the reason the layer means anything: code that could
#: register its own public key could then mint its own "external"
#: attestations, and every check downstream would pass. A subsystem added
#: later that reaches for the trust store fails here.
EXTERNAL_ISSUER_MUTATOR_OWNERS = frozenset(
    {
        ("firewall/sdk.py", "FirewallSDK.trust_external_issuer"),
        ("firewall/sdk.py", "FirewallSDK.revoke_external_issuer_key"),
        ("firewall/sdk.py", "FirewallSDK.revoke_external_issuer"),
    }
)

EXTERNAL_ISSUER_MUTATOR_CALLS = frozenset(
    {"register", "revoke_key", "revoke_issuer"}
)

EXTERNAL_ISSUER_TOKEN = "external_issuers"

#: The SDK methods that may start an attestation claim.
ATTESTATION_HELPER_CALLERS = frozenset(
    {
        ("firewall/sdk.py", "FirewallSDK.record_attestation"),
        ("firewall/sdk.py", "FirewallSDK.commit_effect"),
        ("firewall/sdk.py", "FirewallSDK.run_effect"),
    }
)

_ATTESTATION_HELPER_CALL = "_attest_row_claim"

#: Every name whose mere presence in a function body is a reference to
#: attestation state -- the journal, the trust store, the private helpers
#: and the protocol methods' own accessors.
ATTESTATION_REFERENCE_NAMES = frozenset(
    {
        "attestations",
        "external_issuers",
        "_attest_row_claim",
        "_journal_attestation",
        "_attestation_now",
        "_attestation_current_claims",
        "attestation_records",
        "nonce_claims",
        "external_issuer_records",
    }
)

#: Functions that decide an authorization outcome.
#:
#: None of them may reference attestation state, in any direction. This is
#: the property the release is really about: an ALLOW must never come to
#: rest on evidence that originated outside the firewall, however well
#: signed. Listed explicitly rather than derived, and matched against the
#: qualified owner name *and* its prefixes, so a nested closure inside one
#: of them is caught too.
ATTESTATION_ALLOW_PATH_OWNERS = frozenset(
    {
        "FirewallSDK.authorize",
        "FirewallSDK.authorize_continuous",
        "FirewallSDK.authorize_execution",
        "FirewallSDK.authorize_north_star",
        "FirewallSDK.authorize_with_delegation_budget",
        "FirewallSDK.revalidate",
        "FirewallSDK.is_authorized",
        "FirewallSDK.consume_nonce",
        "FirewallSDK.authority_envelope",
        "FirewallSDK._authority_envelope",
        "FirewallSDK._authorization_chain",
        "FirewallSDK.security_decision",
        "FirewallSDK.reserve_execution",
        "FirewallSDK.start_execution",
        "FirewallSDK.mint_session_capability",
    }
)

_ATTESTATION_OWNER_NAMES = frozenset(
    name
    for _, name in (
        ATTESTATION_STORE_MUTATOR_OWNERS
        | EXTERNAL_ISSUER_MUTATOR_OWNERS
        | ATTESTATION_HELPER_CALLERS
    )
)


def _attestation_census_owner(owner: str) -> str:
    """Longest census-shaped prefix of a qualified owner name."""

    parts = owner.split(".")

    for size in range(len(parts), 0, -1):
        candidate = ".".join(parts[:size])

        if candidate in _ATTESTATION_OWNER_NAMES:
            return candidate

    return owner


def _attestation_node_owners(tree: ast.AST) -> dict[int, str]:
    """Map every node's ``id`` to its enclosing ``Class.method`` name.

    :func:`_qualified_functions` maps *call* nodes only, which is what the
    journal censuses need. The ALLOW-path rule is about any reference --
    a read of ``self.attestations`` is not a call -- so every node needs an
    owner, and this is the same descent one step looser.

    Memoised per tree -- see :data:`_TREE_MEMO`. This is the widest descent
    in the package, so it is also the most expensive one to repeat.
    """

    cached = _tree_memo_get("attestation_node_owners", tree)

    if cached is not _MEMO_MISS:
        return cached

    owners: dict[int, str] = {}

    def descend(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if prefix:
                owners[id(child)] = prefix

            if isinstance(child, ast.ClassDef):
                descend(
                    child,
                    f"{prefix}.{child.name}" if prefix else child.name,
                )
            elif isinstance(
                child,
                (ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                descend(
                    child,
                    f"{prefix}.{child.name}" if prefix else child.name,
                )
            else:
                descend(child, prefix)

    descend(tree, "")

    _tree_memo_put("attestation_node_owners", tree, owners)

    return owners


def _on_attestation_allow_path(owner: str) -> bool:
    """Whether a qualified owner decides an authorization outcome."""

    if not owner:
        return False

    if "_gate_" in owner:
        return True

    parts = owner.split(".")

    for size in range(len(parts), 0, -1):
        if ".".join(parts[:size]) in ATTESTATION_ALLOW_PATH_OWNERS:
            return True

    return False


def _attestation_source_findings() -> (
    tuple[tuple[str, ...], tuple[str, ...]]
):
    """All four source censuses over the attestation layer.

    One walk per module, answering four questions:

    1. who drives the attestation journal (both directions);
    2. who registers or revokes an external issuer key (both directions);
    3. who starts an attestation claim (both directions);
    4. does anything on the ALLOW path reference attestation state at all.

    The last is the one that would matter most if it ever failed, and the
    one no other invariant can see: a gate that read
    ``self.attestations.by_effect(...)`` would still be constructing its
    verdict inside the boundary, so AUTHORIZATION_UNIQUENESS would be
    silent, while an external statement had quietly become an input to an
    allow.
    """

    root = source.package_root()

    if root is None:
        return (
            ("the firewall package source could not be located",),
            (),
        )

    findings: list[str] = []
    notes: list[str] = []
    present: set[str] = set()
    journal_calls: dict[str, set[str]] = {}
    issuer_calls: dict[str, set[str]] = {}
    helper_calls: dict[str, set[str]] = {}
    allow_path_references: list[str] = []

    for path in source.source_modules(root):
        module = source.relative_name(path, root)
        present.add(module)

        try:
            tree = source.parse_module(path)
        except source.ParseFailure as error:
            findings.append(f"{module}: could not be parsed: {error}")
            continue

        owners = _qualified_functions(tree)
        node_owners = _attestation_node_owners(tree)

        for call in source.walk_calls(tree):
            func = call.func

            if not isinstance(func, ast.Attribute):
                continue

            owner = owners.get(id(call))

            if owner is None:
                owner = node_owners.get(id(call))

            if func.attr in ATTESTATION_STORE_MUTATOR_CALLS and (
                _attribute_chain_has(func.value, ATTESTATION_STORE_TOKEN)
            ):
                if owner is None:
                    findings.append(
                        f"{module}: <module level> calls {func.attr} on "
                        "the attestation journal"
                    )
                else:
                    journal_calls.setdefault(module, set()).add(
                        _attestation_census_owner(owner)
                    )

            if func.attr in EXTERNAL_ISSUER_MUTATOR_CALLS and (
                _attribute_chain_has(func.value, EXTERNAL_ISSUER_TOKEN)
            ):
                if owner is None:
                    findings.append(
                        f"{module}: <module level> calls {func.attr} on "
                        "the external issuer trust store"
                    )
                else:
                    issuer_calls.setdefault(module, set()).add(
                        _attestation_census_owner(owner)
                    )

            if (
                func.attr == _ATTESTATION_HELPER_CALL
                and isinstance(func.value, ast.Name)
                and func.value.id == "self"
            ):
                if owner is None:
                    findings.append(
                        f"{module}: <module level> starts an attestation "
                        "claim"
                    )
                else:
                    helper_calls.setdefault(module, set()).add(
                        _attestation_census_owner(owner)
                    )

        for node in ast.walk(tree):
            if not isinstance(node, ast.Attribute):
                continue

            if node.attr not in ATTESTATION_REFERENCE_NAMES:
                continue

            owner = node_owners.get(id(node))

            if _on_attestation_allow_path(owner or ""):
                allow_path_references.append(
                    f"{module}:{owner} references '{node.attr}'"
                )

    for module, function in sorted(ATTESTATION_STORE_MUTATOR_OWNERS):
        if function not in journal_calls.get(module, set()):
            findings.append(
                f"{module}:{function} is declared an attestation journal "
                "caller but drives no journal mutator"
            )

    for module, functions in sorted(journal_calls.items()):
        for owner in sorted(functions):
            if (module, owner) in ATTESTATION_STORE_MUTATOR_OWNERS:
                continue

            findings.append(
                f"{module}:{owner} drives the attestation journal but is "
                "not a declared attestation protocol path"
            )

    for module, function in sorted(EXTERNAL_ISSUER_MUTATOR_OWNERS):
        if function not in issuer_calls.get(module, set()):
            findings.append(
                f"{module}:{function} is declared an external issuer "
                "registration path but registers nothing"
            )

    for module, functions in sorted(issuer_calls.items()):
        for owner in sorted(functions):
            if (module, owner) in EXTERNAL_ISSUER_MUTATOR_OWNERS:
                continue

            findings.append(
                f"{module}:{owner} registers or revokes an external issuer "
                "key but is not a declared trust anchor; a subsystem that "
                "can register its own key can mint its own evidence"
            )

    for module, function in sorted(ATTESTATION_HELPER_CALLERS):
        if function not in helper_calls.get(module, set()):
            findings.append(
                f"{module}:{function} is declared an attestation protocol "
                "path but starts no attestation claim"
            )

    for module, functions in sorted(helper_calls.items()):
        for owner in sorted(functions):
            if (module, owner) in ATTESTATION_HELPER_CALLERS:
                continue

            findings.append(
                f"{module}:{owner} starts an attestation claim but is not "
                "a declared attestation protocol path"
            )

    if allow_path_references:
        findings.append(
            "attestation state is referenced from the ALLOW path ("
            + "; ".join(sorted(set(allow_path_references))[:5])
            + "); an authorization decision must never rest on evidence "
            "that originated outside the firewall"
        )

    notes.append(
        f"{len(ATTESTATION_STORE_MUTATOR_OWNERS)} declared attestation "
        "journal caller, "
        f"{len(EXTERNAL_ISSUER_MUTATOR_OWNERS)} declared issuer trust "
        f"paths, {len(ATTESTATION_HELPER_CALLERS)} declared attestation "
        f"protocol paths, and {len(ATTESTATION_REFERENCE_NAMES)} "
        "attestation reference names absent from the ALLOW path"
    )

    for module, functions in sorted(helper_calls.items()):
        present.add(module)

    return tuple(findings), tuple(notes)


def _attestation_record_findings(claim: Any) -> tuple[str, ...]:
    """Record-level hygiene for one attestation claim.

    A claim is immutable and self-identifying: its stored id must
    re-derive from its binding fields (a forged or edited row disagrees
    with the id it claims). What an ATTESTED verdict may say is bounded --
    it speaks about a signature that verified under a supported algorithm
    for a named issuer and key, about a conclusive outcome, correlated with
    the effect's external request handle, with the state digest the issuer
    signed -- and a CONTRADICTED verdict must be a contradiction of
    conclusive statements, since ``UNKNOWN`` contradicts nothing.
    """

    findings: list[str] = []
    label = getattr(claim, "attestation_id", None)
    label = f"{label[:8]}..." if isinstance(label, str) else "?"

    outcome = getattr(claim, "outcome", None)

    rederived = attestation_binding_digest(
        effect_id=getattr(claim, "effect_id", ""),
        attempt_id=getattr(claim, "attempt_id", ""),
        envelope_id=getattr(claim, "envelope_id", ""),
        issuer_id=getattr(claim, "issuer_id", ""),
        key_id=getattr(claim, "key_id", ""),
        outcome=outcome if isinstance(
            outcome, AttestationOutcome
        ) else AttestationOutcome.NOT_ATTESTED,
    )

    if not isinstance(outcome, AttestationOutcome):
        findings.append(
            f"attestation {label}: its outcome is not a verdict: "
            f"{outcome!r}"
        )
        return tuple(findings)

    if rederived != getattr(claim, "attestation_id", None):
        findings.append(
            f"attestation {label}: its id does not re-derive from its "
            "binding fields; the record is forged or edited"
        )

    for field_name in (
        "effect_id",
        "lease_id",
        "attempt_id",
        "envelope_id",
        "issuer_id",
        "key_id",
        "algorithm",
        "nonce",
        "effect_digest",
        "capability_fingerprint",
        "agent_id",
        "action",
        "idempotency_key",
    ):
        value = getattr(claim, field_name, None)

        if not isinstance(value, str):
            findings.append(
                f"attestation {label}: field {field_name!r} is not a "
                f"string ({type(value).__name__})"
            )

    correlated = getattr(claim, "correlated", None)
    source = getattr(claim, "correlation_source", None)
    request_id = getattr(claim, "external_request_id", None)

    if not isinstance(correlated, bool):
        findings.append(
            f"attestation {label}: 'correlated' is not a boolean"
        )
    elif correlated:
        if source not in ("receipt", "attestation"):
            findings.append(
                f"attestation {label}: it claims correlation but names no "
                f"source ({source!r})"
            )
        if not isinstance(request_id, str) or not request_id:
            findings.append(
                f"attestation {label}: it claims correlation but names no "
                "external request handle"
            )
    elif source != "none":
        findings.append(
            f"attestation {label}: it is not correlated but names "
            f"correlation source {source!r}"
        )

    if source == "receipt" and not correlated:
        findings.append(
            f"attestation {label}: the correlation came from the receipt "
            "but the record is not marked correlated"
        )

    if outcome is AttestationOutcome.ATTESTED:
        if not getattr(claim, "signature_verified", False):
            findings.append(
                f"attestation {label}: ATTESTED without a verified "
                "signature; an unverified statement is not evidence about "
                "an external system"
            )

        missing = [
            field_name
            for field_name in (
                "envelope_id",
                "issuer_id",
                "key_id",
                "nonce",
                "state_digest",
            )
            if not getattr(claim, field_name, "")
        ]

        if missing:
            findings.append(
                f"attestation {label}: ATTESTED without "
                + ", ".join(sorted(missing))
            )

        if getattr(claim, "algorithm", None) not in SUPPORTED_ALGORITHMS:
            findings.append(
                f"attestation {label}: ATTESTED under algorithm "
                f"{getattr(claim, 'algorithm', None)!r}, which this "
                "firewall cannot verify"
            )

        asserted = getattr(claim, "asserted_outcome", None)

        if asserted not in CONCLUSIVE_OUTCOMES:
            findings.append(
                f"attestation {label}: ATTESTED while asserting "
                f"{asserted!r}; only a conclusive outcome attested by the "
                "external system counts"
            )

        if not correlated:
            findings.append(
                f"attestation {label}: ATTESTED without a correlation "
                "handle; a statement that cannot be tied to the effect's "
                "external request attests something else"
            )

        malformed = freshness_failure(
            issued_at=getattr(claim, "issued_at", None),
            not_before=getattr(claim, "not_before", None),
            expires_at=getattr(claim, "expires_at", None),
            now=getattr(claim, "recorded_at", 0.0),
            max_age=1e18,
            skew=0.0,
        )

        if malformed == "attestation_time_malformed":
            findings.append(
                f"attestation {label}: ATTESTED with a validity window "
                "that cannot be compared"
            )

        if (
            getattr(claim, "issued_at", 0.0)
            > getattr(claim, "expires_at", 0.0)
        ):
            findings.append(
                f"attestation {label}: its validity window ends before it "
                "begins"
            )

    elif outcome is AttestationOutcome.CONTRADICTED:
        asserted = getattr(claim, "asserted_outcome", None)

        if asserted not in CONCLUSIVE_OUTCOMES:
            findings.append(
                f"attestation {label}: a contradiction recorded against "
                f"{asserted!r}; only conclusive statements contradict, and "
                "UNKNOWN asserts nothing"
            )

    if outcome is not AttestationOutcome.ATTESTED and getattr(
        claim, "outcome", None
    ) is not None:
        reason = getattr(claim, "reason", None)

        if not isinstance(reason, str) or not reason:
            findings.append(
                f"attestation {label}: a refusal was recorded without a "
                "reason"
            )

    return tuple(findings)


def _attestation_cross_findings(sdk: FirewallSDK) -> tuple[str, ...]:
    """Cross-journal soundness of every attestation claim.

    For every stored claim: the effect it names must exist, the scope field
    values must be the row's -- re-derived from the records, so a claim
    lifted onto another effect cannot hide -- its attempt must be the row's
    current attempt, its correlation handle must be the one the receipt
    recorded when the record says the receipt supplied it, and its provider
    must be the row's provider when the row named one.

    Then the ledger: every ATTESTED claim's nonce must be claimed in the
    replay ledger for that same envelope and effect, and no envelope may be
    the basis of two ATTESTED claims -- a signed statement is evidence once.

    Finally the gate, re-derived: a completed execution over an effect that
    carries any attestation claim must have a current ATTESTED claim with no
    contradiction standing, and when the SDK requires external attestation
    every completed execution over an adopted side effect must have one.
    """

    findings: list[str] = []

    try:
        claims = sdk.attestations.records()
        rows = sdk.effects.records()
        nonce_claims = sdk.attestations.nonce_claims()
    except Exception as error:  # noqa: BLE001 - unreadable is a finding
        return (
            "the attestation journal, the side-effect journal or the nonce "
            f"ledger could not be read: {type(error).__name__}",
        )

    row_by_effect: dict[str, Any] = {}
    lease_by_id: dict[str, Any] = {}

    for row in rows:
        row_by_effect[row.effect_id] = row

    try:
        for lease in sdk.execution_leases.records():
            lease_by_id[lease.lease_id] = lease
    except Exception as error:  # noqa: BLE001
        return (
            "the execution lease store could not be read: "
            f"{type(error).__name__}",
        )

    ledger = {
        (claim.issuer_id, claim.nonce): claim for claim in nonce_claims
    }

    attested_envelopes: dict[str, str] = {}

    for claim in claims:
        label = f"{claim.attestation_id[:8]}..."
        row = row_by_effect.get(claim.effect_id)

        if row is None:
            findings.append(
                f"attestation {label}: names effect "
                f"{claim.effect_id[:8]}... which has no side-effect row; an "
                "attestation must speak about a recorded effect"
            )
            continue

        mismatch = scope_mismatch(row, claim)

        if mismatch is not None:
            findings.append(
                f"attestation {label}: records a different {mismatch} than "
                "the effect row it names; the claim was lifted onto "
                "another effect"
            )

        if row.attempt_id != claim.attempt_id:
            findings.append(
                f"attestation {label}: names attempt "
                f"{claim.attempt_id[:8]}... but the effect row's current "
                f"attempt is "
                f"{row.attempt_id[:8] if row.attempt_id else None}; a claim "
                "must not speak for another attempt"
            )

        if claim.correlation_source == "receipt" and (
            claim.external_request_id != row.external_request_id
        ):
            findings.append(
                f"attestation {label}: records the receipt's correlation "
                f"handle {claim.external_request_id!r} while the effect row "
                f"records {row.external_request_id!r}"
            )

        if (
            claim.outcome is AttestationOutcome.ATTESTED
            and row.provider is not None
            and claim.provider != row.provider
        ):
            findings.append(
                f"attestation {label}: attested by "
                f"{claim.provider!r} while the effect row records provider "
                f"{row.provider!r}; the state was not attested by the "
                "claimed external system"
            )

        if claim.outcome is AttestationOutcome.ATTESTED:
            held = ledger.get((claim.issuer_id, claim.nonce))

            if held is None:
                findings.append(
                    f"attestation {label}: ATTESTED with nonce "
                    f"{claim.nonce[:12]}... which the replay ledger does "
                    "not hold; a statement accepted without claiming its "
                    "nonce can be replayed forever"
                )
            elif (
                held.envelope_id != claim.envelope_id
                or held.effect_id != claim.effect_id
                or held.attempt_id != claim.attempt_id
            ):
                findings.append(
                    f"attestation {label}: the nonce ledger holds envelope "
                    f"{held.envelope_id[:8]}... for effect "
                    f"{held.effect_id[:8]}..., not this claim's"
                )

            previous = attested_envelopes.get(claim.envelope_id)

            if previous is not None:
                findings.append(
                    f"attestation {label}: envelope "
                    f"{claim.envelope_id[:8]}... is already the basis of "
                    f"attestation {previous}; one signed statement is one "
                    "piece of evidence"
                )
            else:
                attested_envelopes[claim.envelope_id] = label

    require_attestation = bool(
        getattr(sdk, "require_external_attestation", False)
    )

    claims_by_effect: dict[str, list[Any]] = {}

    for claim in claims:
        claims_by_effect.setdefault(claim.effect_id, []).append(claim)

    for row in rows:
        lease = lease_by_id.get(row.lease_id)

        if lease is None:
            continue

        state_value = getattr(getattr(lease, "state", None), "value", None)

        if state_value != "completed":
            continue

        from firewall.effect import EffectState as _ES

        if row.state is not _ES.SUCCEEDED:
            continue

        current = [
            claim
            for claim in claims_by_effect.get(row.effect_id, ())
            if claim.attempt_id == row.attempt_id
        ]

        if not current:
            if require_attestation:
                findings.append(
                    f"effect {row.effect_id[:8]}...: the lease is COMPLETED "
                    "over an adopted side effect while this SDK requires an "
                    "external attestation, and no attestation claim stands "
                    "for it"
                )
            continue

        if any(
            claim.outcome is AttestationOutcome.CONTRADICTED
            for claim in current
        ):
            findings.append(
                f"effect {row.effect_id[:8]}...: the lease is COMPLETED "
                "while a CONTRADICTED attestation stands for the same "
                "effect; contradictory external evidence must not complete"
            )
            continue

        if current[-1].outcome is not AttestationOutcome.ATTESTED:
            findings.append(
                f"effect {row.effect_id[:8]}...: the lease is COMPLETED but "
                "the latest attestation claim on its current attempt is "
                f"{current[-1].outcome.value} ({current[-1].reason}), not "
                "attested"
            )

    return tuple(findings)


def check_external_state_attestation_soundness(
    sdk: Optional[Any],
) -> InvariantResult:
    """Attestation is a distinct externally-sourced stage, and the ALLOW
    path never rests on it.

    Three halves, and the result is the weakest of them.

    **Source census.** Only the declared protocol path drives the
    attestation journal, only the declared methods register or revoke an
    external issuer key, only the declared methods start an attestation
    claim -- and no function that decides an authorization outcome
    references attestation state in any direction. The last is the
    release's central negative: an external statement must never become an
    input to an allow, however well signed.

    **Record hygiene.** Every stored claim re-derives to its own id, and an
    ATTESTED verdict necessarily names a verified signature, a supported
    algorithm, an envelope, a nonce, a conclusive asserted outcome, a state
    digest and a correlation handle. A CONTRADICTED verdict necessarily
    contradicts conclusive statements.

    **Live records.** Every claim names a real effect, the scope values and
    attempt of the row it names, and the correlation handle the receipt
    recorded; every ATTESTED claim's nonce is claimed for that same
    envelope and effect, once; and a completion over an attested effect
    carries a current ATTESTED claim with no contradiction standing --
    re-derived from the records, so a stale or tampered completion cannot
    hide.
    """

    source_findings, source_notes = _attestation_source_findings()

    if source_findings:
        return violated(
            _ATTESTATION_NAME,
            "an attestation path exists that the soundness census does not "
            "declare, or the ALLOW path references attestation state",
            findings=source_findings,
        )

    problem = _require_sdk(sdk, _ATTESTATION_NAME)

    if problem is not None:
        return unverifiable(
            _ATTESTATION_NAME,
            "the source censuses hold, but no FirewallSDK was supplied, so "
            "recorded attestation claims could not be inspected",
            source_notes=source_notes,
        )

    try:
        claims = sdk.attestations.records()
    except Exception as error:  # noqa: BLE001 - unreadable is a finding
        return unverifiable(
            _ATTESTATION_NAME,
            "the attestation journal could not be read: "
            f"{type(error).__name__}",
        )

    claim_findings: list[str] = []

    for claim in claims:
        claim_findings.extend(_attestation_record_findings(claim))

    cross_findings = _attestation_cross_findings(sdk)

    if claim_findings or cross_findings:
        return violated(
            _ATTESTATION_NAME,
            "an external attestation has become something it is not: a "
            "forged or unverified claim recorded as attested, a claim "
            "lifted onto another effect, a replayed statement, or a "
            "completion resting on evidence its records do not support",
            findings=tuple(claim_findings) + tuple(cross_findings),
            records=len(claims),
        )

    if not claims and not getattr(
        sdk, "require_external_attestation", False
    ):
        return unverifiable(
            _ATTESTATION_NAME,
            "the source censuses hold, but no external attestation has been "
            "recorded and this SDK does not require one, so record-level "
            "attestation soundness could not be inspected",
            source_notes=source_notes,
        )

    attested = sum(
        1
        for claim in claims
        if claim.outcome is AttestationOutcome.ATTESTED
    )

    return holds(
        _ATTESTATION_NAME,
        f"{len(claims)} recorded attestation claim(s) re-derive to their "
        f"own ids, {attested} are attested over verified signatures from "
        "registered external issuers with claimed nonces, and no ALLOW-path "
        "function references attestation state",
        records=len(claims),
        attested=attested,
        source_notes=source_notes,
    )

# =====================================================================
# TEMPORAL_SECURITY_INTEGRITY (v3.2)
# =====================================================================
#
# v3.2's claim: a security decision is valid only within a provable
# temporal context -- and the context is provable only if the clocks it is
# measured in are audited, the windows it rests on are anchored in both
# time bases, and no recorded event claims a validity its own timestamps
# contradict. Three halves, mirroring the shape of the verification and
# attestation invariants that precede it:
#
# * a **source census**, in both directions, over which code may compare a
#   security deadline: a declared window site must establish its context
#   through the temporal layer, a function that establishes a context must
#   be a declared window site, a deadline comparison anywhere else is a
#   violation, and no security deadline may be compared against a platform
#   clock nothing audits;
# * **record integrity**: locally stamped security timestamps are ordered,
#   windows are well formed, no lease claims a deadline beyond the duration
#   it was granted, and no completion or attestation sits outside the
#   window it relied on;
# * **live integrity**: every clock-reading store is bound to the guard,
#   the guard's own history is self-consistent and its anomaly reasons are
#   ones this release can explain, no recorded monotonic anchor points into
#   the future, and -- on a scratch SDK -- an honest clock allows, a
#   rolled-back wall clock and a regressed monotonic clock each deny by
#   name, and a lease whose elapsed budget is spent is refused even while a
#   wall clock rolled back still says it is open.

from firewall.temporal import (
    TEMPORAL_ANOMALY_PREFIX,
    TEMPORAL_WINDOW_CLOSED,
    TEMPORAL_WINDOW_SITES,
    temporal_of,
)

_TEMPORAL_NAME = "TEMPORAL_SECURITY_INTEGRITY"

#: Deadline attributes whose comparison the census constrains.
#:
#: Deliberately a *small* set of names meaning "an instant this record stops
#: being valid", rather than a heuristic over anything time-shaped. A false
#: positive here makes a reviewer look at one new field; a false negative
#: would let a window be compared somewhere the temporal context is never
#: established, which is the defect this release exists to close.
TEMPORAL_DEADLINE_ATTRIBUTES = frozenset(
    {
        "expires_at",
        "expired_at",
        "deadline_wall",
        "not_after",
        "valid_until",
    }
)

#: Functions permitted to compare a security deadline without being a
#: temporal window site, and why.
#:
#: Every window site is declared in
#: :data:`firewall.temporal.TEMPORAL_WINDOW_SITES`; everything here is
#: either a *second* evaluation of a window the boundary already audited, or
#: an evaluation of a bound that cannot widen authority. The qualification
#: check is a property of the code path, not of the deadline: a function
#: that compares a deadline against a clock its caller passed in is relying
#: on that caller to have established the context, which is exactly what the
#: temporal window sites do.
TEMPORAL_DEADLINE_SITES = frozenset(
    {
        # Second evaluations of a window the boundary already audited: the
        # canonical verifier and the canonical boundary both compare the
        # capability window again, in the same instant the gate did.
        ("firewall/capability.py", "CapabilityVerifier.verify"),
        ("firewall/authorization.py", "authorize"),
        # Bounds on records that cannot widen authority -- an already
        # attenuated capability, a delegation's own validity, a task
        # registration's liveness.
        ("firewall/attenuation.py", "can_attenuate"),
        ("firewall/delegation.py", "Delegation.is_valid"),
        ("firewall/delegation.py", "delegate_capability"),
        ("firewall/delegation.py", "verify_delegation"),
        ("firewall/task/registry.py", "TaskRegistry.is_active"),
        # Read-only projections over capabilities this boundary resolved.
        (
            "firewall/continuous_auth/predicates.py",
            "_is_capability_narrower",
        ),
        (
            "firewall/continuous_auth/predicates.py",
            "authority_monotonicity_check",
        ),
        (
            "firewall/adversarial/__init__.py",
            "AdversarialAgentDefense._verify_capability",
        ),
        # The agent-to-agent surface: its own clock, its own boundary, and
        # not on the canonical ALLOW path.
        ("firewall/a2a/auth.py", "AgentToAgent.is_active"),
        ("firewall/a2a/auth.py", "AgentToAgent.trust_graph"),
        # The replay entry's own bound check, in the mechanism's module.
        ("firewall/replay.py", "_Consumed.closed"),
    }
)

#: Calls that establish a temporal context. A declared window site must make
#: at least one of them.
TEMPORAL_CONTEXT_CALLS = frozenset(
    {
        "sample_temporal",
        "observe_temporal",
        "observe_reading",
        "temporal_context",
        "check_window",
        "validity",
        "lapse_reason",
        "absolute_bound",
        "monotonic_elapsed",
        "close_reason",
        "_temporal_audit",
        "_temporal_context",
    }
)

#: Platform clock reads that only the temporal layer may make.
#:
#: A site comparing a deadline against an *injected* clock relies on whoever
#: injected it, and the boundary audits that clock. A site reaching for the
#: platform clock is answering a security question from a source nothing
#: audits -- including the guard, whose own default is allowed because
#: :mod:`firewall.temporal` is where auditing happens.
TEMPORAL_PLATFORM_CLOCK_CALLS = frozenset(
    {
        "time",
        "monotonic",
        "perf_counter",
        "time_ns",
        "monotonic_ns",
    }
)

#: Anomaly reasons a recorded anomaly may carry. Anything else means an
#: anomaly was recorded that this release cannot explain, which is a finding
#: rather than a curiosity.
TEMPORAL_ANOMALY_REASONS = frozenset(
    {
        "wall_regression",
        "monotonic_regression",
        "cross_restart_regression",
        "monotonic_unavailable",
        "watermark_unwritable",
        "temporal_watermark_unavailable",
        "temporal_watermark_malformed",
        "temporal_context_unprovable",
    }
)

#: The functions that decide an authorization outcome, none of which may
#: read a platform clock of its own.
#:
#: A gate that reached for ``time.time()`` would answer a security question
#: from a source nothing audits -- not the guard, not an injected clock, not
#: anything the deployment configured -- and it would do it inside the one
#: path where the answer becomes authority. Every gate here reads its clock
#: through ``_read_security_state`` on the verifier's clock and audits the
#: reading.
TEMPORAL_ALLOW_PATH_OWNERS = frozenset(
    {
        "FirewallSDK.authorize",
        "FirewallSDK.authorize_continuous",
        "FirewallSDK.authorize_execution",
        "FirewallSDK.authorize_north_star",
        "FirewallSDK.authorize_with_delegation_budget",
        "FirewallSDK.revalidate",
        "FirewallSDK.is_authorized",
        "FirewallSDK.consume_nonce",
        "FirewallSDK.reserve_execution",
        "FirewallSDK.start_execution",
        "FirewallSDK.authority_envelope",
        "FirewallSDK._authority_envelope",
    }
)

#: Modules exempt from the deadline census, and why.
#:
#: ``firewall/invariants`` is a read-only auditor: it constructs no verdict,
#: decides nothing, and reads deadlines in order to *check* them -- including
#: deadlines it deliberately fabricates to probe the boundary. Exempting it
#: is a statement about what it is, and the package's own docstring makes
#: the same statement: the suite is not an authorization authority.
TEMPORAL_AUDIT_MODULES = frozenset(
    {
        "firewall/invariants/__init__.py",
        "firewall/invariants/__main__.py",
        "firewall/invariants/exercise.py",
        "firewall/invariants/model.py",
        "firewall/invariants/registry.py",
        "firewall/invariants/runtime.py",
        "firewall/invariants/source.py",
        "firewall/invariants/static.py",
    }
)

#: The stores whose clocks must be bound to the guard, so their own
#: readings are audited where they are taken.
TEMPORAL_BOUND_COMPONENTS = (
    ("execution_leases", "execution_leases"),
    ("effects", "effects"),
    ("attestations", "attestations"),
    ("replay", "replay"),
    ("lifecycle", "lifecycle"),
)

_TEMPORAL_OWNER_NAMES = frozenset(
    name
    for _, name in (TEMPORAL_WINDOW_SITES | TEMPORAL_DEADLINE_SITES)
)


def _temporal_census_owner(owner: str) -> str:
    """Longest census-shaped prefix of a qualified owner name."""

    parts = owner.split(".")

    for size in range(len(parts), 0, -1):
        candidate = ".".join(parts[:size])

        if candidate in _TEMPORAL_OWNER_NAMES:
            return candidate

    return owner


def _temporal_deadline_sites(
    tree: ast.AST,
) -> dict[str, set[str]]:
    """Every enclosing function that compares a deadline attribute."""

    owners = _attestation_node_owners(tree)
    sites: dict[str, set[str]] = {}

    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue

        names = {
            sub.attr
            for sub in ast.walk(node)
            if isinstance(sub, ast.Attribute)
        } & TEMPORAL_DEADLINE_ATTRIBUTES

        if not names:
            continue

        owner = owners.get(id(node))

        if owner is None:
            sites.setdefault("<module>", set()).update(names)
            continue

        sites.setdefault(owner, set()).update(names)

    return sites


def _temporal_function_calls(
    tree: ast.AST,
) -> dict[str, set[str]]:
    """``owner -> names of the calls made inside it``."""

    owners = _qualified_functions(tree)
    calls: dict[str, set[str]] = {}

    for call in source.walk_calls(tree):
        owner = owners.get(id(call))

        if owner is None:
            continue

        name = source.called_name(call)

        if isinstance(name, str) and name:
            calls.setdefault(owner, set()).add(name)

    return calls


def _temporal_platform_reads(
    tree: ast.AST,
) -> tuple[str, ...]:
    """Qualified owners reading a platform clock, in this module."""

    owners = _qualified_functions(tree)
    found: list[str] = []

    for call in source.walk_calls(tree):
        func = call.func
        owner = owners.get(id(call))

        if owner is None:
            continue

        if isinstance(func, ast.Attribute) and (
            isinstance(func.value, ast.Name)
            and func.value.id == "time"
            and func.attr in TEMPORAL_PLATFORM_CLOCK_CALLS
        ):
            found.append(f"{owner} calls time.{func.attr}")

        elif isinstance(func, ast.Name) and (
            func.id in TEMPORAL_PLATFORM_CLOCK_CALLS
        ):
            found.append(f"{owner} calls {func.id}")

    return tuple(found)


def _temporal_source_findings() -> (
    tuple[tuple[str, ...], tuple[str, ...]]
):
    """Both directions of the temporal deadline census.

    Four questions, one walk per module:

    1. does every declared **window site** establish its context through the
       temporal layer?
    2. does every declared **deadline site** avoid reading a platform clock
       of its own?
    3. does any function compare a security deadline without being declared?
    4. does any function on the ALLOW path read a platform clock, and does
       the temporal layer itself construct an authorization verdict?

    The rule about platform clocks is deliberately scoped to functions that
    *decide* something about a deadline -- a deadline comparison, or an
    authorization outcome -- rather than to every function that stamps a
    record with the time. A benchmark that measures itself with
    ``time.perf_counter`` and a lifecycle log that stamps an event with
    ``time.time`` are not answering a security question; a gate that decided
    a capability's expiry from ``time.time()`` would be.

    Question three is the one that matters over time: a later change cannot
    quietly add a window comparison somewhere the context is not
    established, because the census literal is where the sentence "these are
    all of them" is recorded.
    """

    root = source.package_root()

    if root is None:
        return (("the firewall package source could not be located",), ())

    findings: list[str] = []
    notes: list[str] = []
    present: set[str] = set()
    context_owners: dict[str, set[str]] = {}
    deadline_sites: dict[str, set[str]] = {}
    undeclared: list[str] = []
    unaudited_reads: list[str] = []
    allow_path_reads: list[str] = []
    verdicts: list[str] = []

    for path in source.source_modules(root):
        module = source.relative_name(path, root)
        present.add(module)

        try:
            tree = source.parse_module(path)
        except source.ParseFailure as error:
            findings.append(f"{module}: could not be parsed: {error}")
            continue

        calls_by_owner = _temporal_function_calls(tree)
        platform_reads = _temporal_platform_reads(tree)
        module_deadlines = _temporal_deadline_sites(tree)

        if module not in TEMPORAL_AUDIT_MODULES:
            for owner, calls in calls_by_owner.items():
                if calls & TEMPORAL_CONTEXT_CALLS:
                    context_owners.setdefault(module, set()).add(
                        _temporal_census_owner(owner)
                    )

            for owner, names in module_deadlines.items():
                if owner == "<module>":
                    undeclared.append(
                        f"{module}: <module level> compares a deadline "
                        f"({sorted(names)})"
                    )
                    continue

                reduced = _temporal_census_owner(owner)
                declared = (module, reduced) in (
                    TEMPORAL_WINDOW_SITES | TEMPORAL_DEADLINE_SITES
                )
                deadline_sites.setdefault(module, set()).add(reduced)

                if declared:
                    continue

                if module == "firewall/temporal.py":
                    continue

                undeclared.append(f"{module}:{owner} ({sorted(names)})")

            for entry in platform_reads:
                owner = entry.split(" calls ")[0]
                reduced = _temporal_census_owner(owner)

                if (
                    (module, reduced) in TEMPORAL_WINDOW_SITES
                    or (module, reduced) in TEMPORAL_DEADLINE_SITES
                    or owner in module_deadlines
                ):
                    unaudited_reads.append(f"{module}:{entry}")

                if (
                    module == "firewall/sdk.py"
                    and reduced.split(".")[-1] in TEMPORAL_ALLOW_PATH_OWNERS
                ):
                    allow_path_reads.append(f"{module}:{entry}")

        if module == "firewall/temporal.py":
            for call in source.walk_calls(tree):
                func = call.func
                name = (
                    func.id
                    if isinstance(func, ast.Name)
                    else func.attr
                    if isinstance(func, ast.Attribute)
                    else None
                )

                if name in ("AuthorizationResult", "_result"):
                    verdicts.append(f"{module}: calls {name}")

    for module, function in sorted(TEMPORAL_WINDOW_SITES):
        if module not in present:
            findings.append(
                f"{module}: named by the temporal census but absent from "
                "the package"
            )
            continue

        if function not in context_owners.get(module, set()):
            findings.append(
                f"{module}:{function} is declared a temporal window site "
                "but establishes no temporal context"
            )

    for module, function in sorted(TEMPORAL_DEADLINE_SITES):
        if module not in present:
            findings.append(
                f"{module}: named by the temporal census but absent from "
                "the package"
            )
            continue

        if function not in deadline_sites.get(module, set()):
            findings.append(
                f"{module}:{function} is declared a deadline site but "
                "compares no deadline"
            )

    if undeclared:
        findings.append(
            "a security deadline is compared outside the declared "
            "temporal sites ("
            + "; ".join(sorted(set(undeclared))[:6])
            + ")"
        )

    for entry in sorted(set(unaudited_reads)):
        findings.append(
            f"{entry}; a security deadline must be compared against a "
            "clock the temporal layer audited, not a platform clock"
        )

    for entry in sorted(set(allow_path_reads)):
        findings.append(
            f"{entry}; a function that decides an authorization outcome "
            "may not read a platform clock of its own"
        )

    for entry in sorted(set(verdicts)):
        findings.append(
            f"{entry} constructs an authorization verdict, which no layer "
            "outside the authorization boundary may do"
        )

    notes.append(
        f"{len(TEMPORAL_WINDOW_SITES)} declared temporal window sites and "
        f"{len(TEMPORAL_DEADLINE_SITES)} further deadline sites, all "
        "checked in both directions"
    )

    return tuple(findings), tuple(notes)


def _temporal_window_findings(
    sdk: "FirewallSDK",
) -> tuple[str, ...]:
    """Record-level temporal integrity across every journal.

    Five properties, all read from the records rather than from the code:

    * **Ordered local stamps.** Every timestamp this firewall wrote itself
      -- a lifecycle event, a lease or effect history entry, a verification
      claim, an attestation claim, a state commitment -- must be
      non-decreasing in the order it was recorded. The *issuer's* stamps are
      excluded on purpose: an external system's clock is not this
      firewall's to order.
    * **Well-formed windows.** Every recorded window must end no earlier
      than it begins, and a lease's deadline must not exceed the duration it
      was granted -- a record claiming a deadline beyond its own TTL is a
      record nothing granted.
    * **Consistent anchors.** The three monotonic anchor fields are either
      all present or all absent, and an anchor's generation must be the
      generation the record was written in.
    * **No completion outside its window.** A terminal lease's final
      history entry must not post-date the deadline it was granted.
    * **No attestation outside its window.** An ``ATTESTED`` claim must have
      been recorded inside the envelope's own validity window and no older
      than the deployment's maximum age.
    """

    findings: list[str] = []

    try:
        leases = sdk.execution_leases.records()
    except Exception as error:  # noqa: BLE001 - unreadable is a finding
        leases = ()
        findings.append(
            "the execution lease store could not be read: "
            f"{type(error).__name__}"
        )

    for lease in leases:
        label = f"lease {lease.lease_id[:8]}..."

        if lease.expires_at < lease.issued_at:
            findings.append(
                f"{label}: its deadline precedes its issue instant"
            )

        anchors = (
            lease.issued_monotonic,
            lease.ttl_seconds,
            lease.temporal_generation,
        )
        present = [value is not None for value in anchors]

        if any(present) and not all(present):
            findings.append(
                f"{label}: it carries {sum(present)} of 3 monotonic "
                "anchors; a partial anchor is a budget nobody can measure"
            )

        if lease.ttl_seconds is not None:
            ceiling = lease.issued_at + lease.ttl_seconds

            if lease.expires_at > ceiling + 1e-6:
                findings.append(
                    f"{label}: its deadline extends "
                    f"{lease.expires_at - ceiling:.3f}s beyond the "
                    "duration it was granted"
                )

        previous = None

        for entry in lease.history:
            at = entry[2]

            if previous is not None and at < previous:
                findings.append(
                    f"{label}: a history entry is stamped before the one "
                    "recorded before it"
                )
            previous = at

        if previous is not None and previous > lease.expires_at + 1e-6:
            findings.append(
                f"{label}: its final history entry is stamped "
                f"{previous - lease.expires_at:.3f}s after the deadline it "
                "was granted; a completion cannot outlive its own window"
            )

        state_value = getattr(lease.state, "value", None)

        if (
            lease.temporal_generation is not None
            and state_value == "completed"
            and not lease.complete_authority_valid
        ):
            findings.append(
                f"{label}: COMPLETED without a valid authority basis"
            )

    try:
        rows = sdk.effects.records()
    except Exception:  # noqa: BLE001 - unreadable is handled above
        rows = ()

    for row in rows:
        label = f"effect {row.effect_id[:8]}..."

        if row.expires_at < row.created_at:
            findings.append(
                f"{label}: its deadline precedes the instant the intent "
                "was recorded"
            )

        previous = None

        for entry in row.history:
            at = entry[2]

            if previous is not None and at < previous:
                findings.append(
                    f"{label}: a history entry is stamped before the one "
                    "recorded before it"
                )
            previous = at

    try:
        claims = sdk.verifications.records()
        max_age = None
    except Exception:  # noqa: BLE001
        claims = ()
        max_age = None

    previous = None

    for claim in claims:
        if (
            previous is not None
            and claim.recorded_at < previous
        ):
            findings.append(
                f"verification {claim.verification_id[:8]}...: recorded "
                "before the claim recorded before it"
            )
        previous = claim.recorded_at

    try:
        attestations = sdk.attestations.records()
        max_age = sdk.attestations.max_age
        skew = sdk.attestations.skew
    except Exception:  # noqa: BLE001
        attestations = ()
        max_age = None
        skew = 0.0

    previous = None

    for claim in attestations:
        label = f"attestation {claim.attestation_id[:8]}..."

        if previous is not None and claim.recorded_at < previous:
            findings.append(
                f"{label}: recorded before the claim recorded before it"
            )
        previous = claim.recorded_at

        anchors = (claim.recorded_monotonic, claim.temporal_generation)

        if (anchors[0] is None) != (anchors[1] is None):
            findings.append(
                f"{label}: it carries one of its two monotonic anchor "
                "fields; an age measured in a base nobody recorded"
            )

        if claim.outcome is not AttestationOutcome.ATTESTED:
            continue

        if claim.recorded_at + skew < claim.not_before:
            findings.append(
                f"{label}: ATTESTED before the window it names had opened"
            )

        if claim.recorded_at - skew > claim.expires_at:
            findings.append(
                f"{label}: ATTESTED after the window it names had closed"
            )

        if max_age is not None and (
            claim.recorded_at - claim.issued_at > max_age + skew
        ):
            findings.append(
                f"{label}: ATTESTED over an envelope older than the "
                "maximum age this deployment accepts"
            )

    try:
        commitments = sdk.state_commit_records()
    except Exception:  # noqa: BLE001
        commitments = ()

    previous = None

    for record in commitments:
        at = record.get("committed_at") if isinstance(record, dict) else None

        if at is None:
            continue

        if previous is not None and at < previous:
            findings.append(
                "a state commitment is stamped before the commitment "
                "recorded before it"
            )
        previous = at

    return tuple(findings)


def _temporal_live_findings(
    sdk: "FirewallSDK",
) -> tuple[str, ...]:
    """The guard's own history, its bindings, and the records' anchors.

    Nothing here re-decides anything: a recorded anomaly is *legitimate* --
    it is the mechanism working -- so an anomaly is not a violation. What is
    checked is that the machinery is intact and that no record claims a
    timing it cannot have had.
    """

    findings: list[str] = []
    guard = getattr(sdk, "temporal", None)

    if not isinstance(guard, TemporalGuard):
        return (
            "the SDK exposes no temporal guard, so no decision's temporal "
            "context can be established",
        )

    for label, attribute in TEMPORAL_BOUND_COMPONENTS:
        component = getattr(sdk, attribute, None)

        if component is None:
            continue

        if temporal_of(component) is not guard:
            findings.append(
                f"{label} is not bound to this SDK's temporal guard, so "
                "its own clock readings are unaudited"
            )

    snapshot = guard.snapshot()

    for name, entry in sorted(snapshot.get("sources", {}).items()):
        high = entry.get("wall_high_water")
        last = entry.get("last")

        if high is None:
            continue

        if last is not None and last.get("wall", 0.0) > high + 1e-9:
            findings.append(
                f"source {name!r}: a sampled reading is above its own "
                "high-water mark, so the history is inconsistent"
            )

        for anomaly in entry.get("anomalies", ()):
            reason = str(anomaly.get("reason", ""))

            if reason.split(":")[0] not in TEMPORAL_ANOMALY_REASONS:
                findings.append(
                    f"source {name!r}: recorded an anomaly this release "
                    f"cannot explain ({reason!r})"
                )

    # The reference is the newest monotonic reading the guard holds for this
    # generation, across *every* source it has sampled -- not one named
    # source's last reading. A lease is stamped by the execution-lease
    # source, which samples later than the authorize path's sdk source, so
    # comparing against "sdk" alone reported an honest lease as anchored in
    # the future. Every source in the guard's own history was sampled in this
    # generation, so the maximum of their high-water marks is the latest
    # instant the guard can observe.
    readings = [
        entry["monotonic_high_water"]
        for entry in snapshot.get("sources", {}).values()
        if isinstance(entry.get("monotonic_high_water"), (int, float))
    ]

    if readings:
        newest = max(readings)

        for lease in sdk.execution_leases.records():
            if (
                lease.temporal_generation is not None
                and lease.issued_monotonic is not None
                and lease.issued_monotonic > newest + guard.tolerance
            ):
                findings.append(
                    f"lease {lease.lease_id[:8]}...: its monotonic anchor "
                    "is in the future relative to this generation's newest "
                    "reading"
                )

    return tuple(findings)


def _temporal_probe_findings() -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Behavioural probes on a scratch SDK: ``(findings, blockers)``.

    ``blockers`` are failed positive controls. Neither is a violation, but
    both mean the negative probes would pass for a reason that has nothing
    to do with the property, so the result must be ``UNVERIFIABLE`` rather
    than green.

    Every probe builds its own SDK with its own injected wall clock and
    monotonic clock, so the measurement does not disturb the SDK it is
    auditing -- and so a rollback probe cannot leave the caller's guard
    suspect, which would make every later check in this run refuse.
    """

    findings: list[str] = []
    blockers: list[str] = []

    class _Wall:
        def __init__(self, value: float) -> None:
            self.value = value

        def __call__(self) -> float:
            return self.value

    class _Mono:
        def __init__(self, value: float = 10_000.0) -> None:
            self.value = value

        def __call__(self) -> float:
            return self.value

    def build():
        wall = _Wall(1_000_000.0)
        mono = _Mono()
        sdk = FirewallSDK(clock=wall, monotonic_clock=mono)
        sdk.generate_key("temporal-probe")
        capability = sdk.issue(
            agent="probe-agent",
            capability="payments.temporal",
            constraints={},
            expires_at=wall.value + 3_600.0,
        )
        return sdk, wall, mono, capability

    def build_established():
        """An SDK whose guard has already sampled this clock once.

        A regression is detectable only against a high-water mark the guard
        has itself recorded: an SDK whose first reading is already
        rolled back has no baseline to compare to, and refuses the request
        for the other reason the capability is invalid. So the probe
        establishes the baseline the way a deployment does -- by asking the
        boundary once -- and only then moves the clock. Without this step
        the probe would be measuring the *baseline* it failed to take, and
        would report the mechanism broken when it was merely unsampled.
        """

        sdk, wall, mono, capability = build()
        control, reason = outcome(sdk, capability)

        if control is not True:
            sdk.close()
            return None

        return sdk, wall, mono, capability

    def outcome(sdk, capability):
        try:
            result = sdk.authorize(capability, action="payments.temporal")
        except Exception as error:  # noqa: BLE001 - a raise is a finding
            return None, f"{type(error).__name__}: {error}"

        return bool(result.allowed), str(result.reason)

    # ---- positive control: an honest clock still allows ---------------
    sdk, wall, mono, capability = build()
    allowed, reason = outcome(sdk, capability)
    sdk.close()

    if allowed is None:
        blockers.append(f"the honest control raised ({reason})")
    elif allowed is not True:
        blockers.append(
            "the honest control was denied "
            f"({reason}), so a denial after a clock fault would prove "
            "nothing"
        )

    # ---- a rolled-back wall clock denies by name ----------------------
    built = build_established()

    if built is None:
        blockers.append(
            "a control authorization could not be obtained before the "
            "rollback probe, so the probe would measure an unestablished "
            "baseline"
        )
    else:
        sdk, wall, mono, capability = built
        wall.value -= 30.0
        allowed, reason = outcome(sdk, capability)
        sdk.close()

        if allowed is None:
            findings.append(
                "a rolled-back wall clock raised instead of denying "
                f"({reason})"
            )
        elif allowed is not False or not reason.startswith(
            TEMPORAL_ANOMALY_PREFIX
        ):
            findings.append(
                "a rolled-back wall clock was answered "
                f"allowed={allowed} reason={reason!r} rather than a "
                f"{TEMPORAL_ANOMALY_PREFIX} denial"
            )

    # ---- a regressed monotonic clock denies by name -------------------
    built = build_established()

    if built is None:
        blockers.append(
            "a control authorization could not be obtained before the "
            "monotonic-regression probe"
        )
    else:
        sdk, wall, mono, capability = built
        mono.value -= 5.0
        allowed, reason = outcome(sdk, capability)
        sdk.close()

        if allowed is None:
            findings.append(
                "a regressed monotonic clock raised instead of denying "
                f"({reason})"
            )
        elif allowed is not False or "monotonic_regression" not in reason:
            findings.append(
                "a regressed monotonic clock was answered "
                f"allowed={allowed} reason={reason!r} rather than a "
                "monotonic_regression denial"
            )

    # ---- time moving forward is not an anomaly ------------------------
    sdk, wall, mono, capability = build()
    outcome(sdk, capability)  # establish the baseline first
    wall.value += 7_200.0
    allowed, reason = outcome(sdk, capability)
    sdk.close()

    if allowed is None:
        findings.append(
            f"a forward clock jump raised instead of denying ({reason})"
        )
    elif reason.startswith(TEMPORAL_ANOMALY_PREFIX):
        findings.append(
            "a forward clock jump was refused as an anomaly, so ordinary "
            "passage of time would deny legitimate requests"
        )
    elif allowed is not False:
        findings.append(
            "a capability outside its window was allowed after a forward "
            "clock jump"
        )

    # ---- a lease's elapsed budget governs over a rolled-back clock ----
    sdk, wall, mono, capability = build()
    issued = sdk.authorize_execution(
        capability, "payments.temporal", {}, ttl=60.0
    )

    if not issued.allowed:
        blockers.append(
            "the lease control could not be issued "
            f"({issued.reason}), so the monotonic-budget probe did not run"
        )
        sdk.close()
    else:
        record = sdk.execution_leases.get(issued.lease.lease_id)
        mono.value += 61.0          # 61 s of elapsed time
        verdict = sdk.execution_leases.validity(record)
        sdk.close()

        if verdict != "lease_expired:monotonic_budget":
            findings.append(
                "a lease 61 s into a 60 s budget reported "
                f"{verdict!r}; elapsed time must close the window even "
                "when wall time has not moved"
            )

    # ---- the guard itself constructs no authority ---------------------
    return tuple(findings), tuple(blockers)


def check_temporal_security_integrity(
    sdk: Optional[Any],
) -> InvariantResult:
    """A decision is valid only within a provable temporal context.

    Three halves, and the result is the weakest of them.

    **Source census.** Every deadline comparison in the package is either a
    declared temporal window site -- and establishes its context through the
    temporal layer -- or a declared second evaluation that cannot widen
    authority. Nothing outside :mod:`firewall.temporal` reads a platform
    clock, and the temporal layer itself constructs no authorization verdict.

    **Record integrity.** Locally stamped security timestamps are ordered,
    windows are well formed, no lease claims a deadline beyond the duration
    it was granted, no completion outlives the window it was granted, and no
    attestation was recorded outside the envelope window it relies on.

    **Live integrity.** Every clock-reading store is bound to the guard, the
    guard's history is self-consistent with explainable anomalies, no
    recorded monotonic anchor points into the future, and on a scratch SDK
    the behavioural properties hold: an honest clock allows, a rolled-back
    wall clock and a regressed monotonic clock each deny by name, a forward
    jump is not mistaken for an attack, and an elapsed budget closes a lease
    a rolled-back wall clock would still call open.
    """

    source_findings, source_notes = _temporal_source_findings()

    if source_findings:
        return violated(
            _TEMPORAL_NAME,
            "a security deadline is compared outside the temporal layer, "
            "or the temporal layer itself does something it must not",
            findings=tuple(source_findings),
        )

    probe_findings, blockers = _temporal_probe_findings()

    if probe_findings:
        return violated(
            _TEMPORAL_NAME,
            "the boundary does not refuse a decision taken in a temporal "
            "context it cannot prove",
            findings=tuple(probe_findings),
        )

    problem = _require_sdk(sdk, _TEMPORAL_NAME)

    if problem is not None:
        return unverifiable(
            _TEMPORAL_NAME,
            "the source census and the temporal probes hold, but no "
            "FirewallSDK was supplied, so recorded windows and the live "
            "guard could not be inspected",
            source_notes=source_notes,
        )

    guard = getattr(sdk, "temporal", None)

    if not isinstance(guard, TemporalGuard):
        return violated(
            _TEMPORAL_NAME,
            "the SDK exposes no temporal guard, so no decision's temporal "
            "context can be established",
            findings=(f"temporal is {type(guard).__name__}",),
        )

    live_findings = _temporal_live_findings(sdk)
    window_findings = _temporal_window_findings(sdk)

    if live_findings or window_findings:
        return violated(
            _TEMPORAL_NAME,
            "the temporal context of a recorded security event is not "
            "provable from the records",
            findings=tuple(live_findings) + tuple(window_findings),
        )

    if not snapshot_has_samples(guard):
        return unverifiable(
            _TEMPORAL_NAME,
            "the source census, the probes and the record checks hold, but "
            "this SDK has sampled no clock, so its temporal history was "
            "never exercised",
            source_notes=source_notes,
        )

    if blockers:
        return unverifiable(
            _TEMPORAL_NAME,
            "the temporal probes could not be exercised: "
            + "; ".join(blockers),
            findings=tuple(blockers),
        )

    return holds(
        _TEMPORAL_NAME,
        "every security deadline is compared inside an audited temporal "
        "context, every recorded window is well formed and ordered, no "
        "completion or attestation outlives the window it relied on, and a "
        "rolled-back or regressed clock is refused by name",
        window_sites=len(TEMPORAL_WINDOW_SITES),
        deadline_sites=len(TEMPORAL_DEADLINE_SITES),
        sources=snapshot_sources(guard),
        source_notes=source_notes,
    )


def snapshot_has_samples(guard: Any) -> bool:
    """Whether the guard has audited at least one clock reading."""

    try:
        return bool(guard.snapshot().get("sources"))
    except Exception:  # noqa: BLE001 - an unreadable snapshot is no samples
        return False


def snapshot_sources(guard: Any) -> tuple[str, ...]:
    """The names of the sources the guard has audited."""

    try:
        return tuple(sorted(guard.snapshot().get("sources", {})))
    except Exception:  # noqa: BLE001
        return ()

# =====================================================================
# EXECUTION_LINEAGE_SOUNDNESS (v3.3)
# =====================================================================
#
# v3.3's claim: an execution can only progress when its complete lineage --
#
#   AUTHORIZED -> EXECUTED -> OBSERVED -> VERIFIED -> ATTESTED -> COMPLETED
#
# -- remains intact, unique, correctly bound and tamper-evident. The check
# has three halves, mirroring the shape of the verification, attestation and
# temporal invariants that precede it:
#
# * a **source census**, in both directions, over who may drive the lineage
#   journal -- plus the load-bearing negative: no function on the ALLOW path
#   may reference lineage state at all, so an authorization decision can
#   never come to rest on it;
# * **record integrity**: every stored link re-derives its own id, chains to
#   its parent, sits at a contiguous sequence and the ordinal its stage
#   requires, carries a binding digest that matches its own binding, and
#   accumulates that binding monotonically; exactly one commitment per stage;
#   at most one seal, last;
# * **cross-journal soundness**: every lineage names a real execution, its
#   binding agrees with the lease record it claims, the lease's phase agrees
#   with the stages committed, each evidence commitment describes the row the
#   journal actually holds, and no COMPLETED lease is missing a complete
#   lineage with nothing refused -- re-derived from the four journals, so a
#   stale or tampered completion cannot hide.

_LINEAGE_NAME = "EXECUTION_LINEAGE_SOUNDNESS"

#: The only module that may drive the lineage journal.
LINEAGE_MUTATOR_OWNERS = frozenset(
    {
        ("firewall/sdk.py", "FirewallSDK._open_lineage"),
        ("firewall/sdk.py", "FirewallSDK._advance_lineage"),
        ("firewall/sdk.py", "FirewallSDK._seal_lineage"),
        ("firewall/sdk.py", "FirewallSDK._record_lineage_refusal"),
    }
)

#: The lineage-journal mutators whose call sites the census constrains.
LINEAGE_MUTATOR_CALLS = frozenset(
    {"open", "advance", "seal", "record_finding"}
)

#: The attribute chain that names the lineage journal.
LINEAGE_TOKEN = "lineages"

#: Functions that decide an authorization outcome, none of which may
#: reference lineage state. The same rule the temporal invariant carries, for
#: the same reason: an ALLOW must never come to rest on a record that exists
#: to be *refused*.
#:
#: ``FirewallSDK.authorize_execution`` is deliberately **absent**, and the
#: reason is the point of the rule rather than an exception to it. Its name
#: suggests it decides, but it does not: the verdict is produced by
#: ``authorize()``, which it calls, and the lineage genesis is opened *after*
#: that allow and after the lease is issued. A function cannot rest a verdict
#: on a record it creates later, so listing it would demand that the lease
#: path never mention the lineage it exists to open -- which is the opposite
#: of the property being checked.
LINEAGE_ALLOW_PATH_OWNERS = frozenset(
    {
        "FirewallSDK.authorize",
        "FirewallSDK.authorize_continuous",
        "FirewallSDK.authorize_north_star",
        "FirewallSDK.authorize_with_delegation_budget",
        "FirewallSDK.revalidate",
        "FirewallSDK.is_authorized",
        "FirewallSDK.consume_nonce",
    }
)

#: Names whose presence in an ALLOW-path function body is a reference to
#: lineage state.
LINEAGE_REFERENCE_NAMES = frozenset(
    {
        "lineages",
        "lineage_records",
        "lineage_links",
        "lineage_findings",
        "lineage_for_lease",
        "_open_lineage",
        "_advance_lineage",
        "_seal_lineage",
        "_lineage_gate",
        "_lineage_gate_satisfied",
        "_lineage_head_stage",
        "_lineage_binding",
        "_lineage_for",
        "_complete_lineage_stages",
        "_adopt_lineage_stages",
    }
)

_LINEAGE_OWNER_NAMES = frozenset(
    name for _, name in LINEAGE_MUTATOR_OWNERS
)


def _lineage_census_owner(owner: str) -> str:
    """Longest census-shaped prefix of a qualified owner name."""

    parts = owner.split(".")

    for size in range(len(parts), 0, -1):
        candidate = ".".join(parts[:size])

        if candidate in _LINEAGE_OWNER_NAMES:
            return candidate

    return owner


def _lineage_on_allow_path(owner: str) -> bool:
    """Whether a qualified owner decides an authorization outcome.

    Two tests, and the first is a *prefix* test on the method's own name
    rather than a substring search over the qualified owner. The distinction
    is not pedantic: ``FirewallSDK._lineage_gate_satisfied`` contains the
    characters ``_gate_`` and is not a gate, and a rule that said otherwise
    would report the lineage layer's own helpers as part of the decision
    chain it is required to stay out of.
    """

    if not owner:
        return False

    method = owner.rsplit(".", 1)[-1]

    if method.startswith("_gate_"):
        return True

    parts = owner.split(".")

    for size in range(len(parts), 0, -1):
        if ".".join(parts[:size]) in LINEAGE_ALLOW_PATH_OWNERS:
            return True

    return False


def _lineage_source_findings() -> (
    tuple[tuple[str, ...], tuple[str, ...]]
):
    """Both directions of the lineage census, plus the ALLOW-path negative.

    Four questions, one walk per module:

    1. does every declared caller drive a lineage-journal mutator?
    2. does any *other* function drive one?
    3. does any function on the ALLOW path reference lineage state at all?
    4. does the lineage module itself construct an authorization verdict?
    """

    root = source.package_root()

    if root is None:
        return (("the firewall package source could not be located",), ())

    findings: list[str] = []
    notes: list[str] = []
    present: set[str] = set()
    found: dict[str, set[str]] = {}
    allow_path_references: list[str] = []
    verdicts: list[str] = []

    for path in source.source_modules(root):
        module = source.relative_name(path, root)
        present.add(module)

        try:
            tree = source.parse_module(path)
        except source.ParseFailure as error:
            findings.append(f"{module}: could not be parsed: {error}")
            continue

        owners = _qualified_functions(tree)
        node_owners = _attestation_node_owners(tree)

        for call in source.walk_calls(tree):
            func = call.func

            if not isinstance(func, ast.Attribute):
                continue

            if func.attr not in LINEAGE_MUTATOR_CALLS:
                continue

            if not _attribute_chain_has(func.value, LINEAGE_TOKEN):
                continue

            owner = owners.get(id(call))

            if owner is None:
                findings.append(
                    f"{module}: <module level> calls {func.attr} on the "
                    "lineage journal"
                )
                continue

            found.setdefault(module, set()).add(
                _lineage_census_owner(owner)
            )

        for node in ast.walk(tree):
            if not isinstance(node, ast.Attribute):
                continue

            if node.attr not in LINEAGE_REFERENCE_NAMES:
                continue

            owner = node_owners.get(id(node))

            if _lineage_on_allow_path(owner or ""):
                allow_path_references.append(
                    f"{module}:{owner} references '{node.attr}'"
                )

        if module == "firewall/lineage.py":
            for call in source.walk_calls(tree):
                func = call.func
                name = (
                    func.id
                    if isinstance(func, ast.Name)
                    else func.attr
                    if isinstance(func, ast.Attribute)
                    else None
                )

                if name in ("AuthorizationResult", "_result"):
                    verdicts.append(f"{module}: calls {name}")

    for module, function in sorted(LINEAGE_MUTATOR_OWNERS):
        if module not in present:
            findings.append(
                f"{module}: named by the lineage census but absent from the "
                "package"
            )
            continue

        if function not in found.get(module, set()):
            findings.append(
                f"{module}:{function} is declared a lineage journal caller "
                "but drives no journal mutator"
            )

    for module, functions in sorted(found.items()):
        for owner in sorted(functions):
            if (module, owner) in LINEAGE_MUTATOR_OWNERS:
                continue

            if module == "firewall/lineage.py":
                # The mechanism's own internals drive the journal by
                # definition: it *is* the journal.
                continue

            findings.append(
                f"{module}:{owner} drives the lineage journal but is not a "
                "declared lineage path"
            )

    if allow_path_references:
        findings.append(
            "lineage state is referenced from the ALLOW path ("
            + "; ".join(sorted(set(allow_path_references))[:5])
            + "); an authorization decision must never rest on the record "
            "of what an execution did"
        )

    for entry in sorted(set(verdicts)):
        findings.append(
            f"{entry} constructs an authorization verdict, which no layer "
            "outside the authorization boundary may do"
        )

    notes.append(
        f"{len(LINEAGE_MUTATOR_OWNERS)} declared lineage journal callers, "
        f"and {len(LINEAGE_REFERENCE_NAMES)} lineage reference names absent "
        "from the ALLOW path"
    )

    return tuple(findings), tuple(notes)


def _lineage_grouped(
    guard: LineageJournal,
) -> tuple[tuple[str, ExecutionLineage], ...]:
    """Every chain the journal *stores*, grouped and rebuilt from links.

    Deliberately rebuilt from ``links()`` rather than read from
    ``lineages()``, and that distinction is the whole point of doing it here.
    ``lineages()`` returns the journal's *published view*; a view is a cache,
    and a cache can disagree with the store it caches. An attacker with the
    store handle edits the links -- so the audit reads the links, groups them
    by lineage and verifies each group, and the cross-check against the
    published view happens separately. An audit that trusted the cache would
    be checking what the journal remembered rather than what it holds.
    """

    grouped: dict[str, list[Any]] = {}

    for link in guard.links():
        grouped.setdefault(link.lineage_id, []).append(link)

    chains: list[tuple[str, ExecutionLineage]] = []

    for lineage_id, links in grouped.items():
        links.sort(key=lambda item: item.sequence)

        chains.append(
            (
                lineage_id,
                ExecutionLineage(
                    lineage_id=lineage_id,
                    lease_id=(
                        links[0].binding.get("lease_id") or "" if links else ""
                    ),
                    execution_id=(
                        links[0].binding.get("execution_id") if links else None
                    ),
                    links=tuple(links),
                ),
            )
        )

    return tuple(chains)


def _lineage_record_findings(
    lineage: ExecutionLineage,
) -> tuple[str, ...]:
    """Record-level integrity for one stored chain.

    One finding per *property*, so a reader can tell whether the chain lost
    its anchor, lost a link, was re-ordered or was forged -- rather than
    being told only that it does not verify. The chain's own ``verify``
    supplies the detailed reasons; this adds the properties the invariant
    checks that the chain cannot check on its own.
    """

    findings: list[str] = []
    label = f"lineage {lineage.lineage_id[:8]}..."

    for problem in lineage.verify():
        findings.append(f"{label}: {problem}")

    if not lineage.intact:
        return tuple(findings)

    stages = lineage.stages

    if len(set(stages)) != len(stages):
        findings.append(
            f"{label}: a stage is committed more than once; the chain forked"
        )

    if len(lineage.links) and lineage.genesis is not None:
        if lineage.genesis.stage is not LineageStage.AUTHORIZED:
            findings.append(
                f"{label}: its genesis is not the AUTHORIZED commitment"
            )

    ordinals = [
        link.ordinal
        for link in lineage.links
        if link.is_commitment and link.ordinal is not None
    ]

    if ordinals and ordinals != list(range(len(ordinals))):
        findings.append(
            f"{label}: its ordinals are not the contiguous prefix 0..n-1"
        )

    for link in lineage.links:
        if not link.is_commitment:
            continue

        if link.binding_digest != binding_digest(link.binding):
            findings.append(
                f"{label}: link {link.sequence} carries a binding digest "
                "that does not match its own binding"
            )

    return tuple(findings)


def _lineage_cross_findings(
    sdk: "FirewallSDK",
) -> tuple[str, ...]:
    """Cross-journal soundness of every lineage against every journal.

    Five properties, each read from the records rather than from the code:

    * the lease the lineage names exists, and the lineage's binding agrees
      with it on every field the lease is authoritative for -- which is what
      makes "this chain is about that execution" a fact rather than a
      resemblance;
    * the lease's phase agrees with the stages committed: EXECUTED is
      committed exactly when the lease's own history shows the boundary was
      crossed, and COMPLETED exactly when the lease completed;
    * each evidence commitment describes the row the journal holds, by
      digest -- so a row edited after the chain was written is visible;
    * a stage recorded ``ADOPTED`` is one the journals support, and a
      contradicted claim is never recorded as adopted;
    * a COMPLETED lease carries a complete chain with nothing refused.
    """

    findings: list[str] = []
    guard = getattr(sdk, "lineages", None)

    if not isinstance(guard, LineageJournal):
        return (
            "the SDK exposes no lineage journal, so no execution's sequence "
            "can be proved",
        )

    try:
        published = {
            lineage.lineage_id: lineage for lineage in guard.lineages()
        }
        stored = _lineage_grouped(guard)
        leases = {
            record.lease_id: record
            for record in sdk.execution_leases.records()
        }
        rows = {
            row.lease_id: row for row in sdk.effects.records()
        }
    except Exception as error:  # noqa: BLE001 - unreadable is a finding
        return (
            "a lineage, lease or side-effect journal could not be read: "
            f"{type(error).__name__}",
        )

    # The journal's published view and the links it holds must agree, or one
    # of the two has been edited away from the other.
    for lineage_id, chain in stored:
        view = published.get(lineage_id)

        if view is None:
            findings.append(
                f"lineage {lineage_id[:8]}...: the journal holds links for it "
                "but publishes no lineage; the view and the store disagree"
            )
        elif tuple(view.links) != tuple(chain.links):
            findings.append(
                f"lineage {lineage_id[:8]}...: the published view does not "
                "match the links the journal holds; one of them was edited"
            )

    for lineage_id in published:
        if not any(lineage_id == stored_id for stored_id, _ in stored):
            findings.append(
                f"lineage {lineage_id[:8]}...: the journal publishes a "
                "lineage it holds no links for"
            )

    lineages = tuple(chain for _, chain in stored)

    try:
        findings_seen = tuple(guard.findings())
    except Exception:  # noqa: BLE001 - findings are advisory
        findings_seen = ()

    for finding in findings_seen:
        if finding.kind not in FINDING_KINDS:
            findings.append(
                f"a lineage finding was recorded that this release cannot "
                f"explain ({finding.kind!r})"
            )

    # One lineage per lease, and one per execution identity.
    seen_leases: dict[str, str] = {}
    seen_executions: dict[str, str] = {}

    for lineage in lineages:
        label = f"lineage {lineage.lineage_id[:8]}..."

        if lineage.lease_id in seen_leases:
            findings.append(
                f"{label}: a second lineage for lease "
                f"{lineage.lease_id[:8]}... ({seen_leases[lineage.lease_id]}); "
                "one execution must have one chain"
            )
        else:
            seen_leases[lineage.lease_id] = lineage.lineage_id

        if lineage.execution_id:
            if lineage.execution_id in seen_executions:
                findings.append(
                    f"{label}: a second lineage for execution "
                    f"{lineage.execution_id!r}; the identity may name one "
                    "in-flight execution"
                )
            else:
                seen_executions[lineage.execution_id] = lineage.lineage_id

        lease = leases.get(lineage.lease_id)

        if lease is None:
            findings.append(
                f"{label}: names lease {lineage.lease_id[:8]}... which no "
                "longer exists; a chain of custody must be about an "
                "execution"
            )
            continue

        binding = lineage.binding

        expected = {
            "capability_fingerprint": lease.capability_fingerprint,
            "agent_id": lease.agent_id,
            "capability": lease.capability,
            "action": lease.action,
            "request_digest": lease.request_digest,
            "policy_version": lease.policy_version,
        }

        for name, value in expected.items():
            if binding.get(name) != value:
                findings.append(
                    f"{label}: its binding says {name}="
                    f"{binding.get(name)!r} while the lease records "
                    f"{value!r}; the chain is bound to another execution"
                )

        if binding.get("execution_id") != lease.execution_id:
            findings.append(
                f"{label}: its binding names execution "
                f"{binding.get('execution_id')!r} while the lease records "
                f"{lease.execution_id!r}"
            )

        committed = set(lineage.stages)
        crossed = lease.executed or (
            getattr(lease.state, "value", "") in ("started", "completed")
            or any(
                entry[1] is ExecutionState.STARTED
                for entry in lease.history
            )
        )

        if LineageStage.EXECUTED in committed and not crossed:
            findings.append(
                f"{label}: EXECUTED is committed while the lease's own "
                "history shows the boundary was never crossed"
            )

        if crossed and LineageStage.EXECUTED not in committed:
            findings.append(
                f"{label}: the lease was started, but the chain holds no "
                "EXECUTED commitment; the record of the crossing is missing"
            )

        completed = getattr(lease.state, "value", "") == "completed"

        if completed and LineageStage.COMPLETED not in committed:
            findings.append(
                f"{label}: the lease is COMPLETED but the chain holds no "
                "COMPLETED commitment"
            )

        if LineageStage.COMPLETED in committed and not completed:
            findings.append(
                f"{label}: COMPLETED is committed while the lease is "
                f"{getattr(lease.state, 'value', 'unknown')}"
            )

        if not completed:
            continue

        row = rows.get(lineage.lease_id)

        problems = completeness_problems(
            lineage,
            side_effect_adopted=row is not None,
            attestation_required=bool(
                getattr(sdk, "require_external_attestation", False)
            ),
        )

        for problem in problems:
            findings.append(f"{label}: {problem}")

        if row is not None:
            findings.extend(
                _lineage_evidence_findings(sdk, lineage, row)
            )

    return tuple(findings)


def _lineage_evidence_findings(
    sdk: "FirewallSDK",
    lineage: ExecutionLineage,
    row: Any,
) -> tuple[str, ...]:
    """Whether each evidence commitment describes the row the journal holds.

    The chain commits to a *digest* of the row that justified each stage, so
    re-deriving that digest now is what makes a row edited after the fact
    visible. Two commitments are checked this way and they fail differently
    on purpose: a changed row means the chain and the journal disagree about
    what happened, which is a finding whichever one moved.
    """

    findings: list[str] = []
    label = f"lineage {lineage.lineage_id[:8]}..."

    observed = lineage.link_for(LineageStage.OBSERVED)

    if observed is None:
        return ()

    if observed.outcome is LineageOutcome.ADOPTED:
        if row.observed_outcome is None:
            findings.append(
                f"{label}: OBSERVED is committed as adopted while the "
                "side-effect row records no observation"
            )
        elif row.observed_outcome.value == "unknown":
            findings.append(
                f"{label}: OBSERVED is committed as adopted over an "
                "observation the journal recorded as unknown"
            )

    verified = lineage.link_for(LineageStage.VERIFIED)

    if verified is not None and (
        verified.outcome is LineageOutcome.ADOPTED
    ):
        try:
            claims = sdk._effect_current_claims(row)
        except Exception:  # noqa: BLE001 - unreadable is a finding
            claims = ()

        verdicts = [claim.outcome.value for claim in claims]

        if not claims:
            findings.append(
                f"{label}: VERIFIED is committed as adopted while the "
                "verification journal holds no current claim"
            )
        elif "contradicted" in verdicts:
            findings.append(
                f"{label}: VERIFIED is committed as adopted while the "
                "verification journal records a contradiction against the "
                "same evidence"
            )
        elif verdicts[-1] != "verified":
            findings.append(
                f"{label}: VERIFIED is committed as adopted while the "
                f"latest claim on the current evidence is {verdicts[-1]!r}"
            )

    attested = lineage.link_for(LineageStage.ATTESTED)

    if attested is not None and (
        attested.outcome is LineageOutcome.ADOPTED
    ):
        try:
            claims = sdk._attestation_current_claims(row)
        except Exception:  # noqa: BLE001 - unreadable is a finding
            claims = ()

        verdicts = [
            claim.outcome.value
            for claim in (claims or ())
        ]

        if not verdicts:
            findings.append(
                f"{label}: ATTESTED is committed as adopted while the "
                "attestation journal holds no current claim"
            )
        elif verdicts[-1] != "attested":
            findings.append(
                f"{label}: ATTESTED is committed as adopted while the "
                f"latest claim on the current attempt is {verdicts[-1]!r}"
            )

    return tuple(findings)


def check_execution_lineage_soundness(
    sdk: Optional[Any],
) -> InvariantResult:
    """An execution progresses only over an intact, unique, bound lineage.

    Three halves, and the result is the weakest of them.

    **Source census.** Only the declared SDK methods drive the lineage
    journal, and each of them does. No function that decides an
    authorization outcome references lineage state at all -- an ALLOW must
    never rest on the record of what an execution did -- and the lineage
    module constructs no verdict of its own.

    **Record integrity.** Every stored chain is checked link by link: ids
    re-derive, parents chain, sequences are contiguous, ordinals match the
    stage pipeline, binding digests match their bindings, no stage is
    committed twice, and at most one seal exists and it is last.

    **Cross-journal soundness.** Every lineage names a real lease and agrees
    with it on every field the lease is authoritative for; its stages agree
    with the lease's phase; its evidence commitments describe the rows the
    journals hold; and every COMPLETED lease carries a complete chain with
    nothing refused -- all re-derived from the records, so a stale or
    tampered completion cannot hide.
    """

    source_findings, source_notes = _lineage_source_findings()

    if source_findings:
        return violated(
            _LINEAGE_NAME,
            "a lineage path exists that the soundness census does not "
            "declare, or the ALLOW path references lineage state",
            findings=tuple(source_findings),
        )

    problem = _require_sdk(sdk, _LINEAGE_NAME)

    if problem is not None:
        return unverifiable(
            _LINEAGE_NAME,
            "the source census holds, but no FirewallSDK was supplied, so "
            "recorded execution lineages could not be inspected",
            source_notes=source_notes,
        )

    guard = getattr(sdk, "lineages", None)

    if not isinstance(guard, LineageJournal):
        return violated(
            _LINEAGE_NAME,
            "the SDK exposes no lineage journal, so no execution's sequence "
            "can be proved",
            findings=(f"lineages is {type(guard).__name__}",),
        )

    try:
        lineages = tuple(guard.lineages())
    except Exception as error:  # noqa: BLE001 - unreadable is a finding
        return unverifiable(
            _LINEAGE_NAME,
            "the lineage journal could not be read: "
            f"{type(error).__name__}",
        )

    if not lineages:
        return unverifiable(
            _LINEAGE_NAME,
            "the source census holds, but no execution lineage has been "
            "opened, so record-level lineage soundness could not be "
            "inspected",
            source_notes=source_notes,
        )

    record_findings: list[str] = []

    for lineage in lineages:
        record_findings.extend(_lineage_record_findings(lineage))

    cross_findings = _lineage_cross_findings(sdk)

    if record_findings or cross_findings:
        return violated(
            _LINEAGE_NAME,
            "an execution lineage is broken, forked, mis-bound or does not "
            "describe the execution its journals record",
            findings=tuple(record_findings) + tuple(cross_findings),
            lineages=len(lineages),
        )

    completed = sum(
        1 for lineage in lineages if lineage.completed
    )
    sealed = sum(1 for lineage in lineages if lineage.sealed)

    return holds(
        _LINEAGE_NAME,
        f"{len(lineages)} execution lineage(s) re-derive link by link, chain "
        "from their genesis anchor, agree with the lease and effect journals "
        f"they describe, and {completed} complete chain(s) carry all six "
        "stages with nothing refused",
        lineages=len(lineages),
        sealed=sealed,
        completed=completed,
        source_notes=source_notes,
    )


# =====================================================================
# EXTERNAL_ANCHOR_SOUNDNESS (v3.4)
# =====================================================================
#
# v3.4's claim: a trust root the firewall holds is not a root of trust.
#
# Every layer before this one raised the cost of tampering and then, in its
# honest-non-guarantees list, admitted the same thing -- the root of trust
# stayed inside the process. The lineage head is a row in the lineage store.
# A hash chain whose head sits next to the chain proves the chain is
# internally consistent; it does not prove the chain is the one that was
# built, because the only thing separating a real history from a fabricated
# one is a digest the same process also writes.
#
# The check has two halves, mirroring the shape of the four invariants that
# precede it:
#
# * a **source census**, in both directions, over who may drive the anchor
#   journal -- plus the load-bearing negative: no function on the ALLOW path
#   may reference anchor state at all, so an authorization decision can never
#   come to rest on a witness's statement about storage;
# * **record integrity and cross-journal soundness**: every stored checkpoint
#   re-derives to its own id, carries a signature that verifies under a key
#   the journal registered, and sits at a sequence strictly ahead of the one
#   before it; the confirmed set is a subset of the published set; every
#   finding is one the release can explain; and no COMPLETED execution's
#   anchor disagrees with the last confirmed checkpoint.

_ANCHOR_NAME = "EXTERNAL_ANCHOR_SOUNDNESS"

#: The only SDK methods that may drive the anchor journal.
ANCHOR_MUTATOR_OWNERS = frozenset(
    {
        ("firewall/sdk.py", "FirewallSDK.anchor_publish"),
        ("firewall/sdk.py", "FirewallSDK.anchor_confirm"),
    }
)

#: The anchor-journal mutators whose call sites the census constrains.
ANCHOR_MUTATOR_CALLS = frozenset(
    {"publish", "confirm", "record_finding"}
)

#: The attribute chain that names the anchor journal.
ANCHOR_TOKEN = "anchors"

#: Functions that decide an authorization outcome, none of which may
#: reference anchor state. The same rule the temporal and lineage invariants
#: carry, for the same reason: an ALLOW must never come to rest on a record
#: that exists to be *refused*.
ANCHOR_ALLOW_PATH_OWNERS = frozenset(
    {
        "FirewallSDK.authorize",
        "FirewallSDK.authorize_continuous",
        "FirewallSDK.authorize_north_star",
        "FirewallSDK.authorize_with_delegation_budget",
        "FirewallSDK.revalidate",
        "FirewallSDK.is_authorized",
        "FirewallSDK.consume_nonce",
    }
)

#: Names whose presence in an ALLOW-path function body is a reference to
#: anchor state.
ANCHOR_REFERENCE_NAMES = frozenset(
    {
        "anchors",
        "anchor_store",
        "anchor_journal",
        "anchor_publish",
        "anchor_confirm",
        "anchor_compare",
        "anchor_records",
        "anchor_receipts",
        "anchor_findings",
        "bind_anchor_reader",
        "bind_anchor_prefix_reader",
        "_anchor_gate",
        "_anchor_store",
        "_require_external_anchor",
    }
)

_ANCHOR_OWNER_NAMES = frozenset(
    name for _, name in ANCHOR_MUTATOR_OWNERS
)


def _anchor_census_owner(owner: str) -> str:
    """Longest census-shaped prefix of a qualified owner name."""

    parts = owner.split(".")

    for size in range(len(parts), 0, -1):
        candidate = ".".join(parts[:size])

        if candidate in _ANCHOR_OWNER_NAMES:
            return candidate

    return owner


def _anchor_on_allow_path(owner: str) -> bool:
    """Whether a qualified owner decides an authorization outcome."""

    if not owner:
        return False

    method = owner.rsplit(".", 1)[-1]

    if method.startswith("_gate_"):
        return True

    parts = owner.split(".")

    for size in range(len(parts), 0, -1):
        if ".".join(parts[:size]) in ANCHOR_ALLOW_PATH_OWNERS:
            return True

    return False


def _anchor_source_findings() -> (
    tuple[tuple[str, ...], tuple[str, ...]]
):
    """Both directions of the anchor census, plus the ALLOW-path negative.

    Four questions, one walk per module:

    1. does every declared caller drive an anchor-journal mutator?
    2. does any *other* function drive one?
    3. does any function on the ALLOW path reference anchor state at all?
    4. does the anchor module itself construct an authorization verdict?
    """

    root = source.package_root()

    if root is None:
        return (
            ("the firewall package source could not be located",),
            (),
        )

    findings: list[str] = []
    notes: list[str] = []
    present: set[str] = set()
    found: dict[str, set[str]] = {}
    allow_path_references: list[str] = []
    verdicts: list[str] = []

    for path in source.source_modules(root):
        module = source.relative_name(path, root)
        present.add(module)

        try:
            tree = source.parse_module(path)
        except source.ParseFailure as error:
            findings.append(f"{module}: could not be parsed: {error}")
            continue

        owners = _qualified_functions(tree)
        node_owners = _attestation_node_owners(tree)

        for call in source.walk_calls(tree):
            func = call.func

            if not isinstance(func, ast.Attribute):
                continue

            if func.attr not in ANCHOR_MUTATOR_CALLS:
                continue

            if not _attribute_chain_has(func.value, ANCHOR_TOKEN):
                continue

            owner = owners.get(id(call))

            if owner is None:
                findings.append(
                    f"{module}: <module level> calls {func.attr} on the "
                    "anchor journal"
                )
                continue

            found.setdefault(module, set()).add(
                _anchor_census_owner(owner)
            )

        for node in ast.walk(tree):
            if not isinstance(node, ast.Attribute):
                continue

            if node.attr not in ANCHOR_REFERENCE_NAMES:
                continue

            owner = node_owners.get(id(node))

            if _anchor_on_allow_path(owner or ""):
                allow_path_references.append(
                    f"{module}:{owner} references '{node.attr}'"
                )

        if module == "firewall/anchor.py":
            for call in source.walk_calls(tree):
                func = call.func
                name = (
                    func.id
                    if isinstance(func, ast.Name)
                    else func.attr
                    if isinstance(func, ast.Attribute)
                    else None
                )

                if name in ("AuthorizationResult", "_result"):
                    verdicts.append(f"{module}: calls {name}")

    for module, function in sorted(ANCHOR_MUTATOR_OWNERS):
        if module not in present:
            findings.append(
                f"{module}: named by the anchor census but absent from the "
                "package"
            )
            continue

        if function not in found.get(module, set()):
            findings.append(
                f"{module}:{function} is declared an anchor journal caller "
                "but drives no journal mutator"
            )

    for module, functions in sorted(found.items()):
        for owner in sorted(functions):
            if (module, owner) in ANCHOR_MUTATOR_OWNERS:
                continue

            if module == "firewall/anchor.py":
                # The mechanism's own internals drive the journal by
                # definition: it *is* the journal.
                continue

            findings.append(
                f"{module}:{owner} drives the anchor journal but is not a "
                "declared anchor path"
            )

    if allow_path_references:
        findings.append(
            "anchor state is referenced from the ALLOW path ("
            + "; ".join(sorted(set(allow_path_references))[:5])
            + "); an authorization decision must never rest on a witness's "
            "statement about storage"
        )

    for entry in sorted(set(verdicts)):
        findings.append(
            f"{entry} constructs an authorization verdict, which no layer "
            "outside the authorization boundary may do"
        )

    notes.append(
        f"{len(ANCHOR_MUTATOR_OWNERS)} declared anchor journal callers, and "
        f"{len(ANCHOR_REFERENCE_NAMES)} anchor reference names absent from "
        "the ALLOW path"
    )

    return tuple(findings), tuple(notes)


def _anchor_record_findings(
    journal: AnchorJournal,
) -> list[str]:
    """Every way one stored checkpoint can fail to be what it claims."""

    findings: list[str] = []

    try:
        records = journal.records()
    except Exception as exc:  # noqa: BLE001 - an unreadable store
        return [
            "the anchor store could not be read: "
            f"{type(exc).__name__}"
        ]

    for checkpoint in records:
        label = (
            f"{checkpoint.kind.value}@"
            f"{checkpoint.anchor_id[:8]}.../"
            f"{checkpoint.sequence}"
        )

        if checkpoint.rederived_id() != checkpoint.checkpoint_id:
            findings.append(
                f"{label}: the checkpoint id does not re-derive from its "
                "own fields"
            )
            continue

        if not checkpoint.is_signed():
            findings.append(f"{label}: the checkpoint carries no signature")

        if not journal.verify_receipt(checkpoint):
            findings.append(
                f"{label}: the checkpoint does not verify under a key this "
                "journal registered"
            )

    # Sequences must be strictly increasing per anchor, and the confirmed
    # set must be a subset of the published set. Both are properties the
    # store's primary key should already enforce, so a finding here means
    # the store was written around -- which is exactly what the invariant
    # exists to notice.
    published: dict[tuple[str, str], list[int]] = {}
    confirmed: dict[tuple[str, str], list[int]] = {}

    for checkpoint in records:
        key = (checkpoint.kind.value, checkpoint.anchor_id)
        published.setdefault(key, []).append(int(checkpoint.sequence))

    try:
        receipts = journal.receipts()
    except Exception as exc:  # noqa: BLE001 - an unreadable store
        findings.append(
            "the confirmed anchor set could not be read: "
            f"{type(exc).__name__}"
        )
        receipts = ()

    for checkpoint in receipts:
        key = (checkpoint.kind.value, checkpoint.anchor_id)
        confirmed.setdefault(key, []).append(int(checkpoint.sequence))

        if int(checkpoint.sequence) not in published.get(key, []):
            findings.append(
                f"{checkpoint.kind.value}@{checkpoint.anchor_id[:8]}.../"
                f"{checkpoint.sequence}: a confirmed checkpoint is not in "
                "the published set"
            )

    for key, sequences in sorted(published.items()):
        ordered = sorted(sequences)

        if len(set(ordered)) != len(ordered):
            findings.append(
                f"{key[0]}@{key[1][:8]}...: two checkpoints claim one "
                "sequence"
            )

    for key, sequences in sorted(confirmed.items()):
        if not sequences:
            continue

        if max(sequences) > max(published.get(key, [0])):
            findings.append(
                f"{key[0]}@{key[1][:8]}...: the confirmed sequence is ahead "
                "of anything published"
            )

    for finding in journal.findings():
        if finding.kind not in ANCHOR_FINDING_KINDS:
            findings.append(
                f"an anchor finding of kind {finding.kind!r} is not one "
                "this release can explain"
            )

    return findings


def _anchor_cross_findings(
    sdk: Any,
    journal: AnchorJournal,
) -> list[str]:
    """A completed execution whose anchor disagrees is a completion that
    rested on a trust root the firewall cannot prove is the one the witness
    confirmed. Re-derived from the records, so a stale completion cannot
    hide."""

    findings: list[str] = []

    if not getattr(sdk, "require_external_anchor", False):
        return findings

    try:
        lineages = sdk.lineage_records()
    except Exception:  # noqa: BLE001 - an unreadable journal
        return findings

    for lineage in lineages:
        if not getattr(lineage, "completed", False):
            continue

        try:
            reason = journal.compare(
                AnchorKind.LINEAGE_HEAD,
                lineage.lineage_id,
            )
        except Exception as exc:  # noqa: BLE001 - an unreadable anchor
            reason = f"anchor_unverifiable:{type(exc).__name__}"

        if reason is not None:
            findings.append(
                f"lineage {lineage.lineage_id[:8]}... is COMPLETED but its "
                f"anchor refuses: {reason}"
            )

    return findings


def check_external_anchor_soundness(
    sdk: Optional[Any],
) -> InvariantResult:
    """Every anchor read on a progression path is bound to something outside.

    Two halves, and the result is the weaker of them.

    **Source census.** Only the declared SDK methods drive the anchor
    journal, and each of them does. No function that decides an
    authorization outcome references anchor state at all -- an ALLOW must
    never rest on a witness's statement about storage -- and the anchor
    module constructs no verdict of its own.

    **Record integrity and cross-journal soundness.** Every stored
    checkpoint re-derives to its own id, carries a signature that verifies
    under a registered witness key, sits at a sequence the published set
    holds exactly once, and the confirmed set is a subset of it. Every
    finding is one the release can explain. And no COMPLETED execution's
    anchor disagrees with the last confirmed checkpoint.
    """

    source_findings, source_notes = _anchor_source_findings()

    if source_findings:
        return violated(
            _ANCHOR_NAME,
            "an anchor path exists that the soundness census does not "
            "declare, or the ALLOW path references anchor state",
            findings=tuple(source_findings),
        )

    problem = _require_sdk(sdk, _ANCHOR_NAME)

    if problem is not None:
        return unverifiable(
            _ANCHOR_NAME,
            "the source census holds in both directions, but no FirewallSDK "
            "was supplied, so the anchor records could not be inspected",
            source_notes=source_notes,
        )

    journal = getattr(sdk, "anchors", None)

    if not isinstance(journal, AnchorJournal):
        return violated(
            _ANCHOR_NAME,
            "the SDK exposes no anchor journal, so its progression paths "
            "have no external root of trust",
            findings=(f"anchors is {type(journal).__name__}",),
        )

    records = journal.records()

    if not records:
        return unverifiable(
            _ANCHOR_NAME,
            "the source census holds, but no anchor checkpoint has been "
            "published, so record-level anchor soundness could not be "
            "inspected",
            source_notes=source_notes,
        )

    findings = _anchor_record_findings(journal)
    findings.extend(_anchor_cross_findings(sdk, journal))

    if findings:
        return violated(
            _ANCHOR_NAME,
            "an anchor checkpoint does not re-derive, does not verify under "
            "a registered witness key, or a completed execution disagrees "
            "with the checkpoint its anchor was confirmed at",
            findings=tuple(findings),
            checkpoints=len(records),
        )

    receipts = journal.receipts()

    return holds(
        _ANCHOR_NAME,
        f"{len(records)} anchor checkpoint(s) re-derive and verify under a "
        f"registered witness key, {len(receipts)} are confirmed, and no "
        "completed execution disagrees with the checkpoint its anchor was "
        "confirmed at",
        checkpoints=len(records),
        confirmed=len(receipts),
        bound_kinds=journal.bound_kinds(),
        source_notes=source_notes,
    )
