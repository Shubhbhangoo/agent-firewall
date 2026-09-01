"""Runtime (live-state) checks for the v2.2 security invariants.

Seven of the eleven invariants are properties of a *running* system:
whether the delegation edges that actually exist narrow, whether a
revocation actually propagated, whether the authorization path denies
rather than raises on hostile input, whether a simulation left the
control plane untouched. Those cannot be read off the source, so they
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
from typing import Any, Optional, Sequence

from firewall.capability import Capability
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
        )
    except Exception as error:
        return None, f"{type(error).__name__}: {error}"

    return bool(result.allowed), None


def check_fail_closed() -> InvariantResult:
    """Hostile input produces a denial, never an exception or an allow.

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
    can still say yes.
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

    if findings:
        return violated(
            name,
            "the authorization path did not fail closed on hostile "
            "input",
            findings=tuple(findings),
            probes=len(probes),
        )

    return holds(
        name,
        f"a legitimate request is allowed and all {len(probes)} "
        "hostile probes are denied without raising",
        probes=len(probes),
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
