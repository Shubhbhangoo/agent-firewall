"""v2.5: attacking the composition -- Aegis, the envelope, and the races.

The v2.4 attack surface that is not one function is the *interaction*
between three things that each hold on their own: the Aegis state machine,
the authority envelope, and the eleven-gate chain. This file attacks the
seams.

Four findings and several failed attacks are pinned here.

**The envelope was not total.** ``authority_envelope`` documented that a
projection it cannot compute "yields the bottom envelope -- which excludes
everything -- rather than an exception or a permissive default", and then
raised for an unreadable revocation store, an unreadable trust store, an
unreadable lineage store, a capability that could not be fingerprinted and
non-numeric validity bounds. ENVELOPE_SOUNDNESS could not see it: the
projection raised, the invariant filed that under ``unresolved``, and the
report stayed green. Same shape as FAIL_CLOSED's original gap, in a second
invariant.

**A bottom envelope is only sound because the gates now deny.** Soundness
is ``excludes => the boundary denies``, so answering "excludes everything"
is a claim about every request against that grant. Before the v2.5 gate
fixes the boundary *raised* on exactly these inputs, and the bottom would
have been asserting a decision that was never made. The two fixes are
therefore not independent, and :class:`TestAnUnreadableProjectionIsBottom`
measures both halves together.

**The commit-time re-check covers suspension, not narrowing.** That is a
deliberate, documented asymmetry -- and it is a real race, so it is pinned
deterministically rather than described.

**One validity window was measured in two time bases.** ``issue`` let
``sign_capability`` default ``issued_at`` to ``time.time()`` while
``_gate_time`` compared against the injected clock, so the window the
boundary honoured was displaced from the window the capability's own
timestamps declare -- by exactly the skew the caller injected. The visible
symptom was fail-closed (``not_yet_valid`` on a freshly issued capability),
which is why it survived 4,000 tests and an invariant that had already
tripped over it. See :class:`TestOneWindowIsMeasuredInOneTimeBase`.

The failed attacks are here too, with the reason each failed, because a
failed attack is evidence only if the reason is known. In particular Aegis
state labels are *not* enforcement: a latched ``REVOKED`` that no registry
revocation stands behind does not deny, and that is architecture rather
than a defect. v2.4 pinned it on purpose; see
:class:`TestAegisStateIsALabelAndTheStoreIsEnforcement`.
"""

from __future__ import annotations

import dataclasses
import threading
import time
from typing import Any, Optional

import pytest

from firewall.aegis import AegisController, IllegalTransition
from firewall.aegis.state import AegisState
from firewall.sdk import FirewallSDK

ACTION = "payments.send"
NAMESPACE = "payments.*"
CONSTRAINTS = {"amount_max": 100}
CHILD_CONSTRAINTS = {"amount_max": 50}
WITHIN = {"amount": 10}
BEYOND = {"amount": 10_000}


class Unreadable:
    """One dependency whose named reads raise. Everything else forwards.

    The same wrapper the totality suite uses, and for the same reason:
    replacing a subsystem with a stub proves much less, because a denial
    afterwards could have any cause. Here exactly one question becomes
    unanswerable.
    """

    def __init__(self, wrapped: Any, *failing: str) -> None:
        object.__setattr__(self, "_wrapped", wrapped)
        object.__setattr__(self, "_failing", frozenset(failing))

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


def lineage() -> tuple[FirewallSDK, AegisController, Any, Any]:
    """An SDK with Aegis, a parent grant, and a narrower delegated child.

    A two-member chain rather than a single capability, because every
    composition question here is about what a restriction on one member
    does to a request against the other.
    """

    controller = AegisController()
    sdk = FirewallSDK(aegis=controller)
    sdk.generate_key("v25-composition")

    parent = sdk.issue(
        agent="probe-agent",
        capability=NAMESPACE,
        constraints=dict(CONSTRAINTS),
    )

    child = sdk.delegate(
        parent,
        sdk.active_key().private_key,
        delegatee="child-agent",
        constraints=dict(CHILD_CONSTRAINTS),
    ).child

    return sdk, controller, parent, child


def tracked(
    sdk: FirewallSDK,
    controller: AegisController,
    *capabilities: Any,
) -> tuple[str, ...]:
    """Register each capability with Aegis and return its fingerprint.

    ``_gate_aegis`` abstains entirely when Aegis tracks nothing, so a probe
    that forgot to register would measure the abstention rather than the
    restriction.
    """

    names = []

    for capability in capabilities:
        fingerprint = sdk.fingerprint(capability)
        controller.register(
            fingerprint,
            agent_id=capability.agent_id,
            capability=capability.capability,
        )
        names.append(fingerprint)

    return tuple(names)


def root() -> tuple[FirewallSDK, Any]:
    """A single signed capability, no Aegis, no delegation.

    The envelope probes want the smallest grant that can be projected, so
    that a bottom envelope is attributable to the sabotaged dependency and
    not to a chain that was already unresolvable.
    """

    sdk = FirewallSDK()
    sdk.generate_key("v25-envelope")

    capability = sdk.issue(
        agent="probe-agent",
        capability=ACTION,
        constraints=dict(CONSTRAINTS),
    )

    return sdk, capability


#: ``(attribute, read, boundary_prefix)`` for each dependency the
#: projection consults. The third element is the *boundary's* denial, not
#: the envelope's -- the two need not name the same subsystem, and for
#: lineage they do not: ``_gate_revocation`` runs before
#: ``_gate_delegation_chain`` and ``is_effectively_revoked`` walks the
#: lineage itself, so it is the revocation gate that reports the outage.
UNREADABLE_DEPENDENCIES = (
    (
        "revocation",
        "is_revoked",
        "revocation_state_unavailable:RuntimeError",
    ),
    (
        "issuer_trust_store",
        "is_trusted",
        "issuer_trust_unavailable:RuntimeError",
    ),
    (
        "delegation_lineage",
        "chain",
        "revocation_state_unavailable:RuntimeError",
    ),
)


class Hostile:
    """A constraint value that cannot be serialised, and so cannot be hashed
    into a fingerprint. Not malformed input in the parsing sense -- the
    capability is structurally intact and correctly signed, and the thing
    that fails is the projection's own bookkeeping.
    """

    def __repr__(self) -> str:
        return "<hostile>"


class TestAnUnreadableProjectionIsBottom:
    """Finding: ``authority_envelope`` raised where it promised bottom.

    Its docstring said a projection it cannot compute "yields the bottom
    envelope -- which excludes everything -- rather than an exception or a
    permissive default". Five reachable inputs contradicted that: three
    unreadable dependencies, a capability that cannot be fingerprinted, and
    a non-numeric validity bound. Only ``ValueError`` around chain
    resolution was guarded.

    Every probe here asserts *both* halves of soundness, because a bottom
    envelope is a claim about the boundary and not just about the
    projection. ``excludes`` returning a reason means "``authorize()``
    denies this"; if the boundary allowed, or raised, the bottom would be a
    lie about a decision that was never made. Before the v2.5 gate fixes it
    raised on exactly these inputs.
    """

    @pytest.mark.parametrize(
        "attribute,read,boundary_reason",
        UNREADABLE_DEPENDENCIES,
    )
    def test_an_unreadable_dependency_projects_bottom_and_denies(
        self,
        attribute: str,
        read: str,
        boundary_reason: str,
    ) -> None:
        sdk, capability = root()

        # Control. Without it a bottom envelope and a denial afterwards
        # could both be explained by a grant that never carried the
        # authority in the first place.
        healthy = sdk.authority_envelope(capability)
        assert healthy.bottom is False
        assert healthy.excludes(ACTION, WITHIN) is None
        assert sdk.authorize(
            capability,
            ACTION,
            WITHIN,
        ).allowed is True

        setattr(
            sdk,
            attribute,
            Unreadable(
                getattr(sdk, attribute),
                read,
            ),
        )

        envelope = sdk.authority_envelope(capability)

        assert envelope.bottom is True
        assert envelope.reasons == (
            "envelope_unavailable:RuntimeError",
        )

        # Bottom means *everything* is excluded, including the request the
        # control just had allowed.
        assert envelope.excludes(ACTION, WITHIN) == (
            "envelope_bottom:envelope_unavailable:RuntimeError"
        )
        assert envelope.excludes(ACTION, BEYOND)
        assert envelope.excludes("unrelated.action", {})

        # The other half: the boundary agrees, by denying rather than by
        # raising.
        outcome = sdk.authorize(capability, ACTION, WITHIN)

        assert outcome.allowed is False
        assert outcome.reason == boundary_reason

    @pytest.mark.parametrize(
        "field,value",
        [
            ("constraints", {"amount_max": Hostile()}),
            ("expires_at", object()),
        ],
        ids=["unfingerprintable", "non-numeric-bound"],
    )
    def test_a_capability_that_cannot_be_fingerprinted_is_bottom(
        self,
        field: str,
        value: Any,
    ) -> None:
        sdk, capability = root()

        assert sdk.authority_envelope(capability).bottom is False

        broken = dataclasses.replace(
            capability,
            **{field: value},
        )

        envelope = sdk.authority_envelope(broken)

        assert envelope.bottom is True
        assert envelope.reasons == (
            "envelope_unavailable:TypeError",
        )
        assert envelope.excludes(ACTION, WITHIN)

        outcome = sdk.authorize(broken, ACTION, WITHIN)

        assert outcome.allowed is False
        assert outcome.reason == "invalid_capability:TypeError"

    def test_a_non_capability_argument_still_raises(self) -> None:
        """The one raise kept, and the reason it is different in kind.

        Unreadable state is a security question the firewall must answer.
        A caller passing a string is a caller error: there is no grant to
        project, so there is no envelope whose bottom would mean anything.
        Returning bottom here would silently accept a bug.
        """

        sdk, _ = root()

        with pytest.raises(TypeError):
            sdk.authority_envelope("payments.send")  # type: ignore[arg-type]


class TestAegisStateIsALabelAndTheStoreIsEnforcement:
    """A failed attack, pinned with the reason it failed.

    ``mark_revoked`` leaves the grant labelled ``REVOKED`` while
    ``authorize()`` still allows. That looks like the worst possible bug --
    a revoked grant that authorises -- and it is not one, so the reason is
    recorded rather than the symptom silently accepted.

    Enforcement has exactly two sources: the revocation registry and the
    restriction store. ``AegisGrant.state`` is a label over them.
    ``mark_revoked`` documents that it "records a revocation the revocation
    registry owns; it does not perform one", and ``restriction_reason``
    consults only the store. So a bare label has nothing behind it.

    Making the label enforcing would make Aegis an authority -- in the
    denying direction, but still an authority, and one with no liftable
    restriction record behind its denials. The controller's own revoke path
    is built the other way round: it writes an ``aegis:suspend:revoked``
    restriction *first* and latches the label second, and suspends instead
    of latching if the hook did not fire.
    """

    def test_a_bare_revoked_label_does_not_deny(self) -> None:
        sdk, controller, _, child = lineage()
        (fingerprint,) = tracked(sdk, controller, child)

        controller.mark_revoked(fingerprint, reason="probe")

        assert controller.grant(fingerprint).state is AegisState.REVOKED
        assert (
            controller.restriction_reason(
                [fingerprint],
                ACTION,
                WITHIN,
            )
            is None
        )

        outcome = sdk.authorize(child, ACTION, WITHIN)

        assert outcome.allowed is True
        assert outcome.reason == "authorized"

    def test_the_registry_is_what_denies(self) -> None:
        """Same label, plus the enforcement the label is supposed to stand
        for. The denial arrives, and it is attributed to the registry."""

        sdk, controller, _, child = lineage()
        (fingerprint,) = tracked(sdk, controller, child)

        assert sdk.authorize(child, ACTION, WITHIN).allowed is True

        controller.mark_revoked(fingerprint, reason="probe")
        sdk.revoke(child, reason="probe")

        outcome = sdk.authorize(child, ACTION, WITHIN)

        assert outcome.allowed is False
        assert outcome.reason == "capability_revoked"

    def test_a_suspension_denies_because_it_writes_a_restriction(self) -> None:
        """The contrast that makes the point. ``suspend`` is not a label
        change; it writes to the store, and the store is enforcement. The
        denial names the restriction key, which is what makes it liftable.
        """

        sdk, controller, _, child = lineage()
        (fingerprint,) = tracked(sdk, controller, child)

        controller.suspend(
            fingerprint,
            key="incident-1",
            reason="probe",
            trigger="manual",
        )

        assert controller.grant(fingerprint).state is AegisState.SUSPENDED
        assert (
            controller.restriction_reason(
                [fingerprint],
                ACTION,
                WITHIN,
            )
            == "aegis_suspended:incident-1"
        )

        outcome = sdk.authorize(child, ACTION, WITHIN)

        assert outcome.allowed is False
        assert outcome.reason == "aegis_suspended:incident-1"


class TestLiftingASuspensionDoesNotRestoreAuthorityByItself:
    """Phase 2A: authority restoration must route through the boundary.

    ``lift`` removes the restriction and drops the grant to
    ``REVALIDATING`` -- residual authority zero -- rather than back to
    ``ACTIVE``. Only a canonical allow promotes it, and the probes here
    establish that the promotion is not something a caller can fake with a
    denial or with a different capability's success.
    """

    def test_a_lift_lands_in_revalidating_not_active(self) -> None:
        sdk, controller, _, child = lineage()
        (fingerprint,) = tracked(sdk, controller, child)

        controller.suspend(fingerprint, key="incident-1", reason="probe")

        removed = controller.lift(fingerprint, "incident-1")

        assert len(removed) == 1
        assert controller.grant(fingerprint).state is AegisState.REVALIDATING

        # The lift did remove the enforcement, so the boundary allows -- and
        # it is that allow, produced by the boundary, that promotes the
        # label.
        outcome = sdk.authorize(child, ACTION, WITHIN)

        assert outcome.allowed is True
        assert controller.grant(fingerprint).state is AegisState.ACTIVE

    def test_a_denied_request_does_not_promote_the_grant(self) -> None:
        sdk, controller, _, child = lineage()
        (fingerprint,) = tracked(sdk, controller, child)

        controller.suspend(fingerprint, key="incident-1", reason="probe")
        controller.lift(fingerprint, "incident-1")

        assert controller.grant(fingerprint).state is AegisState.REVALIDATING

        outcome = sdk.authorize(child, ACTION, BEYOND)

        assert outcome.allowed is False
        assert outcome.reason == "constraint_denied"
        assert controller.grant(fingerprint).state is AegisState.REVALIDATING

    def test_another_capabilitys_allow_does_not_promote_this_grant(
        self,
    ) -> None:
        """The observation is keyed by fingerprint. A sibling or ancestor
        succeeding is not evidence about *this* grant."""

        sdk, controller, parent, child = lineage()
        child_fingerprint, _ = tracked(sdk, controller, child, parent)

        controller.suspend(child_fingerprint, key="incident-1", reason="probe")
        controller.lift(child_fingerprint, "incident-1")

        assert sdk.authorize(parent, ACTION, WITHIN).allowed is True

        assert (
            controller.grant(child_fingerprint).state
            is AegisState.REVALIDATING
        )


class TestAParentRestrictionBindsTheChild:
    """Phase 2B: a restriction one level up must reach a delegated request.

    The attack is the mission's "create a child whose effective authority
    exceeds its parent". Aegis restrictions are keyed by fingerprint, so if
    ``_gate_aegis`` consulted only the presented capability, restricting the
    parent would leave every child of it untouched -- authority surviving
    below a restriction placed above it.

    It does not: the gate runs *after* chain resolution precisely so it can
    pass every ancestor fingerprint to the store. The narrowing case also
    shows the restriction is a ceiling and not a blanket denial, which
    matters because a restriction that denied everything would pass this
    test while being a different, blunter mechanism.
    """

    def test_suspending_the_parent_denies_the_child(self) -> None:
        sdk, controller, parent, child = lineage()
        _, parent_fingerprint = tracked(sdk, controller, child, parent)

        assert sdk.authorize(child, ACTION, WITHIN).allowed is True

        controller.suspend(
            parent_fingerprint,
            key="parent-incident",
            reason="probe",
        )

        outcome = sdk.authorize(child, ACTION, WITHIN)

        assert outcome.allowed is False
        assert outcome.reason == "aegis_suspended:parent-incident"

    def test_narrowing_the_parent_below_the_childs_ceiling_binds(
        self,
    ) -> None:
        """The child's own ceiling is 50 and the request is 10, so nothing
        about the child denies this. The parent's new ceiling of 5 does."""

        sdk, controller, parent, child = lineage()
        _, parent_fingerprint = tracked(sdk, controller, child, parent)

        controller.narrow(
            parent_fingerprint,
            key="parent-narrow",
            reason="probe",
            constraints={"amount_max": 5},
        )

        denied = sdk.authorize(child, ACTION, WITHIN)

        assert denied.allowed is False
        assert denied.reason == "aegis_constraint_denied:parent-narrow"

    def test_the_narrowing_is_a_ceiling_not_a_blanket_denial(self) -> None:
        sdk, controller, parent, child = lineage()
        _, parent_fingerprint = tracked(sdk, controller, child, parent)

        controller.narrow(
            parent_fingerprint,
            key="parent-narrow",
            reason="probe",
            constraints={"amount_max": 5},
        )

        allowed = sdk.authorize(child, ACTION, {"amount": 1})

        assert allowed.allowed is True
        assert allowed.reason == "authorized"

    def test_a_child_cannot_be_delegated_past_a_narrowed_parent(self) -> None:
        """The other direction: issuing new authority under a restricted
        parent. Delegation attenuates against the parent *capability*, which
        Aegis does not rewrite -- so the grant is issuable at 50, and it is
        the boundary that refuses to honour it. Aegis restricts; it does not
        reissue capabilities, and it must not, because a rewritten
        capability would be authority created outside the signing path.
        """

        sdk, controller, parent, child = lineage()
        _, parent_fingerprint = tracked(sdk, controller, child, parent)

        controller.narrow(
            parent_fingerprint,
            key="parent-narrow",
            reason="probe",
            constraints={"amount_max": 5},
        )

        grandchild = sdk.delegate(
            child,
            sdk.active_key().private_key,
            delegatee="grandchild-agent",
            constraints=dict(CHILD_CONSTRAINTS),
        ).child

        outcome = sdk.authorize(grandchild, ACTION, WITHIN)

        assert outcome.allowed is False
        assert outcome.reason == "aegis_constraint_denied:parent-narrow"


class TestTheEnvelopeIsNotAnApproval:
    """Phase 2C: what the envelope leaves out, deliberately.

    ``may_admit`` is the negation of ``excludes``, so it answers "the
    envelope does not rule this out" and never "the boundary will allow
    this". The mission asks specifically for the opposite bug -- an envelope
    failing to exclude something the boundary necessarily denies -- and this
    is a case of exactly that, on purpose: the projection describes the
    *signed grant*, and live Aegis restrictions are not folded in.

    That is safe in the one direction soundness needs (nothing the envelope
    excludes is allowed) and it is why ``may_admit`` cannot be used as a
    pre-authorisation check. A caller that treated it as one would be
    reading an approval out of a description, which is the second
    authorization path the Prime Directive forbids.
    """

    def test_may_admit_ignores_a_live_narrowing_the_boundary_enforces(
        self,
    ) -> None:
        sdk, controller, parent, child = lineage()
        _, parent_fingerprint = tracked(sdk, controller, child, parent)

        controller.narrow(
            parent_fingerprint,
            key="parent-narrow",
            reason="probe",
            constraints={"amount_max": 5},
        )

        envelope = sdk.authority_envelope(child)

        assert envelope.bottom is False
        assert envelope.excludes(ACTION, WITHIN) is None
        assert envelope.may_admit(ACTION, WITHIN) is True

        assert sdk.authorize(child, ACTION, WITHIN).allowed is False

    def test_the_direction_soundness_needs_still_holds(self) -> None:
        """Omitting restrictions is only safe because it can never make the
        envelope *narrower* than the truth. What it does exclude -- here the
        child's own signed ceiling -- the boundary denies."""

        sdk, controller, parent, child = lineage()
        tracked(sdk, controller, child, parent)

        envelope = sdk.authority_envelope(child)

        assert envelope.excludes(ACTION, BEYOND) == "ceiling_exceeded:amount"
        assert envelope.may_admit(ACTION, BEYOND) is False

        outcome = sdk.authorize(child, ACTION, BEYOND)

        assert outcome.allowed is False
        assert outcome.reason == "constraint_denied"


class Blocked:
    """Hold a request open inside signature verification, without sleeping.

    The window this parks in is the one the implementation itself names:
    ``_gate_aegis`` runs before ``_gate_cryptographic_authority``, which
    verifies signatures over the whole chain and is the slowest step in the
    pipeline. Parking the *first* verification means the request has passed
    the Aegis gate and has not yet reached the commit re-check, which is
    exactly the interval a concurrent restriction has to land in.

    Two events make the interleaving deterministic rather than likely:
    ``arrived`` is set from inside the window, and the request does not
    resume until ``resume`` is set. No sleeps, so nothing here is a race
    against the scheduler.
    """

    def __init__(self, verify: Any) -> None:
        self._verify = verify
        self.arrived = threading.Event()
        self.resume = threading.Event()
        self._parked = False

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        if not self._parked:
            self._parked = True
            self.arrived.set()

            if not self.resume.wait(10):  # pragma: no cover - deadlock guard
                raise AssertionError("the request was never released")

        return self._verify(*args, **kwargs)


def during_verification(
    sdk: FirewallSDK,
    capability: Any,
    land: Any,
) -> Any:
    """Run one authorization, invoking ``land`` while it sits mid-flight."""

    blocked = Blocked(sdk.verifier.verify)
    sdk.verifier.verify = blocked  # type: ignore[method-assign]

    outcome: dict[str, Any] = {}

    def request() -> None:
        outcome["result"] = sdk.authorize(capability, ACTION, WITHIN)

    thread = threading.Thread(target=request)
    thread.start()

    try:
        assert blocked.arrived.wait(10), "verification was never reached"
        land()
    finally:
        blocked.resume.set()
        thread.join(10)

    assert not thread.is_alive(), "the authorization never returned"

    return outcome["result"]


class TestTheCommitWindowRaces:
    """Phase 2D: the Race Matrix, deterministically.

    Every row lands a restriction in the interval between ``_gate_aegis``
    and the commit re-check in ``_gate_transaction``. The first four rows
    are caught. The fifth is not, and it is a documented asymmetry rather
    than an oversight: ``_gate_transaction`` re-reads revocation and Aegis
    *suspension*, and deliberately not the full constraint evaluation,
    because suspension is the total refusal and the cheapest question the
    store answers, and a slow check inside the transaction would widen the
    window it exists to close.

    The narrowing row is therefore pinned as a *measurement of the
    non-guarantee*, not as an aspiration. A request that has already passed
    the Aegis gate completes under the constraints that were live when the
    gate evaluated it. The bound on that is the row after it: the very next
    request is denied.
    """

    def test_a_suspension_landing_mid_flight_is_caught_at_commit(
        self,
    ) -> None:
        sdk, controller, parent, child = lineage()
        child_fingerprint, _ = tracked(sdk, controller, child, parent)

        result = during_verification(
            sdk,
            child,
            lambda: controller.suspend(
                child_fingerprint,
                key="mid-flight",
                reason="race",
            ),
        )

        assert result.allowed is False
        assert result.reason == (
            f"aegis_suspended_at_commit:{child_fingerprint}"
        )

    def test_a_parent_suspension_landing_mid_flight_is_caught(self) -> None:
        """The commit re-check passes the whole resolved chain, not just the
        presented fingerprint, so an ancestor suspended mid-flight is caught
        too -- and the reason names which member it was."""

        sdk, controller, parent, child = lineage()
        _, parent_fingerprint = tracked(sdk, controller, child, parent)

        result = during_verification(
            sdk,
            child,
            lambda: controller.suspend(
                parent_fingerprint,
                key="mid-flight",
                reason="race",
            ),
        )

        assert result.allowed is False
        assert result.reason == (
            f"aegis_suspended_at_commit:{parent_fingerprint}"
        )

    def test_a_revocation_landing_mid_flight_is_caught_at_commit(self) -> None:
        sdk, controller, parent, child = lineage()
        tracked(sdk, controller, child, parent)

        result = during_verification(
            sdk,
            child,
            lambda: sdk.revoke(child, reason="race"),
        )

        assert result.allowed is False
        assert result.reason == "capability_revoked"

    def test_an_ancestor_revocation_landing_mid_flight_is_caught(self) -> None:
        sdk, controller, parent, child = lineage()
        tracked(sdk, controller, child, parent)

        result = during_verification(
            sdk,
            child,
            lambda: sdk.revoke(parent, reason="race"),
        )

        assert result.allowed is False
        assert result.reason == "capability_revoked"

    def test_a_narrowing_landing_mid_flight_completes_the_in_flight_request(
        self,
    ) -> None:
        """The documented non-guarantee, measured.

        The request is for 10, the narrowing takes the ceiling to 1, and the
        request completes as authorized. It is not a *widening* -- the
        narrowing landed after the only gate that evaluates constraints -- but
        it does mean the serialization point for a narrowing is
        ``_gate_aegis`` and not the commit.
        """

        sdk, controller, parent, child = lineage()
        child_fingerprint, _ = tracked(sdk, controller, child, parent)

        result = during_verification(
            sdk,
            child,
            lambda: controller.narrow(
                child_fingerprint,
                key="mid-flight",
                reason="race",
                constraints={"amount_max": 1},
            ),
        )

        assert result.allowed is True
        assert result.reason == "authorized"

        # And the bound on it: the window is one in-flight request wide.
        after = sdk.authorize(child, ACTION, WITHIN)

        assert after.allowed is False
        assert after.reason == "aegis_constraint_denied:mid-flight"

    def test_a_narrowing_landing_before_the_gate_is_enforced(self) -> None:
        """The control for the row above. Without it, "a narrowing is not
        re-checked at commit" would be indistinguishable from "a narrowing is
        never enforced", and only one of those is the documented behaviour.

        It also shows *why* the asymmetry exists. This request never reaches
        signature verification: ``_gate_aegis`` denies upstream of the
        expensive step, so constraint evaluation is cheap there and would not
        be at the commit, which runs inside the transaction.
        """

        sdk, controller, parent, child = lineage()
        child_fingerprint, _ = tracked(sdk, controller, child, parent)

        controller.narrow(
            child_fingerprint,
            key="pre-flight",
            reason="race",
            constraints={"amount_max": 1},
        )

        verifications = []
        real = sdk.verifier.verify

        def counted(*args: Any, **kwargs: Any) -> Any:
            verifications.append(args)
            return real(*args, **kwargs)

        sdk.verifier.verify = counted  # type: ignore[method-assign]

        result = sdk.authorize(child, ACTION, WITHIN)

        assert result.allowed is False
        assert result.reason == "aegis_constraint_denied:pre-flight"
        assert verifications == []


class TestTheStatefulWalk:
    """Phase 7: drive the whole lifecycle and watch for authority appearing.

    The sequence the mission asks for -- issue, delegate, authorize, narrow,
    authorize, revalidate, suspend, authorize, lift, authorize, revoke,
    authorize, expire, authorize -- run as one walk over one grant, with the
    boundary's verdict recorded at every step.

    The property is not that the state label never rises. It does rise, once,
    and legitimately: lifting a suspension lands in ``REVALIDATING`` and a
    canonical allow promotes it to ``ACTIVE``. The property is that *every
    allow in the walk is an allow the boundary produced against unrestricted
    state* -- so a restriction, once applied, always shows up as the next
    verdict, and a registry revocation is never undone by anything the
    controller can do afterwards.
    """

    def test_no_step_in_the_walk_produces_unearned_authority(self) -> None:
        sdk, controller, parent, child = lineage()
        (fingerprint,) = tracked(sdk, controller, child)

        verdicts: list[tuple[str, bool, str, AegisState]] = []

        def step(label: str) -> None:
            outcome = sdk.authorize(child, ACTION, WITHIN)
            verdicts.append(
                (
                    label,
                    outcome.allowed,
                    outcome.reason,
                    controller.grant(fingerprint).state,
                )
            )

        step("issued")

        controller.narrow(
            fingerprint,
            key="n",
            reason="walk",
            constraints={"amount_max": 1},
        )
        step("narrowed")

        # An invalid transition: leaving NARROWED means naming the
        # restriction being lifted, so this cannot be used to shed the
        # narrowing by relabelling.
        with pytest.raises(IllegalTransition):
            controller.begin_revalidation(fingerprint)

        step("narrowed-after-refused-transition")

        controller.suspend(fingerprint, key="s", reason="walk")
        step("suspended")

        controller.lift(fingerprint, "s")
        controller.lift(fingerprint, "n")
        step("lifted")

        sdk.revoke(child, reason="walk")
        step("revoked")

        # Nothing the controller can do afterwards restores it. The label is
        # terminal, and -- more to the point -- the registry entry is what
        # denies, and the controller does not own the registry.
        controller.mark_revoked(fingerprint, reason="walk")

        with pytest.raises(IllegalTransition):
            controller.expire(fingerprint, reason="walk")

        step("after-terminal-attempts")

        labels = [entry[0] for entry in verdicts]
        allowed = [entry[0] for entry in verdicts if entry[1]]
        reasons = {entry[0]: entry[2] for entry in verdicts}

        assert labels == [
            "issued",
            "narrowed",
            "narrowed-after-refused-transition",
            "suspended",
            "lifted",
            "revoked",
            "after-terminal-attempts",
        ]

        # Exactly two allows: the unrestricted grant at the start, and the
        # grant after both restrictions were explicitly lifted.
        assert allowed == ["issued", "lifted"]

        assert reasons["narrowed"] == "aegis_constraint_denied:n"
        assert reasons["narrowed-after-refused-transition"] == (
            "aegis_constraint_denied:n"
        )
        assert reasons["suspended"] == "aegis_suspended:s"
        assert reasons["revoked"] == "capability_revoked"
        assert reasons["after-terminal-attempts"] == "capability_revoked"

    def test_the_child_never_outlives_a_restriction_on_the_parent(
        self,
    ) -> None:
        """The same walk from the parent's side. Whatever is done to the
        parent, the child's effective authority is never wider -- and the two
        move together, so the child cannot be left holding authority the
        parent has lost.
        """

        sdk, controller, parent, child = lineage()
        child_fingerprint, parent_fingerprint = tracked(
            sdk,
            controller,
            child,
            parent,
        )

        def both() -> tuple[bool, bool]:
            return (
                sdk.authorize(parent, ACTION, WITHIN).allowed,
                sdk.authorize(child, ACTION, WITHIN).allowed,
            )

        observed = [both()]

        controller.narrow(
            parent_fingerprint,
            key="pn",
            reason="walk",
            constraints={"amount_max": 1},
        )
        observed.append(both())

        controller.suspend(parent_fingerprint, key="ps", reason="walk")
        observed.append(both())

        controller.lift(parent_fingerprint, "ps")
        controller.lift(parent_fingerprint, "pn")
        observed.append(both())

        sdk.revoke(parent, reason="walk")
        observed.append(both())

        assert observed == [
            (True, True),
            (False, False),
            (False, False),
            (True, True),
            (False, False),
        ]

        # And the child is restricted at every step where the parent is, with
        # no step where the child is wider.
        assert not any(
            child_allowed and not parent_allowed
            for parent_allowed, child_allowed in observed
        )


class Clockless:
    """A verifier with no ``clock`` attribute at all. Forwards the rest."""

    clock = None

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


class TestOneWindowIsMeasuredInOneTimeBase:
    """Finding: issuance and the boundary read different clocks.

    ``FirewallSDK(clock=...)`` reaches the verifier, and ``_gate_time``
    compares against it -- but ``issue`` passed ``issued_at=None`` through to
    ``sign_capability``, which defaulted it to ``time.time()``. So the start
    of a validity window came from wall time while the comparison against
    that window came from the injected clock, and the default
    ``expires_at = issued_at + 3600`` was anchored in the wall-time base too.

    The visible symptom is a freshly issued capability denied as
    ``not_yet_valid``, which is fail-closed and was therefore easy to miss.
    The security-relevant half is the other one: the window the boundary
    honours is displaced from the window the capability's own timestamps
    declare, by whatever skew the caller injected.

    An earlier session met the symptom from the other side and left a
    comment in ``check_envelope_soundness`` reading "``issue`` stamps
    ``issued_at`` from the clock" -- which was not true of this path, and is
    now. ``mint_session_capability`` already stamped from the boundary's
    clock, so the fix makes the two issuance paths agree rather than
    inventing a rule.
    """

    def test_issued_at_comes_from_the_boundarys_clock(self) -> None:
        # An explicit skew rather than whatever elapsed during construction:
        # the defect is proportional to how far the injected clock sits from
        # wall time, so the probe states that distance instead of racing it.
        frozen = [time.time() - 600.0]
        sdk = FirewallSDK(clock=lambda: frozen[0])
        sdk.generate_key("v25-clock")

        capability = sdk.issue(
            agent="probe-agent",
            capability=ACTION,
            constraints=dict(CONSTRAINTS),
        )

        assert capability.issued_at == frozen[0]

        # The regression: before the fix ``issued_at`` was wall time, ten
        # minutes ahead of the clock the boundary reads, and this request was
        # denied ``not_yet_valid``.
        assert capability.issued_at < time.time() - 300.0

        outcome = sdk.authorize(capability, ACTION, WITHIN)

        assert outcome.allowed is True
        assert outcome.reason == "authorized"

    def test_the_default_lifetime_is_anchored_in_the_same_base(self) -> None:
        frozen = [time.time()]
        sdk = FirewallSDK(clock=lambda: frozen[0])
        sdk.generate_key("v25-clock")

        capability = sdk.issue(
            agent="probe-agent",
            capability=ACTION,
            constraints=dict(CONSTRAINTS),
        )

        assert capability.issued_at == frozen[0]
        assert capability.expires_at - capability.issued_at == 3_600.0

        assert sdk.authorize(capability, ACTION, WITHIN).allowed is True

        # And expiry is judged in that base, so the window is exactly the one
        # the capability declares -- no displacement in either direction.
        frozen[0] = capability.expires_at - 1.0
        assert sdk.authorize(capability, ACTION, WITHIN).allowed is True

        frozen[0] = capability.expires_at
        expired = sdk.authorize(capability, ACTION, WITHIN)

        assert expired.allowed is False
        assert expired.reason == "expired"

    def test_an_explicit_issued_at_is_still_the_callers_to_set(self) -> None:
        """The clock is a *default*. A caller backdating a capability on
        purpose -- replaying a historical grant, reconstructing an audit
        scenario -- is not overridden."""

        sdk = FirewallSDK()
        sdk.generate_key("v25-clock")

        capability = sdk.issue(
            agent="probe-agent",
            capability=ACTION,
            issued_at=1_000.0,
            expires_at=2_000.0,
        )

        assert capability.issued_at == 1_000.0
        assert capability.expires_at == 2_000.0

    @pytest.mark.parametrize(
        "label,clock,message",
        [
            (
                "clockless",
                None,
                "the verifier exposes no clock",
            ),
            (
                "raises",
                "raise",
                "the clock could not be read",
            ),
            (
                "non-finite",
                float("nan"),
                "the clock returned a non-finite reading",
            ),
        ],
    )
    def test_an_unusable_clock_refuses_to_issue(
        self,
        label: str,
        clock: Any,
        message: str,
    ) -> None:
        """Refusing to issue, rather than falling back to wall time.

        A silent fallback would put the capability back in a base the
        boundary cannot compare against -- the exact defect, reintroduced as
        an error path. Note the asymmetry with ``authorize()``, which *denies*
        for the same unreadable clock instead of raising: the boundary owes
        every caller a decision, and issuance owes nobody a capability.
        """

        if clock is None:
            sdk = FirewallSDK()
            sdk.generate_key("v25-clock")
            sdk.verifier = Clockless(sdk.verifier)  # type: ignore[assignment]
        elif clock == "raise":

            def unreachable() -> float:
                raise RuntimeError("clock is unreachable")

            sdk = FirewallSDK(clock=unreachable)
            sdk.generate_key("v25-clock")
        else:
            sdk = FirewallSDK(clock=lambda: clock)
            sdk.generate_key("v25-clock")

        with pytest.raises(ValueError, match=message):
            sdk.issue(
                agent="probe-agent",
                capability=ACTION,
                constraints=dict(CONSTRAINTS),
            )

    def test_mint_session_capability_already_agreed(self) -> None:
        """The precedent. It stamped from the boundary's clock before v2.5,
        which is why the fix is a consistency correction and not a new rule.
        """

        frozen = [time.time()]
        sdk = FirewallSDK(clock=lambda: frozen[0])
        sdk.generate_key("v25-clock")

        session = sdk.mint_session_capability(
            agent="probe-agent",
            capability=ACTION,
            tool="probe-tool",
            ttl=60.0,
        )

        assert session.issued_at == frozen[0]
        assert session.expires_at == frozen[0] + 60.0

    def test_a_label_only_revocation_landing_mid_flight_changes_nothing(
        self,
    ) -> None:
        """The same failed attack as
        :class:`TestAegisStateIsALabelAndTheStoreIsEnforcement`, in the race
        window, because a race is where a label that looked harmless would be
        most tempting to rely on. It is still not enforcement here."""

        sdk, controller, parent, child = lineage()
        child_fingerprint, _ = tracked(sdk, controller, child, parent)

        result = during_verification(
            sdk,
            child,
            lambda: controller.mark_revoked(
                child_fingerprint,
                reason="race",
            ),
        )

        assert result.allowed is True
        assert controller.grant(child_fingerprint).state is AegisState.REVOKED

    def test_an_unreadable_aegis_at_commit_denies(self) -> None:
        """The v2.4 precedent the v2.5 gate fixes were built on, exercised
        through the race harness rather than asserted from the source: if the
        store becomes unreadable inside the window, the commit denies."""

        sdk, controller, parent, child = lineage()
        tracked(sdk, controller, child, parent)

        def sabotage() -> None:
            sdk.aegis = Unreadable(sdk.aegis, "suspended_in")

        result = during_verification(sdk, child, sabotage)

        assert result.allowed is False
        assert result.reason == (
            "aegis_state_unavailable_at_commit:RuntimeError"
        )

    def test_an_unreadable_revocation_store_at_commit_denies(self) -> None:
        sdk, controller, parent, child = lineage()
        tracked(sdk, controller, child, parent)

        def sabotage() -> None:
            sdk.revocation = Unreadable(sdk.revocation, "is_revoked")

        result = during_verification(sdk, child, sabotage)

        assert result.allowed is False
        assert result.reason == (
            "revocation_state_unavailable_at_commit:RuntimeError"
        )
