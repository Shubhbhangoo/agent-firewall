"""The thirteen attacks, run against the shipped implementation.

The mission's final section says: "Before completion, attempt to break
it. Answer with tests." What follows is one section per question, in the
mission's order, each attempting the attack through the real public API
and asserting it fails closed.

Two rules govern what may be written here.

**Attack through the front door.** A test that reaches into a private
attribute to construct an impossible state proves nothing about what an
attacker can do. Where a private surface is touched, it is because the
attack genuinely has that reach -- a forged capability registered
directly into ``delegation_lineage`` models an attacker who can call the
control plane's own API, which is question 13.

**Where the system does not make a guarantee, say so instead of faking
one.** Question 4 is the case that matters: posture is *not* an input to
any ``authorize()`` gate. A test asserting that a posture change flips a
verdict would pass only by wiring something the platform does not wire,
and would advertise a guarantee no deployment gets. The honest answer is
narrower and is pinned as such below.
"""

from __future__ import annotations

import dataclasses
import inspect
from types import MappingProxyType

import pytest

from firewall.a2a.auth import A2AError, AgentToAgent
from firewall.authorization import AuthorizationResult, authorize
from firewall.capability import (
    Capability,
    capability_fingerprint,
    sign_capability,
)
from firewall.capability2.constraints import Capability2
from firewall.continuous_auth.engine import (
    PROBE_FAILED,
    UNKNOWN,
    ContinuousAuthorizationEngine,
    RevalidationTrigger,
)
from firewall.continuous_auth.monitor import MonitoringConfig
from firewall.delegation_budget import (
    DelegationBudgetExceeded,
    DelegationBudgetState,
)
from firewall.delegation_lineage import LineageCycleError
from firewall.evidence_graph import EvidenceGraph, KeyEvidenceSigner
from firewall.ident import IdentityRegistry
from firewall.invariants import (
    InvariantStatus,
    canonical_estate,
    control_plane_snapshot,
    invariant,
)
from firewall.platform import Provenance, coerce, combine, is_factual
from firewall.posture.engine import PostureEngine, PostureSignal
from firewall.revocation import AlreadyRevokedError, RevokedCapabilityError
from firewall.risk_context import RiskContext
from firewall.sdk import FirewallSDK
from firewall.simulation import RuleSet, simulate, simulate_change
from firewall.simulation.case import RequestCase
from firewall.tools import (
    UntrustedString,
    mark_untrusted,
    protect_tool,
    unwrap_untrusted,
)
from firewall.transport import TransportError

KEY_ID = "self-attack-key"
CAP = "payments.send"
ACTION = "payments.send"

#: The constraint shape ``authorize()`` actually evaluates: ``amount_max``
#: is compared against the request's ``amount``. Spelled the same way as
#: :mod:`firewall.invariants.runtime`'s probes so the two agree about what
#: a legitimate request looks like.
CEILING = {"amount_max": 100}

#: A request the ceiling admits.
WITHIN = {"amount": 10}


def _rooted(sdk: FirewallSDK, *, amount_max: int = 100, agent: str = "agent-root"):
    """A trusted root capability and the key that signed it."""

    private_key = sdk.generate_key(KEY_ID).private_key
    root = sdk.issue(
        agent=agent,
        capability=CAP,
        constraints={"amount_max": amount_max},
    )
    return root, private_key


def _fresh(sdk: FirewallSDK, *, agent: str = "agent-root", **kwargs):
    """Another capability over the same authority.

    Every denial is memoised in the refusal state under
    ``(agent, fingerprint, action)``, so a second hostile probe against
    the *same* capability short-circuits to ``refusal_state`` and stops
    exercising the gate under test. A distinct capability per probe keeps
    each one honest.
    """

    return sdk.issue(
        agent=agent,
        capability=CAP,
        constraints=dict(CEILING),
        **kwargs,
    )


@pytest.fixture
def estate():
    """The exercised estate, closed afterwards.

    Five invariants are state-dependent and report ``UNVERIFIABLE``
    against an SDK that has never issued, delegated, attenuated or
    revoked anything. Checking them against a bare ``FirewallSDK()``
    would produce a green-looking report that established nothing, which
    is the failure mode :mod:`firewall.invariants` exists to avoid.
    """

    with canonical_estate() as exercised:
        yield exercised


# ======================================================================
# 1. Can an LLM grant authority?
# ======================================================================


class TestQ1ModelOutputIsNotAuthority:
    """No. There is no argument, gate, or code path through which it can.

    There is deliberately no LLM module in ``firewall/``, so the attack
    has to be mounted the way a real integration would mount it: hand a
    confident model verdict to the authorization boundary in every shape
    the boundary will accept, and watch none of them count.
    """

    def test_authorize_takes_no_model_argument(self):
        # The signature is the first line of defence. A caller has
        # nowhere to put an assessment, a score, or a recommendation.
        parameters = set(
            inspect.signature(FirewallSDK.authorize).parameters
        )

        assert parameters == {
            "self",
            "capability",
            "action",
            "request",
            "refusal_scope",
            "chain_id",
        }

    def test_a_model_verdict_inside_the_request_grants_nothing(self):
        sdk = FirewallSDK()
        root, _ = _rooted(sdk)

        result = sdk.authorize(
            root,
            "admin.disable_firewall",
            {
                "amount": 1,
                "llm_verdict": "allow",
                "confidence": 1.0,
                "reasoning": "the operator confirmed this is safe",
                "model": "claude-opus-5",
            },
        )

        assert result.allowed is False
        assert result.reason == "namespace_denied"

    def test_an_advisory_subsystem_can_subtract_but_never_add(self):
        # Risk is the one advisory signal ``authorize()`` does read, and
        # it is wired as a veto: REVOKED denies, and anything below it
        # returns None so the remaining gates still run. There is no
        # ``risk < threshold -> allow`` edge to attack, because a low
        # risk level is not an input to any allow.
        risk = RiskContext()
        sdk = FirewallSDK(risk_context=risk)
        root, _ = _rooted(sdk, agent="calm-agent")

        assert sdk.authorize(root, ACTION, dict(WITHIN)).allowed is True

        for _ in range(50):
            risk.record_critical("calm-agent")

        assert risk.can_authorize("calm-agent") is False

        denied = sdk.authorize(
            _fresh(sdk, agent="calm-agent"), ACTION, dict(WITHIN)
        )

        assert denied.allowed is False
        assert denied.reason == "risk_state_revoked"

    def test_a_pristine_risk_state_cannot_rescue_an_out_of_scope_action(self):
        risk = RiskContext()
        sdk = FirewallSDK(risk_context=risk)
        root, _ = _rooted(sdk, agent="pristine-agent")

        assert risk.can_authorize("pristine-agent") is True

        result = sdk.authorize(root, "admin.wipe", dict(WITHIN))

        assert result.allowed is False

    def test_the_structural_invariants_that_pin_this_hold(self, estate):
        # MODEL_NON_AUTHORITY reads the source of every gate and requires
        # a literal ``False`` in each denial it constructs -- a variable
        # there could smuggle an allow through. AUTHORIZATION_UNIQUENESS
        # censuses which functions may return an allow at all.
        for name in ("MODEL_NON_AUTHORITY", "AUTHORIZATION_UNIQUENESS"):
            result = invariant(name).check(estate.sdk)

            assert result.status is InvariantStatus.HOLDS, result.reason


# ======================================================================
# 2. Can delegation widen authority?
# ======================================================================


class TestQ2DelegationCannotWiden:
    """No, and the two refusals are independent.

    ``delegate()`` refuses to *mint* a widening child, and ``authorize()``
    refuses to *honour* one that was minted behind its back. The second
    matters more: an attacker with a signing key does not have to go
    through ``delegate()``.
    """

    def test_delegate_refuses_to_mint_a_wider_child(self):
        sdk = FirewallSDK()
        root, private_key = _rooted(sdk, amount_max=100)

        with pytest.raises(
            ValueError, match="delegation cannot broaden constraints"
        ):
            sdk.delegate(
                root,
                private_key,
                delegatee="agent-child",
                constraints={"amount_max": 500},
            )

    def test_delegate_permits_only_attenuation(self):
        sdk = FirewallSDK()
        root, private_key = _rooted(sdk, amount_max=100)

        child = sdk.delegate(
            root,
            private_key,
            delegatee="agent-child",
            constraints={"amount_max": 50},
        ).child

        assert child.constraints["amount_max"] == 50
        assert sdk.authorize(child, ACTION, {"amount": 10}).allowed is True
        assert sdk.authorize(child, ACTION, {"amount": 80}).allowed is False

    def test_a_forged_wider_child_is_denied_at_the_boundary(self):
        # The attack that skips ``delegate()`` entirely: sign a child with
        # a wider ceiling, point its signed ``parent_fingerprint`` at the
        # real root, and register the lineage edge directly. Every
        # signature verifies. The structural gate is what stops it.
        sdk = FirewallSDK()
        root, private_key = _rooted(sdk, amount_max=100)

        forged = sign_capability(
            private_key,
            "agent-child",
            CAP,
            constraints={"amount_max": 10_000},
            parent_fingerprint=capability_fingerprint(root),
        )

        sdk.delegation_lineage.register(
            child_fingerprint=capability_fingerprint(forged),
            parent_fingerprint=capability_fingerprint(root),
        )

        result = sdk.authorize(forged, ACTION, {"amount": 5_000})

        assert result.allowed is False
        assert "delegation_widening" in result.reason

    def test_the_forged_child_cannot_even_spend_the_parents_allowance(self):
        # Not "denied only above the parent's ceiling" -- denied outright.
        # The chain is structurally invalid, so nothing flows through it.
        sdk = FirewallSDK()
        root, private_key = _rooted(sdk, amount_max=100)

        forged = sign_capability(
            private_key,
            "agent-child",
            CAP,
            constraints={"amount_max": 10_000},
            parent_fingerprint=capability_fingerprint(root),
        )
        sdk.delegation_lineage.register(
            child_fingerprint=capability_fingerprint(forged),
            parent_fingerprint=capability_fingerprint(root),
        )

        assert sdk.authorize(forged, ACTION, {"amount": 10}).allowed is False

    def test_delegation_monotonicity_holds_over_the_exercised_estate(
        self, estate
    ):
        result = invariant("DELEGATION_MONOTONICITY").check(estate.sdk)

        assert result.status is InvariantStatus.HOLDS, result.reason


# ======================================================================
# 3. Can revocation restore authority?
# ======================================================================


class TestQ3RevocationIsOneWay:
    """No. There is no inverse operation and no path that behaves like one.

    The interesting attacks are the ones that look like a restore without
    calling one: revoking twice, deriving a fresh child from a dead
    parent, or re-issuing over the same authority.
    """

    def test_there_is_no_inverse_operation(self):
        sdk = FirewallSDK()

        for forbidden in (
            "unrevoke",
            "restore",
            "reinstate",
            "clear",
            "undo",
        ):
            assert not hasattr(sdk.revocation, forbidden)
            assert not hasattr(sdk, forbidden)

    def test_revoking_twice_raises_and_leaves_it_revoked(self):
        sdk = FirewallSDK()
        root, _ = _rooted(sdk)

        sdk.revoke(root, reason="self-attack")

        with pytest.raises(AlreadyRevokedError):
            sdk.revoke(root, reason="second attempt")

        assert sdk.is_revoked(root) is True
        assert sdk.authorize(root, ACTION, dict(WITHIN)).allowed is False

    def test_the_revocation_record_cannot_be_edited_out(self):
        # ``records()`` hands out a tuple, not the live store, so a caller
        # who wants a capability un-revoked cannot get there by pruning
        # the list it was told about.
        sdk = FirewallSDK()
        root, _ = _rooted(sdk)
        sdk.revoke(root, reason="self-attack")

        records = sdk.revocation.records()

        assert isinstance(records, tuple)
        with pytest.raises(AttributeError):
            records.clear()

        assert sdk.is_revoked(root) is True
        assert sdk.revocation.size() == 1

    def test_a_child_derived_after_the_parent_died_is_born_dead(self):
        # The attack: the parent is revoked, so mint a *new* child from it
        # and use that instead. Lineage revocation is transitive, so the
        # child inherits the parent's death rather than escaping it.
        sdk = FirewallSDK()
        root, private_key = _rooted(sdk)

        sdk.revoke(root, reason="self-attack")

        child = sdk.delegate(
            root,
            private_key,
            delegatee="agent-child",
            constraints={"amount_max": 50},
        ).child

        assert sdk.is_revoked(child) is False
        assert sdk.is_effectively_revoked(child) is True
        assert sdk.authorize(child, ACTION, {"amount": 10}).allowed is False

    def test_a_grandchild_cannot_outlive_a_revoked_middle_link(self, estate):
        # The exercised estate revokes the middle of a three-link chain
        # and keeps the grandchild. Both must be dead. The count is
        # asserted too: a loop that matched nothing would pass silently.
        assert estate.revoked_agents

        dead = [
            capability
            for capability in estate.sdk.known_capabilities().values()
            if capability.agent_id in estate.revoked_agents
        ]

        assert len(dead) == len(estate.revoked_agents)
        for capability in dead:
            assert estate.sdk.is_effectively_revoked(capability) is True

    def test_re_issuing_is_a_new_grant_not_a_restoration(self):
        # Re-issuing is legitimate -- a trusted issuer may grant fresh
        # authority. What must not happen is the *revoked* capability
        # coming back to life alongside it.
        sdk = FirewallSDK()
        root, _ = _rooted(sdk)
        sdk.revoke(root, reason="self-attack")

        replacement = _fresh(sdk, agent="agent-root")

        assert sdk.authorize(replacement, ACTION, dict(WITHIN)).allowed is True
        assert sdk.is_revoked(root) is True
        assert sdk.authorize(root, ACTION, dict(WITHIN)).allowed is False

    def test_revocation_monotonicity_holds_over_the_exercised_estate(
        self, estate
    ):
        result = invariant("REVOCATION_MONOTONICITY").check(estate.sdk)

        assert result.status is InvariantStatus.HOLDS, result.reason


# ======================================================================
# 4. Can stale authorization survive a posture change?
# ======================================================================
#
# The honest answer is narrower than the question invites, and the
# narrowing is the point.
#
# Posture is *not* an input to any ``authorize()`` gate. ``grep posture
# firewall/sdk.py`` finds the continuous-auth constructor wiring and
# ``_annotate_delegation_posture``, and nothing in the gate chain.
# So "the posture changed, therefore the verdict flips" is not a
# guarantee this platform makes, and a test asserting it would advertise
# one that no deployment gets.
#
# What is guaranteed, and is tested below:
#
#   * a posture change is detected as material drift and named in the
#     revalidation reason, so it cannot pass unnoticed;
#   * it is an immediate trigger, so throttling cannot swallow it;
#   * the re-evaluation goes through ``FirewallSDK.authorize()`` -- there
#     is no second engine that could answer differently; and
#   * when the containment response to that posture *does* change state
#     ``authorize()`` reads, the live authority dies on the next
#     revalidation.
#
# The gap between the third and fourth points is where an operator has
# work to do, and naming it is more useful than hiding it.


def _monitored(**wiring) -> FirewallSDK:
    """An SDK with continuous authorization wired and the sweep off.

    Periodic revalidation is disabled so the tests drive revalidation
    explicitly; a background sweep would race the assertions.
    """
    return FirewallSDK(
        continuous_auth_config=MonitoringConfig(
            enable_periodic_revalidation=False
        ),
        **wiring,
    )


def _a2a(sdk_provider=None) -> AgentToAgent:
    """A three-agent mesh, optionally wired to an authorization pipeline.

    ``sdk_provider`` is the seam through which the mesh consults the real
    pipeline: ``(actor, target, action, request) -> (allowed, reason)``.
    Passing a stub here is not a bypass of the boundary -- it is how a
    test observes *whether the mesh asks*, which is the property under
    attack in questions 9 and 11.
    """

    identities = IdentityRegistry()
    for agent in ("agent-a", "agent-b", "agent-c"):
        identities.create(agent)

    return AgentToAgent(identities, sdk_provider=sdk_provider)


class TestQ4PostureChangeUnderALiveDecision:
    def test_a_posture_change_is_detected_and_named(self):
        posture = PostureEngine()
        sdk = _monitored(continuous_auth_posture_engine=posture)
        root, _ = _rooted(sdk)

        assert sdk.authorize_continuous(root, ACTION, dict(WITHIN)).allowed

        posture.ingest(
            "agent-root",
            PostureSignal(
                name="host_compromise",
                severity=9,
                description="the agent's host was compromised",
            ),
        )

        outcome = sdk.revalidate(
            root,
            ACTION,
            dict(WITHIN),
            trigger=RevalidationTrigger.POSTURE_CHANGED,
        )

        assert posture.state("agent-root").posture == "compromised"
        assert outcome.state_changed is True
        assert "posture: 'unknown' -> 'compromised'" in outcome.reason

        sdk.close()

    def test_posture_alone_does_not_flip_the_verdict_and_says_so(self):
        # The non-guarantee, pinned. If a future change makes posture an
        # ``authorize()`` gate, this test fails -- which is the right
        # outcome: the documented non-guarantee would have become a
        # guarantee and both this test and the docs must be updated
        # together.
        posture = PostureEngine()
        sdk = _monitored(continuous_auth_posture_engine=posture)
        root, _ = _rooted(sdk)

        sdk.authorize_continuous(root, ACTION, dict(WITHIN))
        posture.ingest(
            "agent-root",
            PostureSignal(name="breach", severity=9, description="breached"),
        )

        outcome = sdk.revalidate(
            root,
            ACTION,
            dict(WITHIN),
            trigger=RevalidationTrigger.POSTURE_CHANGED,
        )

        assert outcome.revalidated_allowed is True
        assert outcome.authority_revoked is False

        sdk.close()

    def test_a_posture_change_is_never_throttled_away(self):
        assert (
            RevalidationTrigger.POSTURE_CHANGED
            in MonitoringConfig().immediate_triggers
        )

    def test_the_reevaluation_runs_the_canonical_path(self):
        # Not a paraphrase of authorize() -- authorize() itself. The
        # counter proves the call happened; the engine has no verdict of
        # its own to fall back on.
        posture = PostureEngine()
        sdk = _monitored(continuous_auth_posture_engine=posture)
        root, _ = _rooted(sdk)

        sdk.authorize_continuous(root, ACTION, dict(WITHIN))

        calls: list[str] = []
        canonical = sdk.authorize

        def counting(*args, **kwargs):
            calls.append(kwargs.get("action") or args[1])
            return canonical(*args, **kwargs)

        sdk.authorize = counting  # type: ignore[method-assign]
        posture.ingest(
            "agent-root",
            PostureSignal(name="breach", severity=9, description="breached"),
        )

        sdk.revalidate(
            root,
            ACTION,
            dict(WITHIN),
            trigger=RevalidationTrigger.POSTURE_CHANGED,
        )

        assert calls == [ACTION]

        sdk.authorize = canonical  # type: ignore[method-assign]
        sdk.close()

    def test_containment_that_touches_authorize_state_kills_the_authority(
        self,
    ):
        # The posture change is the signal; revocation is the response.
        # Once the response lands in state ``authorize()`` reads, the
        # live decision is withdrawn on the next revalidation.
        sdk = _monitored()
        root, _ = _rooted(sdk)

        assert sdk.authorize_continuous(root, ACTION, dict(WITHIN)).allowed

        sdk.revoke(root, reason="containment after posture change")

        outcome = sdk.revalidate(
            root,
            ACTION,
            dict(WITHIN),
            trigger=RevalidationTrigger.CAPABILITY_REVOKED,
        )

        assert outcome.original_allowed is True
        assert outcome.revalidated_allowed is False
        assert outcome.authority_revoked is True
        assert "capability_revoked: False -> True" in outcome.reason
        assert outcome.details["revalidated_reason"] == "capability_revoked"

        sdk.close()


# ======================================================================
# 5. Can malformed state create permission?
# ======================================================================


class TestQ5MalformedStateCreatesNothing:
    """It could, once. This section is where the suite found a live bug.

    Numeric ceilings are enforced by negation -- the request is admitted
    unless ``actual > expected`` -- and NaN compares ``False`` against
    every bound. So ``{"amount": float("nan")}`` satisfied every
    ``_max`` ceiling and every ``_min`` floor simultaneously, and
    ``json.loads`` accepts the bare token ``NaN`` by default, which put
    the value one untrusted request body away.
    :func:`firewall.authorization._check_constraints` now refuses a
    non-finite request value outright, and
    :meth:`test_a_non_finite_amount_satisfies_no_ceiling` is the
    regression.
    """

    def test_a_non_finite_amount_satisfies_no_ceiling(self):
        sdk = FirewallSDK()
        _rooted(sdk)

        for value in (
            float("nan"),
            float("inf"),
            float("-inf"),
        ):
            result = sdk.authorize(
                _fresh(sdk), ACTION, {"amount": value}
            )

            assert result.allowed is False, value
            assert result.reason == "constraint_denied"

    def test_a_non_finite_amount_satisfies_no_floor(self):
        # ``inf`` is the floor's version of the bug and ``-inf`` the
        # ceiling's: a floor denies when ``actual < expected``, so
        # ``inf < 10`` is False and infinity passed every floor, while
        # ``-inf < 10`` is True and was always denied. Both directions are
        # listed so the asymmetry is visible rather than looking like an
        # arbitrary choice of probe values.
        sdk = FirewallSDK()
        sdk.generate_key(KEY_ID)

        for value in (
            float("nan"),
            float("inf"),
            float("-inf"),
        ):
            floored = sdk.issue(
                agent="agent-root",
                capability=CAP,
                constraints={"amount_min": 10},
            )

            assert (
                sdk.authorize(floored, ACTION, {"amount": value}).allowed
                is False
            ), value

    def test_the_floor_still_admits_a_real_amount(self):
        sdk = FirewallSDK()
        sdk.generate_key(KEY_ID)
        floored = sdk.issue(
            agent="agent-root",
            capability=CAP,
            constraints={"amount_min": 10},
        )

        assert sdk.authorize(floored, ACTION, {"amount": 10}).allowed is True

    def test_the_ceiling_still_admits_a_real_amount(self):
        # The negative control for the fix: a repair that denied
        # everything would satisfy every test above and break the system.
        sdk = FirewallSDK()
        root, _ = _rooted(sdk)

        assert sdk.authorize(root, ACTION, {"amount": 100}).allowed is True

    def test_no_malformed_input_raises_instead_of_deciding(self):
        # A raise is its own fail-open: a caller wrapping ``authorize``
        # in ``except Exception`` and continuing has been handed an
        # unauthorized request with no verdict attached.
        sdk = FirewallSDK()
        _rooted(sdk)

        probes = (
            ("a capability of None", None, ACTION, dict(WITHIN)),
            ("a capability of str", "capability", ACTION, dict(WITHIN)),
            ("an action of None", _fresh(sdk), None, dict(WITHIN)),
            ("an empty action", _fresh(sdk), "", dict(WITHIN)),
            ("a whitespace action", _fresh(sdk), "   ", dict(WITHIN)),
            ("a request of None", _fresh(sdk), ACTION, None),
            ("a request of list", _fresh(sdk), ACTION, ["amount", 10]),
            (
                "a wrong-typed request value",
                _fresh(sdk),
                ACTION,
                {"amount": "lots"},
            ),
        )

        for label, capability, action, request in probes:
            result = sdk.authorize(capability, action, request)

            assert result.allowed is False, label
            assert result.reason, label

    def test_the_two_pre_gate_guards_name_themselves(self):
        sdk = FirewallSDK()
        root, _ = _rooted(sdk)

        assert (
            sdk.authorize(None, ACTION, dict(WITHIN)).reason
            == "invalid_capability"
        )
        assert sdk.authorize(root, "", dict(WITHIN)).reason == "invalid_action"

    def test_editing_a_signed_field_invalidates_the_capability(self):
        # The signature covers the constraints, so raising the ceiling in
        # the in-memory copy makes the capability unverifiable rather
        # than more powerful.
        sdk = FirewallSDK()
        root, _ = _rooted(sdk)

        widened = dataclasses.replace(
            root, constraints={"amount_max": 10_000}
        )

        result = sdk.authorize(widened, ACTION, {"amount": 5_000})

        assert result.allowed is False
        assert result.reason == "invalid_signature"

    def test_a_zeroed_signature_is_not_a_missing_check(self):
        sdk = FirewallSDK()
        root, _ = _rooted(sdk)

        blanked = dataclasses.replace(root, signature="00" * 64)

        assert (
            sdk.authorize(blanked, ACTION, dict(WITHIN)).reason
            == "invalid_signature"
        )

    def test_fail_closed_holds(self):
        # The shipped invariant runs its own eight probes against a
        # scratch SDK, with a positive control first.
        result = invariant("FAIL_CLOSED").check()

        assert result.status is InvariantStatus.HOLDS, result.reason


# ======================================================================
# 6. Can a policy change silently widen authority?
# ======================================================================


class TestQ6PolicyWideningIsNotSilent:
    """It can widen. It cannot do so *silently*, which is the claim.

    Three independent mechanisms have to fail for a widening to pass
    unnoticed: the invariant that walks recorded transformations, the
    policy fingerprint that a live decision is revalidated against, and
    the simulator that shows the blast radius before the change is
    enforced.
    """

    #: A transformation that adds an action the old policy did not allow.
    WIDENING = (
        (
            Capability2(
                capability=CAP, constraints={"action": ["send"]}
            ),
            Capability2(
                capability=CAP,
                constraints={"action": ["send", "refund"]},
            ),
        ),
    )

    def test_a_widening_transformation_is_named_as_violated(self):
        result = invariant("POLICY_NON_WIDENING").check(
            policy_history=list(self.WIDENING)
        )

        assert result.status is InvariantStatus.VIOLATED
        assert result.findings
        assert "widens namespace" in result.findings[0]

    def test_a_narrowing_transformation_holds(self, estate):
        result = invariant("POLICY_NON_WIDENING").check(
            estate.sdk, policy_history=list(estate.policy_history)
        )

        assert result.status is InvariantStatus.HOLDS, result.reason

    def test_no_recorded_history_is_unverifiable_not_clean(self):
        # The failure mode that would make the other two tests worthless:
        # an invariant that reports HOLDS when it was handed nothing to
        # check. Absent verification is not a security claim.
        result = invariant("POLICY_NON_WIDENING").check()

        assert result.status is InvariantStatus.UNVERIFIABLE
        assert bool(result) is False

    def test_a_policy_change_under_a_live_decision_is_detected(self):
        # The default fingerprint covers the trusted-issuer set and the
        # delegation-depth ceiling. Adding an issuer moves it, and the
        # live decision's revalidation names the move.
        sdk = _monitored()
        root, _ = _rooted(sdk)

        assert sdk.authorize_continuous(root, ACTION, dict(WITHIN)).allowed

        sdk.trust_issuer("attacker-controlled-issuer")

        outcome = sdk.revalidate(
            root,
            ACTION,
            dict(WITHIN),
            trigger=RevalidationTrigger.POLICY_CHANGED,
        )

        assert outcome.state_changed is True
        assert outcome.reason.startswith("policy_version: ")

        sdk.close()

    def test_the_default_fingerprint_does_not_claim_policy_coverage(self):
        # Two knobs is not policy coverage, and the docstring says so. A
        # deployment with real policy must inject its own provider; a test
        # that treated this fingerprint as complete would manufacture the
        # false guarantee the docs refuse to make.
        sdk = _monitored()
        sdk.generate_key(KEY_ID)

        assert sdk._authorization_policy_version().startswith("sdk-policy:")

        doc = FirewallSDK._authorization_policy_version.__doc__

        assert "would be a false guarantee" in doc
        assert "constraint semantics" in doc

        # A change to constraint semantics is outside the two knobs, so
        # the fingerprint does not move for it. Pinned, because the gap is
        # the thing a deployment has to cover for itself.
        before = sdk._authorization_policy_version()
        sdk.issue(
            agent="agent-root",
            capability=CAP,
            constraints={"amount_max": 1_000_000},
        )

        assert sdk._authorization_policy_version() == before

        sdk.close()

    def test_the_effect_of_a_change_is_visible_before_it_is_enforced(self):
        # The simulator answers "what would this widening do" without the
        # widening ever being enforced.
        sdk = FirewallSDK()
        _rooted(sdk)

        case = RequestCase(
            case_id="depth-probe",
            action=ACTION,
            capability=CAP,
            root_agent="agent-root",
            root_constraints=dict(CEILING),
            request=dict(WITHIN),
        )

        before = control_plane_snapshot(sdk)
        report = simulate_change(sdk, [case], max_delegation_depth=1)
        after = control_plane_snapshot(sdk)

        assert before == after
        assert report.caveats
        assert RuleSet.from_sdk(sdk).max_delegation_depth is None


# ======================================================================
# 7. Can inferred evidence become observed?
# ======================================================================


class TestQ7InferenceCannotBecomeObservation:
    """No. The one shared vocabulary has no promoting operation.

    ``combine`` is the only way to merge provenance from several sources,
    and it returns the *weakest* input. There is no ``promote``, no
    ``assume_observed``, and no threshold above which enough inference
    counts as a fact.
    """

    def test_combining_an_observation_with_an_inference_yields_inference(
        self,
    ):
        assert (
            combine(Provenance.OBSERVED, Provenance.INFERRED)
            is Provenance.INFERRED
        )
        assert (
            combine(Provenance.INFERRED, Provenance.OBSERVED)
            is Provenance.INFERRED
        )

    def test_no_quantity_of_inference_adds_up_to_an_observation(self):
        # The obvious attack on a weakest-wins rule: overwhelm it. Twenty
        # observations and one inference is still an inference.
        inputs = [Provenance.OBSERVED] * 20 + [Provenance.INFERRED]

        assert combine(*inputs) is Provenance.INFERRED

    def test_simulated_is_absorbing_in_both_orders(self):
        assert (
            combine(Provenance.SIMULATED, Provenance.OBSERVED)
            is Provenance.SIMULATED
        )
        assert (
            combine(Provenance.OBSERVED, Provenance.SIMULATED)
            is Provenance.SIMULATED
        )
        assert (
            combine(
                Provenance.OBSERVED,
                Provenance.DERIVED,
                Provenance.INFERRED,
                Provenance.SIMULATED,
            )
            is Provenance.SIMULATED
        )

    def test_combining_nothing_is_unknown_not_observed(self):
        # The empty case is where a "start optimistic and narrow down"
        # implementation would put OBSERVED, and it is exactly backwards.
        assert combine() is Provenance.UNKNOWN

    def test_inferred_and_simulated_are_not_factual(self):
        assert is_factual(Provenance.OBSERVED) is True
        assert is_factual(Provenance.DERIVED) is True
        assert is_factual(Provenance.INFERRED) is False
        assert is_factual(Provenance.SIMULATED) is False
        assert is_factual(Provenance.UNKNOWN) is False

    def test_a_confident_looking_label_degrades_to_unknown(self):
        # A subsystem that writes its own label cannot invent a stronger
        # one: anything outside the vocabulary reads as UNKNOWN, not as
        # the nearest-looking member.
        for label in (
            "observed_for_real",
            "OBSERVED!",
            "high_confidence",
            "verified",
            None,
            "",
            42,
        ):
            assert coerce(label) is Provenance.UNKNOWN, label

    def test_there_is_no_promoting_operation_in_the_vocabulary(self):
        import firewall.platform as platform

        for forbidden in (
            "promote",
            "upgrade",
            "assume_observed",
            "strengthen",
            "escalate",
        ):
            assert not hasattr(platform, forbidden)

    def test_provenance_integrity_holds(self):
        result = invariant("PROVENANCE_INTEGRITY").check()

        assert result.status is InvariantStatus.HOLDS, result.reason


# ======================================================================
# 8. Can simulation modify production?
# ======================================================================


class TestQ8SimulationTouchesNothing:
    """No. It replays against re-signed copies on a throwaway rule set.

    The strongest version of the attack is a simulation whose cases are
    designed to have side effects -- revocations, issuances, an untrusted
    issuer -- and then checking whether any of it landed. The control
    plane fingerprint before and after is the assertion.
    """

    def _cases(self, count: int = 3) -> list[RequestCase]:
        return [
            RequestCase(
                case_id=f"case-{index}",
                action=ACTION,
                capability=CAP,
                root_agent="agent-root",
                root_constraints=dict(CEILING),
                request=dict(WITHIN),
            )
            for index in range(count)
        ]

    def test_the_control_plane_fingerprint_is_unchanged(self):
        sdk = FirewallSDK()
        root, _ = _rooted(sdk)
        sdk.revoke(root, reason="pre-existing state")

        before = control_plane_snapshot(sdk)

        rules = RuleSet.from_sdk(sdk)
        simulate(
            self._cases(),
            rules,
            rules.replace(trusted_issuers=[]),
            limit=len(self._cases()),
        )

        after = control_plane_snapshot(sdk)

        assert before == after
        assert before["revocations"]
        assert before["capabilities"]

    def test_simulating_a_revocation_revokes_nothing(self):
        sdk = FirewallSDK()
        root, _ = _rooted(sdk)

        report = simulate_change(sdk, self._cases(), trusted_issuers=[])

        assert report.to_dict()["outcomes"][0]["change"] == "newly_denied"
        assert sdk.is_revoked(root) is False
        assert sdk.authorize(root, ACTION, dict(WITHIN)).allowed is True

    def test_a_simulated_result_is_labelled_and_never_a_verdict(self):
        # A simulation outcome is not an ``AuthorizationResult``. Nothing
        # downstream can mistake one for a decision, because it has no
        # ``allowed`` attribute to read.
        sdk = FirewallSDK()
        _rooted(sdk)

        rules = RuleSet.from_sdk(sdk)
        report = simulate(self._cases(1), rules, rules, limit=1)
        outcome = report.outcomes[0]

        assert not hasattr(outcome, "allowed")
        assert any("simulation key" in caveat for caveat in report.caveats)

    def test_the_replay_is_bounded_and_reports_what_it_dropped(self):
        # Termination is guaranteed by truncation, and truncation is
        # reported. A bounded run that silently discarded the remainder
        # would let a caller read a partial replay as a complete one.
        sdk = FirewallSDK()
        _rooted(sdk)

        rules = RuleSet.from_sdk(sdk)
        report = simulate(self._cases(3), rules, rules, limit=1)

        assert report.skipped == 2
        assert any("were not replayed" in caveat for caveat in report.caveats)
        assert report.safe is False

    def test_a_simulation_cannot_reach_the_live_authorization_path(self):
        # ``simulate`` takes rule sets, not an SDK. ``simulate_change``
        # takes one only to read the live rules for the ``before`` side.
        parameters = set(inspect.signature(simulate).parameters)

        assert parameters == {"cases", "before", "after", "limit"}

    def test_simulation_isolation_holds(self, estate):
        result = invariant("SIMULATION_ISOLATION").check(estate.sdk)

        assert result.status is InvariantStatus.HOLDS, result.reason


# ======================================================================
# 9. Can a compromised agent bypass FirewallSDK.authorize()?
# ======================================================================


def _counting_handler(log: list) -> "callable":
    """A tool body that records every invocation.

    The interesting assertion for a denied call is not the exception --
    it is that this list stays empty. An exception raised *after* the
    side effect would satisfy a test that only checked for
    ``PermissionError``.
    """

    def handler(**kwargs):
        log.append(kwargs)
        return "money moved"

    return handler


class TestQ9CompromisedAgentCannotBypassTheBoundary:
    """No. The agent never holds the decision.

    A compromised agent controls its own arguments and its own
    reasoning, and can call anything reachable from its process. What it
    cannot do is reach the effect without passing the gate, because the
    gate is on the near side of the handler rather than inside it:
    :class:`firewall.tools.ProtectedTool` authorizes and only then calls
    the body, so a denial means the body was never entered.

    Its second route is to ask a *different* agent to act. When an
    :class:`~firewall.a2a.auth.AgentToAgent` mesh is wired with an
    ``sdk_provider``, a relationship grant is necessary and not
    sufficient -- the real pipeline runs too, and if the pipeline cannot
    be reached the request is denied rather than admitted.
    """

    def test_a_denied_call_never_enters_the_handler(self):
        sdk = FirewallSDK()
        sdk.generate_key(KEY_ID)
        log: list = []

        tool = protect_tool(
            sdk=sdk,
            capability=_fresh(sdk, agent="agent-a"),
            handler=_counting_handler(log),
            action=ACTION,
            request_builder=lambda **kwargs: dict(kwargs),
        )

        with pytest.raises(PermissionError) as caught:
            tool(amount=10_000)

        assert "constraint_denied" in str(caught.value)
        assert log == []

    def test_an_allowed_call_runs_and_returns_untrusted_output(self):
        sdk = FirewallSDK()
        sdk.generate_key(KEY_ID)
        log: list = []

        tool = protect_tool(
            sdk=sdk,
            capability=_fresh(sdk, agent="agent-a"),
            handler=_counting_handler(log),
            action=ACTION,
            request_builder=lambda **kwargs: dict(kwargs),
        )

        result = tool(**WITHIN)

        # The negative control: the gate is not simply refusing
        # everything. And what comes back is tagged untrusted, which is
        # question 10's subject.
        assert log == [WITHIN]
        assert isinstance(result, UntrustedString)
        assert result.tool == ACTION

    def test_the_default_request_shape_cannot_satisfy_a_ceiling(self):
        # Without a request_builder the wrapper forwards ``args`` and
        # ``kwargs`` verbatim rather than guessing which argument the
        # ``amount_max`` ceiling refers to. The constraint then has no
        # matching request key, and a constraint that cannot be
        # evaluated is not waived.
        sdk = FirewallSDK()
        sdk.generate_key(KEY_ID)
        log: list = []

        tool = protect_tool(
            sdk=sdk,
            capability=_fresh(sdk, agent="agent-a"),
            handler=_counting_handler(log),
            action=ACTION,
        )

        with pytest.raises(PermissionError):
            tool(amount=10)

        assert log == []

    def test_a_tool_bound_capability_cannot_be_pointed_elsewhere(self):
        sdk = FirewallSDK()
        sdk.generate_key(KEY_ID)
        bound = sdk.issue(
            agent="agent-a",
            capability=CAP,
            constraints=dict(CEILING),
            tool=ACTION,
        )

        with pytest.raises(ValueError, match="tool binding"):
            protect_tool(
                sdk=sdk,
                capability=bound,
                handler=lambda **kwargs: None,
                action="payments.refund",
            )

    def test_a_relationship_grant_alone_does_not_authorize(self):
        # The mesh's own bookkeeping says yes; the pipeline says no; the
        # answer is no. This is the shape that matters -- the mesh is
        # subtractive, so no amount of relationship state can add.
        consulted: list = []

        def deny(actor, target, action, request):
            consulted.append((actor, target, action, dict(request)))
            return False, "pipeline_denied_for_test"

        mesh = _a2a(deny)
        mesh.establish(
            initiator="agent-a",
            responder="agent-b",
            permissions={"allowed_actions": [ACTION]},
        )

        decision = mesh.authorize(
            actor="agent-a",
            target="agent-b",
            action=ACTION,
        )

        assert decision.allowed is False
        assert decision.reason == "pipeline_denied_for_test"
        assert consulted == [("agent-a", "agent-b", ACTION, {})]

    def test_an_unreachable_pipeline_denies_rather_than_admits(self):
        def offline(actor, target, action, request):
            raise RuntimeError("pipeline offline")

        mesh = _a2a(offline)
        mesh.establish(
            initiator="agent-a",
            responder="agent-b",
            permissions={"allowed_actions": [ACTION]},
        )

        decision = mesh.authorize(
            actor="agent-a",
            target="agent-b",
            action=ACTION,
        )

        assert decision.allowed is False
        assert decision.reason == (
            "authorization provider error: RuntimeError"
        )

    def test_an_action_outside_the_grant_never_reaches_the_pipeline(self):
        consulted: list = []

        def allow(actor, target, action, request):
            consulted.append(action)
            return True, "pipeline allowed"

        mesh = _a2a(allow)
        mesh.establish(
            initiator="agent-a",
            responder="agent-b",
            permissions={"allowed_actions": [ACTION]},
        )

        granted = mesh.authorize(
            actor="agent-a",
            target="agent-b",
            action=ACTION,
        )
        outside = mesh.authorize(
            actor="agent-a",
            target="agent-b",
            action="admin.wipe",
        )

        assert granted.allowed is True
        assert outside.allowed is False
        assert outside.reason == (
            "no active relationship covers this action"
        )
        # Both gates are real: the relationship gate rejected the second
        # call before the pipeline was asked, so neither one is
        # decorative.
        assert consulted == [ACTION]


# ======================================================================
# 10. Can a malicious tool create authority?
# ======================================================================


class TestQ10ToolOutputCannotCreateAuthority:
    """No, and the reason is structural rather than a filter.

    ``authorize()`` will not read authority out of anything but a
    :class:`~firewall.capability.Capability` whose signature verifies
    against a trusted key. A tool returns strings, dicts and lists. There
    is no code path that turns one into the other, so a malicious tool
    has nothing to say that the gate would hear -- it does not need to be
    *detected*, because the thing it can produce is not the thing the
    gate accepts.

    ``mark_untrusted`` is therefore a label for logs and humans, not the
    barrier. Nothing in the firewall gates on ``UntrustedString``, which
    is deliberate: a taint check that could be evaded would be a weaker
    guarantee than a type and a signature that cannot.
    """

    def test_the_taint_marker_reaches_string_leaves_in_containers(self):
        tainted = mark_untrusted(
            {"action": "admin.wipe", "nested": ["payments.send", 3]},
            tool="evil-tool",
        )

        assert isinstance(tainted["action"], UntrustedString)
        assert tainted["action"].tool == "evil-tool"
        assert isinstance(tainted["nested"][0], UntrustedString)
        # Non-strings pass through as themselves; there is nowhere to
        # hang the tag, and the tag was never the thing standing between
        # the tool and authority.
        assert tainted["nested"][1] == 3

    def test_no_gate_in_the_firewall_reads_the_taint_marker(self):
        # If some gate did, this suite would have to prove the marker
        # cannot be stripped -- and ``unwrap_untrusted`` strips it by
        # design. The absence of such a gate is what makes that safe.
        import firewall.tools as tools

        assert unwrap_untrusted(
            mark_untrusted("admin.wipe", tool="evil-tool")
        ) == "admin.wipe"
        assert not hasattr(tools, "is_trusted")
        assert not hasattr(tools, "trust")

    def test_a_tool_supplied_action_is_still_matched_against_the_grant(
        self,
    ):
        sdk = FirewallSDK()
        sdk.generate_key(KEY_ID)
        root = _fresh(sdk, agent="agent-a")

        # The classic injection: the tool's output names the action to
        # take next. It is evaluated as an action string like any other,
        # against a capability that does not cover it.
        action = mark_untrusted("admin.wipe", tool="evil-tool")

        result = sdk.authorize(root, action, dict(WITHIN))

        assert result.allowed is False
        assert result.reason == "namespace_denied"

    def test_tool_output_offered_as_a_capability_is_not_one(self):
        sdk = FirewallSDK()
        sdk.generate_key(KEY_ID)

        for forgery in (
            mark_untrusted("payments.send", tool="evil-tool"),
            {"capability": CAP, "agent_id": "agent-a"},
            ["payments.send"],
            None,
            42,
        ):
            result = sdk.authorize(forgery, ACTION, dict(WITHIN))

            assert result.allowed is False, forgery
            assert result.reason == "invalid_capability", forgery

    def test_a_numeric_looking_string_does_not_satisfy_a_ceiling(self):
        # A tool that reports ``"10"`` where a number is expected is not
        # under the ceiling: the constraint branch requires a real number
        # and refuses to coerce, because coercion is where a tool's
        # choice of representation would start deciding outcomes.
        sdk = FirewallSDK()
        sdk.generate_key(KEY_ID)

        result = sdk.authorize(
            _fresh(sdk, agent="agent-a"),
            ACTION,
            {"amount": mark_untrusted("10", tool="evil-tool")},
        )

        assert result.allowed is False
        assert result.reason == "constraint_denied"

    def test_editing_a_serialized_capability_breaks_its_signature(self):
        sdk = FirewallSDK()
        sdk.generate_key(KEY_ID)
        payload = sdk.serialize(_fresh(sdk, agent="agent-a"))

        widened = dict(payload)
        widened["capability"] = "admin.*"
        raised = dict(payload)
        raised["constraints"] = {"amount_max": 10**9}

        # ``deserialize`` is a decoder, not a gate: it will hand back a
        # Capability object carrying whatever the payload said. The
        # signature check happens at the boundary that matters.
        assert sdk.deserialize(widened).capability == "admin.*"

        assert sdk.authorize(
            sdk.deserialize(widened), "admin.wipe"
        ).reason == "invalid_signature"
        assert sdk.authorize(
            sdk.deserialize(raised), ACTION, {"amount": 10**6}
        ).reason == "invalid_signature"

    def test_a_capability_the_tool_signed_itself_is_not_trusted(self):
        # The strongest version of the attack: the tool holds a real
        # Ed25519 key and issues itself a valid capability. The signature
        # is genuine; the key is not one this SDK trusts, and that is the
        # whole difference.
        sdk = FirewallSDK()
        sdk.generate_key(KEY_ID)
        rogue_sdk = FirewallSDK()
        rogue_sdk.generate_key("rogue-key")
        rogue = rogue_sdk.issue(
            agent="agent-a",
            capability="admin.*",
            constraints={},
        )

        assert rogue_sdk.authorize(rogue, "admin.wipe").allowed is True

        imported = sdk.deserialize(rogue_sdk.serialize(rogue))
        result = sdk.authorize(imported, "admin.wipe")

        assert result.allowed is False
        assert result.reason == "invalid_signature"

    def test_the_transport_boundary_refuses_before_decoding_completes(
        self,
    ):
        sdk = FirewallSDK()
        sdk.generate_key(KEY_ID)
        root = _fresh(sdk, agent="agent-a")
        token = sdk.encode(root)
        rogue_sdk = FirewallSDK()
        rogue_sdk.generate_key("rogue-key")

        # An untrusted issuer's token.
        with pytest.raises(
            ValueError, match="decoded capability failed verification"
        ):
            sdk.decode_verified(
                rogue_sdk.encode(
                    rogue_sdk.issue(
                        agent="agent-a",
                        capability="admin.*",
                        constraints={},
                    )
                )
            )

        # A token with one character changed.
        edited = token[:-6] + ("a" if token[-6] != "a" else "b") + token[-5:]
        with pytest.raises(TransportError, match="invalid transport payload"):
            sdk.decode_verified(edited)

        # A token larger than the decoder will consider at all, which is
        # what keeps a hostile tool from choosing how much work the
        # control plane does.
        with pytest.raises(TransportError, match="exceeds maximum size"):
            sdk.decode_verified("x" * 40_000)

        # And a genuine token for a capability that has since died.
        sdk.revoke(root)
        with pytest.raises(
            RevokedCapabilityError, match="capability is revoked"
        ):
            sdk.decode_verified(token)


# ======================================================================
# 11. Can two agents collude to bypass policy?
# ======================================================================


class TestQ11CollusionAddsNothing:
    """Not by combining grants -- and cumulative spend is opt-in.

    Two agents can share anything they hold, so the question is whether
    sharing *composes*. It does not: every path that moves authority
    between agents intersects rather than unions. A grant sharing no key
    with the parent raises; a grant whose actions are disjoint from the
    parent's yields a relationship that covers nothing; a wider set
    silently narrows to the parent's; and round-tripping a grant back to
    its origin does not restore what was dropped on the way out.

    The one place collusion has real leverage is arithmetic. An
    ``amount_max`` ceiling is per request, so two siblings each holding a
    100 ceiling can make two 100 requests. That is not a bypass of the
    gate -- both requests were within the authority granted -- but an
    operator who meant "100 in total" needs
    :meth:`FirewallSDK.authorize_with_delegation_budget`, which meters
    the whole lineage against the root. The non-guarantee and the
    mechanism are both pinned below, because the difference between them
    is a deployment decision and should not be discoverable only by
    losing money.
    """

    def test_a_grant_sharing_no_key_with_the_parent_raises(self):
        mesh = _a2a(lambda *args: (True, "pipeline allowed"))
        parent = mesh.establish(
            initiator="agent-a",
            responder="agent-b",
            permissions={"allowed_actions": [ACTION]},
        )

        for grant in ({}, {"max_amount": 100}, {"other_key": ["x"]}):
            with pytest.raises(A2AError) as caught:
                mesh.delegate(
                    parent,
                    responder="agent-c",
                    permissions=grant,
                )

            assert "outside the parent's authority" in str(caught.value)

    def test_a_disjoint_action_list_confers_nothing(self):
        # The other shape of the same attack: the key *is* shared, so the
        # intersection is a present-but-empty list rather than an empty
        # map, and delegation succeeds. It grants nothing -- ``_covers``
        # asks ``action in allowed``, so an empty list matches no action,
        # and a missing key matches none either.
        mesh = _a2a(lambda *args: (True, "pipeline allowed"))
        parent = mesh.establish(
            initiator="agent-a",
            responder="agent-b",
            permissions={"allowed_actions": [ACTION]},
        )

        child = mesh.delegate(
            parent,
            responder="agent-c",
            permissions={"allowed_actions": ["admin.wipe"]},
        )

        assert child.permissions["allowed_actions"] == []

        for action in ("admin.wipe", ACTION):
            decision = mesh.authorize(
                actor="agent-b",
                target="agent-c",
                action=action,
            )

            assert decision.allowed is False, action
            assert decision.reason == (
                "no active relationship covers this action"
            )

        # And it cannot be used as a fresh root: delegating onward from an
        # empty grant intersects against nothing.
        onward = mesh.delegate(
            child,
            responder="agent-a",
            permissions={"allowed_actions": [ACTION]},
        )

        assert onward.permissions["allowed_actions"] == []

    def test_a_wider_request_is_narrowed_to_the_parents_set(self):
        mesh = _a2a(lambda *args: (True, "pipeline allowed"))
        parent = mesh.establish(
            initiator="agent-a",
            responder="agent-b",
            permissions={
                "allowed_actions": [ACTION, "payments.refund"]
            },
        )

        child = mesh.delegate(
            parent,
            responder="agent-c",
            permissions={"allowed_actions": [ACTION]},
        )

        # Now the child asks for everything back, for a third party.
        grandchild = mesh.delegate(
            child,
            responder="agent-a",
            permissions={
                "allowed_actions": [ACTION, "payments.refund"]
            },
        )

        assert grandchild.permissions["allowed_actions"] == [ACTION]
        assert mesh.effective_permissions(
            grandchild.relationship_id
        )["allowed_actions"] == [ACTION]

    def test_a_round_trip_does_not_restore_a_dropped_permission(self):
        mesh = _a2a(lambda *args: (True, "pipeline allowed"))
        parent = mesh.establish(
            initiator="agent-a",
            responder="agent-b",
            permissions={
                "allowed_actions": [ACTION, "payments.refund"]
            },
        )
        child = mesh.delegate(
            parent,
            responder="agent-c",
            permissions={"allowed_actions": [ACTION]},
        )
        mesh.delegate(
            child,
            responder="agent-a",
            permissions={"allowed_actions": [ACTION]},
        )

        recovered = mesh.authorize(
            actor="agent-c",
            target="agent-a",
            action="payments.refund",
        )

        assert recovered.allowed is False
        assert recovered.reason == (
            "no active relationship covers this action"
        )

    def test_nothing_unions_two_capabilities(self):
        # The absence is the guarantee. A ``merge`` or ``union`` helper is
        # exactly the primitive collusion would need, so its absence is
        # asserted rather than assumed.
        for name in (
            "merge",
            "union",
            "combine_capabilities",
            "aggregate",
            "widen",
            "broaden",
        ):
            assert not hasattr(FirewallSDK, name), name

    def test_two_siblings_can_each_spend_the_ceiling(self):
        # The non-guarantee, stated as a passing test so it cannot be
        # mistaken for an oversight. Both requests are inside the
        # authority that was granted; the ceiling never claimed to be a
        # budget.
        sdk = FirewallSDK()
        private_key = sdk.generate_key(KEY_ID).private_key
        root = sdk.issue(
            agent="agent-root",
            capability=CAP,
            constraints=dict(CEILING),
        )
        left = sdk.delegate(
            root,
            private_key,
            delegatee="agent-a",
            constraints=dict(CEILING),
        ).child
        right = sdk.delegate(
            root,
            private_key,
            delegatee="agent-b",
            constraints=dict(CEILING),
        ).child

        assert sdk.authorize(left, ACTION, {"amount": 100}).allowed is True
        assert sdk.authorize(right, ACTION, {"amount": 100}).allowed is True

    def test_a_lineage_budget_is_what_stops_the_second_sibling(self):
        sdk = FirewallSDK()
        private_key = sdk.generate_key(KEY_ID).private_key
        root = sdk.issue(
            agent="agent-root",
            capability=CAP,
            constraints=dict(CEILING),
        )
        sdk.configure_delegation_budget(root, max_total_amount=100)
        left = sdk.delegate(
            root,
            private_key,
            delegatee="agent-a",
            constraints=dict(CEILING),
        ).child
        right = sdk.delegate(
            root,
            private_key,
            delegatee="agent-b",
            constraints=dict(CEILING),
        ).child

        first = sdk.authorize_with_delegation_budget(
            left, ACTION, {"amount": 60}
        )
        second = sdk.authorize_with_delegation_budget(
            right, ACTION, {"amount": 60}
        )

        assert first.allowed is True
        assert second.allowed is False
        assert second.reason == "delegation_budget_exceeded"
        # The refused request consumed nothing, so a denial is not a way
        # to drain a sibling's remaining allowance.
        assert sdk.delegation_budget_total(root) == 60.0
        assert sdk.delegation_budget_limit(root) == 100.0

    def test_an_unconfigured_budget_denies_instead_of_waiving_itself(self):
        # Opting in is fail-closed: asking for metered authorization
        # where no meter exists is a denial, not an unmetered allow.
        sdk = FirewallSDK()
        private_key = sdk.generate_key(KEY_ID).private_key
        root = sdk.issue(
            agent="agent-root",
            capability=CAP,
            constraints=dict(CEILING),
        )
        child = sdk.delegate(
            root,
            private_key,
            delegatee="agent-a",
            constraints=dict(CEILING),
        ).child

        result = sdk.authorize_with_delegation_budget(
            child, ACTION, dict(WITHIN)
        )

        assert result.allowed is False
        assert result.reason == "delegation_budget_not_configured"


# ======================================================================
# 12. Can failed security dependencies cause fail-open behavior?
# ======================================================================
#
# This is the second section where the suite found a live bug, and the
# more interesting of the two because the fail-open was *intermittent*.
#
# The continuous-authorization engine snapshots the security state a
# decision was taken under, and refuses to confirm a decision on
# revalidation when a configured dependency could not be read. That
# subtraction was applied on all three ``revalidate()`` paths -- and not
# to the first decision. So the sequence for an agent whose posture store
# had just gone dark was:
#
#     authorize_continuous(...)  -> allowed,  'authorized'
#     revalidate(...)            -> denied,   'security_dependency_unavailable'
#     revalidate(...)            -> denied,   'security_dependency_unavailable'
#
# One permissive answer, at the front, in the window an attacker who can
# silence a probe would aim at. ``FirewallSDK.authorize_continuous`` now
# applies the same subtraction to the decision it hands back, so the
# first answer agrees with every later one.
#
# Two properties keep the correction honest, and both are pinned below:
# it can only ever narrow (a denial keeps its own more specific reason),
# and it does not touch ``authorize()``. The canonical boundary still
# answers from capability, signature, revocation and constraints alone;
# the continuous layer subtracts on top of that answer for callers who
# asked for monitoring. Making posture readability an ``authorize()``
# input would make every deployment that never wired a posture engine
# fail differently, and would put a monitoring subsystem inside the
# decision.


class BlindPosture:
    """A posture engine that is wired but cannot answer.

    The distinction this class exists to create is the whole of question
    12: an *absent* subsystem is a deployment that never asked for the
    signal, while a *present but unreadable* one is a signal the
    deployment relies on and is not getting. Only the second is a
    degradation. ``_probe_posture`` reads ``state(agent).posture``, so
    that is what raises.
    """

    def state(self, agent_id):
        raise RuntimeError("posture store unreachable")


class BlindTrustGraph:
    """A trust graph that is wired but cannot answer."""

    def find_dangers(self):
        raise RuntimeError("trust graph unreachable")


class TestQ12FailedDependenciesWithholdRatherThanWaive:
    def test_the_first_decision_is_withheld_and_names_the_dependency(self):
        sdk = _monitored(continuous_auth_posture_engine=BlindPosture())
        root, _ = _rooted(sdk)

        result = sdk.authorize_continuous(root, ACTION, dict(WITHIN))

        assert result.allowed is False
        assert result.reason == "security_dependency_unavailable: posture"

        sdk.close()

    def test_the_first_decision_agrees_with_its_revalidations(self):
        # The regression for the bug itself. Before the fix the first
        # element of this list was ``True`` and the rest ``False``.
        sdk = _monitored(continuous_auth_posture_engine=BlindPosture())
        root, _ = _rooted(sdk)

        verdicts = [sdk.authorize_continuous(root, ACTION, dict(WITHIN)).allowed]
        for _ in range(2):
            verdicts.append(
                sdk.revalidate(
                    root,
                    ACTION,
                    dict(WITHIN),
                    trigger=RevalidationTrigger.POSTURE_CHANGED,
                ).revalidated_allowed
            )

        assert verdicts == [False, False, False]

        sdk.close()

    def test_a_wired_and_readable_dependency_changes_nothing(self):
        # The negative control. Without it every assertion above would
        # also pass on an SDK that denied unconditionally.
        sdk = _monitored(continuous_auth_posture_engine=PostureEngine())
        root, _ = _rooted(sdk)

        result = sdk.authorize_continuous(root, ACTION, dict(WITHIN))

        assert result.allowed is True
        assert result.reason == "authorized"

        sdk.close()

    def test_an_unwired_subsystem_is_unknown_and_not_a_degradation(self):
        # ``unknown`` is recorded in the snapshot -- the state is not
        # being claimed -- but it is not treated as a failure, because
        # nothing failed. A deployment that never wired posture is not a
        # deployment whose posture store is down.
        sdk = _monitored()
        root, _ = _rooted(sdk)

        result = sdk.authorize_continuous(root, ACTION, dict(WITHIN))
        snapshot = sdk.continuous_auth_engine.snapshot_for(
            root, ACTION, dict(WITHIN)
        )

        assert result.allowed is True
        assert snapshot.posture == UNKNOWN
        assert snapshot.degraded is False
        assert snapshot.degraded_dependencies == ()

        sdk.close()

    def test_the_two_states_are_different_values(self):
        assert UNKNOWN != PROBE_FAILED
        assert UNKNOWN == "unknown"
        assert PROBE_FAILED == "probe_failed"

    def test_every_blind_dependency_is_named_not_just_the_first(self):
        # A partial report would let an operator restore one subsystem,
        # see the same denial, and conclude the mechanism is broken.
        sdk = _monitored(
            continuous_auth_posture_engine=BlindPosture(),
            continuous_auth_trust_graph=BlindTrustGraph(),
        )
        root, _ = _rooted(sdk)

        result = sdk.authorize_continuous(root, ACTION, dict(WITHIN))
        snapshot = sdk.continuous_auth_engine.snapshot_for(
            root, ACTION, dict(WITHIN)
        )

        assert snapshot.degraded_dependencies == ("posture", "trust")
        assert result.reason == (
            "security_dependency_unavailable: posture, trust"
        )

        sdk.close()

    def test_a_blind_policy_version_provider_withholds_too(self):
        # Not being able to read *which* policy is in force is the same
        # class of blindness as not being able to read posture: the
        # decision cannot be described, so it is not reported as live.
        def unreadable():
            raise RuntimeError("policy store unreachable")

        sdk = _monitored(continuous_auth_policy_version_provider=unreadable)
        root, _ = _rooted(sdk)

        result = sdk.authorize_continuous(root, ACTION, dict(WITHIN))

        assert result.allowed is False
        assert result.reason == "security_dependency_unavailable: policy"

        sdk.close()

    def test_a_blind_environment_provider_withholds_too(self):
        def unreadable():
            raise RuntimeError("environment unreadable")

        sdk = _monitored(continuous_auth_environment_provider=unreadable)
        root, _ = _rooted(sdk)

        result = sdk.authorize_continuous(root, ACTION, dict(WITHIN))

        assert result.allowed is False
        assert result.reason == "security_dependency_unavailable: environment"

        sdk.close()

    def test_the_withheld_decision_is_not_registered_for_monitoring(self):
        # Registering it would put an entry in the bounded monitor table
        # whose revalidation can withdraw nothing, evicting decisions
        # that do carry live authority.
        sdk = _monitored(continuous_auth_posture_engine=BlindPosture())
        root, _ = _rooted(sdk)

        sdk.authorize_continuous(root, ACTION, dict(WITHIN))

        assert sdk.continuous_auth_monitor.get_monitored_decisions() == {}

        sdk.close()

    def test_the_trace_names_what_was_refused(self):
        sdk = _monitored(continuous_auth_posture_engine=BlindPosture())
        root, _ = _rooted(sdk)

        result = sdk.authorize_continuous(root, ACTION, dict(WITHIN))
        trace = result.trace or {}

        # Still identifies the capability, agent and action, so the audit
        # record says what was refused and not merely that something was.
        assert trace["agent"] == "agent-root"
        assert trace["action"] == ACTION
        assert trace["capability_id"] == sdk.fingerprint(root)
        # And the trace's reason agrees with the verdict it belongs to.
        assert trace["reason"] == result.reason
        assert result.decision.allowed is False

        sdk.close()

    def test_a_real_denial_keeps_its_own_reason(self):
        # The subtraction only ever removes an allow. Overwriting
        # ``constraint_denied`` with the degradation notice would lose
        # the more specific fact without changing the outcome -- and
        # would tell an operator to go fix a posture store when the
        # request was simply over its ceiling.
        sdk = _monitored(continuous_auth_posture_engine=BlindPosture())
        root, _ = _rooted(sdk)

        result = sdk.authorize_continuous(root, ACTION, {"amount": 5000})

        assert result.allowed is False
        assert result.reason == "constraint_denied"

        sdk.close()

    def test_the_subtraction_cannot_turn_a_denial_into_an_allow(self):
        # Asserted against the function directly, in both states, because
        # this is the one direction the mechanism must never move.
        sdk = _monitored(continuous_auth_posture_engine=BlindPosture())
        root, _ = _rooted(sdk)
        sdk.authorize_continuous(root, ACTION, dict(WITHIN))
        degraded = sdk.continuous_auth_engine.snapshot_for(
            root, ACTION, dict(WITHIN)
        )

        healthy_sdk = _monitored(continuous_auth_posture_engine=PostureEngine())
        healthy_root, _ = _rooted(healthy_sdk)
        healthy_sdk.authorize_continuous(healthy_root, ACTION, dict(WITHIN))
        healthy = healthy_sdk.continuous_auth_engine.snapshot_for(
            healthy_root, ACTION, dict(WITHIN)
        )

        denied = AuthorizationResult(False, "constraint_denied")
        verdict = ContinuousAuthorizationEngine.effective_verdict

        assert verdict(denied, degraded)[0] is False
        assert verdict(denied, healthy) == (False, None)

        sdk.close()
        healthy_sdk.close()

    def test_the_canonical_verdict_is_not_rewritten_by_degradation(self):
        # The subtraction belongs to the monitored path. ``authorize()``
        # answers from capability, signature, revocation and constraints,
        # and a monitoring subsystem's health is not one of its inputs.
        sdk = _monitored(continuous_auth_posture_engine=BlindPosture())
        root, _ = _rooted(sdk)

        assert sdk.authorize_continuous(root, ACTION, dict(WITHIN)).allowed is (
            False
        )
        canonical = sdk.authorize(root, ACTION, dict(WITHIN))

        assert canonical.allowed is True
        assert canonical.reason == "authorized"

        sdk.close()

    def test_the_engine_reports_state_and_does_not_mint_verdicts(self):
        # Structural, and the reason the fix landed in the SDK: the
        # engine returns a ``(bool, reason)`` pair because
        # ``AUTHORIZATION_UNIQUENESS`` reserves verdict construction to
        # the authorization boundary. An earlier version of this fix put
        # the construction in the engine and the invariant caught it.
        sdk = _monitored(continuous_auth_posture_engine=BlindPosture())
        root, _ = _rooted(sdk)
        sdk.authorize_continuous(root, ACTION, dict(WITHIN))
        snapshot = sdk.continuous_auth_engine.snapshot_for(
            root, ACTION, dict(WITHIN)
        )

        pair = ContinuousAuthorizationEngine.effective_verdict(
            AuthorizationResult(True, "authorized"), snapshot
        )

        assert isinstance(pair, tuple)
        assert not isinstance(pair, AuthorizationResult)
        allowed, reason = pair
        assert allowed is False
        assert reason == "security_dependency_unavailable: posture"

        assert invariant("AUTHORIZATION_UNIQUENESS").check(sdk).status is (
            InvariantStatus.HOLDS
        )

        sdk.close()

    def test_revalidation_is_unavailable_rather_than_vacuous(self):
        # An SDK without continuous authorization must not answer
        # "revalidated, still fine". A ``None`` or a permissive
        # ``RevalidationResult`` would read as a successful check to any
        # caller that only looks at ``revalidated_allowed``.
        sdk = FirewallSDK()
        root, _ = _rooted(sdk)

        assert sdk.continuous_auth_engine is None

        with pytest.raises(RuntimeError, match="not configured"):
            sdk.revalidate(root, ACTION, dict(WITHIN))

    def test_an_unmonitored_sdk_still_decides_from_the_canonical_path(self):
        # And the other half of that: ``authorize_continuous`` on an SDK
        # without monitoring is not an error and not an allow-by-default
        # -- it is ``authorize()``, with no revalidation attached.
        sdk = FirewallSDK()
        root, _ = _rooted(sdk)

        assert sdk.authorize_continuous(root, ACTION, dict(WITHIN)).allowed
        assert (
            sdk.authorize_continuous(
                _fresh(sdk), ACTION, {"amount": 5000}
            ).reason
            == "constraint_denied"
        )

    def test_an_unreadable_revocation_store_yields_no_verdict_at_all(self):
        # The canonical boundary's own dependencies fail differently:
        # rather than reporting a degraded allow, the exception
        # propagates and no ``AuthorizationResult`` is produced. A caller
        # cannot mistake a raised exception for permission, so this is
        # fail-closed -- but it is worth pinning that the call does not
        # instead swallow the error and answer from the remaining gates.
        sdk = FirewallSDK()
        root, _ = _rooted(sdk)

        class BlindRevocation:
            def is_revoked(self, fingerprint):
                raise RuntimeError("revocation store unreachable")

        sdk.revocation = BlindRevocation()

        with pytest.raises(RuntimeError, match="revocation store unreachable"):
            sdk.authorize(root, ACTION, dict(WITHIN))

    def test_an_unreadable_lineage_store_yields_no_verdict_at_all(self):
        sdk = FirewallSDK()
        root, _ = _rooted(sdk)

        class BlindLineage:
            def chain(self, fingerprint):
                raise RuntimeError("lineage store unreachable")

        sdk.delegation_lineage = BlindLineage()

        with pytest.raises(RuntimeError, match="lineage store unreachable"):
            sdk.authorize(root, ACTION, dict(WITHIN))

    def test_a_signature_verifier_that_cannot_answer_denies(self):
        # Here the dependency failure *is* expressible as a verdict,
        # because verification is an input to the decision rather than a
        # description of it. Unknown is not trusted.
        sdk = FirewallSDK()
        root, _ = _rooted(sdk)

        class BlindVerifier:
            def verify(self, capability):
                raise RuntimeError("key store unreachable")

        result = authorize(root, ACTION, dict(WITHIN), verifier=BlindVerifier())

        assert result.allowed is False
        assert result.reason == "verification_error"

    def test_a_clock_that_cannot_answer_denies(self):
        sdk = FirewallSDK()
        root, _ = _rooted(sdk)

        def unreadable_clock():
            raise RuntimeError("no clock")

        result = authorize(root, ACTION, dict(WITHIN), clock=unreadable_clock)

        assert result.allowed is False
        assert result.reason == "invalid_clock"

    def test_a_probe_failure_is_not_silently_dropped_from_the_snapshot(self):
        # The snapshot is what a revalidation diffs against. If a blind
        # probe recorded the same value as a healthy one, drift detection
        # would go quiet at exactly the moment it matters.
        sdk = _monitored(continuous_auth_posture_engine=BlindPosture())
        root, _ = _rooted(sdk)
        sdk.authorize_continuous(root, ACTION, dict(WITHIN))

        snapshot = sdk.continuous_auth_engine.snapshot_for(
            root, ACTION, dict(WITHIN)
        )

        assert snapshot.posture == PROBE_FAILED
        assert snapshot.degraded is True
        assert "posture" in snapshot.to_dict()["degraded_dependencies"]

        sdk.close()


# ======================================================================
# 13. Can the control plane itself become an escalation path?
# ======================================================================
#
# The honest answer has two halves, and stating only the first would be
# advertising a guarantee nobody gets.
#
# **Where the answer is no.** The control plane's administrative surfaces
# hand out views rather than the state itself, and the state they do
# expose is bound by signatures they cannot forge. Erasing the delegation
# registry does not unbind a child from its parent, because the parent
# fingerprint is inside what was signed; re-pointing a child at a cleaner
# parent is detected for the same reason. Clearing the revalidation cache
# can only cost a redundant ``authorize()`` call. Removing the risk veto
# returns a decision to the capability's own terms and cannot widen them.
# Reconfiguring a delegation budget adjusts the ceiling and leaves the
# ledger alone -- this section is where the suite found its third bug,
# and that one *was* a live escalation path: ``configure`` rebuilt the
# state object, so re-applying the same limit reset the consumed total to
# zero and restored an exhausted lineage's whole allowance.
#
# **Where the answer is yes, and must be.** Possession of a signing key
# is authority -- that is what a signature means. An attacker who can
# call :meth:`FirewallSDK.trust_issuer` for an issuer whose keys they
# control, or who holds a trusted private key, can mint capabilities.
# There is no cryptographic answer to that and pretending otherwise
# would be the fake guarantee; the boundary of the threat model is the
# key material, and the tests below pin exactly where it sits -- naming
# an issuer as trusted does *not* import its keys, so the two are not
# the same reach.
#
# The sharp edge inside that second half is :meth:`retire_key`. It reads
# like containment and is not: a retired key keeps verifying, because
# rotation retires the outgoing key and invalidating its signatures would
# kill every capability in flight. The lever that does contain a stolen
# key is :meth:`revoke_issuer`. Both are pinned below so the difference
# is discoverable from the test suite and not only from an incident.


class TestQ13TheControlPlaneIsNotAGrantingSurface:
    def test_the_capability_registry_is_handed_out_as_a_view(self):
        sdk = FirewallSDK()
        root, _ = _rooted(sdk)

        known = sdk.known_capabilities()

        assert isinstance(known, MappingProxyType)

        with pytest.raises(TypeError):
            known["forged"] = root  # type: ignore[index]

    def test_the_view_reflects_control_plane_state_rather_than_copying_it(
        self,
    ):
        # A snapshot would go stale, and a stale view of revocation state
        # is the kind of thing a responder reads before deciding not to
        # act. The view must track the registry it projects.
        sdk = FirewallSDK()
        root, _ = _rooted(sdk)
        fingerprint = sdk.fingerprint(root)

        assert fingerprint in sdk.known_capabilities()

        view = sdk.known_capabilities()
        second = _fresh(sdk, agent="agent-second")

        assert sdk.fingerprint(second) in view

    def test_the_view_does_not_report_revocation(self):
        # v2.2 described this view as preventing a subsystem from
        # "pinning a snapshot past a revocation". It does not, because
        # revocation is not recorded here at all -- it lives in the
        # revocation store, which ``authorize()`` consults directly. The
        # registry is a record of what was issued, and a revoked
        # capability stays in it.
        #
        # This is not a hole: nothing is authorized off the view. It is a
        # correction to what the view can be read as saying, and it is
        # pinned so the claim cannot drift back. A subsystem that needs
        # revocation status must ask, not iterate.
        sdk = FirewallSDK()
        root, _ = _rooted(sdk)
        fingerprint = sdk.fingerprint(root)

        sdk.revoke(root, reason="containment")

        assert fingerprint in sdk.known_capabilities()
        assert sdk.is_effectively_revoked(root) is True
        assert (
            sdk.authorize(root, ACTION, dict(WITHIN)).reason
            == "capability_revoked"
        )

    def test_a_capability_cannot_be_edited_in_place(self):
        sdk = FirewallSDK()
        root, _ = _rooted(sdk)

        assert dataclasses.is_dataclass(Capability)
        assert Capability.__dataclass_params__.frozen is True

        with pytest.raises(dataclasses.FrozenInstanceError):
            root.capability = "admin.*"  # type: ignore[misc]

    def test_erasing_the_delegation_registry_does_not_free_a_child(self):
        # The attack: a child is denied because its root was revoked, so
        # erase the lineage that connects them. The parent fingerprint is
        # inside what the child's signature covers, so the child is now a
        # signed delegation with no registered parent -- which is refused,
        # not admitted.
        sdk = FirewallSDK()
        root, private_key = _rooted(sdk)
        child = sdk.delegate(
            root,
            private_key,
            delegatee="agent-a",
            constraints=dict(CEILING),
        ).child

        assert sdk.authorize(child, ACTION, dict(WITHIN)).allowed is True

        sdk.revoke(root, reason="containment")

        assert (
            sdk.authorize(child, ACTION, dict(WITHIN)).reason
            == "capability_revoked"
        )

        sdk.delegation_lineage.clear()
        result = sdk.authorize(child, ACTION, dict(WITHIN))

        assert result.allowed is False
        assert result.reason.startswith("delegation_chain_error")

    def test_a_child_cannot_be_re_pointed_at_an_unrevoked_parent(self):
        # Same attack with a forged link instead of an erased one. The
        # registry is asked to say the child descends from a capability
        # that was never its parent; the signature disagrees and the
        # signature wins.
        sdk = FirewallSDK()
        root, private_key = _rooted(sdk)
        child = sdk.delegate(
            root,
            private_key,
            delegatee="agent-a",
            constraints=dict(CEILING),
        ).child
        clean_root = _fresh(sdk, agent="agent-clean")

        sdk.revoke(root, reason="containment")
        sdk.delegation_lineage.clear()
        sdk.delegation_lineage.register(
            child_fingerprint=sdk.fingerprint(child),
            parent_fingerprint=sdk.fingerprint(clean_root),
        )

        result = sdk.authorize(child, ACTION, dict(WITHIN))

        assert result.allowed is False
        assert "does not match its registered delegation parent" in (
            result.reason
        )

    def test_a_lineage_cycle_is_refused_at_registration(self):
        # Not an escalation but a denial-of-service on the gate chain: a
        # cycle in the lineage would be walked on every authorization.
        # Refusing the write is what keeps the walk bounded.
        sdk = FirewallSDK()
        root, private_key = _rooted(sdk)
        child = sdk.delegate(
            root,
            private_key,
            delegatee="agent-a",
            constraints=dict(CEILING),
        ).child
        child_fingerprint = sdk.fingerprint(child)

        with pytest.raises(LineageCycleError):
            sdk.delegation_lineage.register(
                child_fingerprint=child_fingerprint,
                parent_fingerprint=child_fingerprint,
            )

        with pytest.raises(LineageCycleError):
            sdk.delegation_lineage.register(
                child_fingerprint=sdk.fingerprint(root),
                parent_fingerprint=child_fingerprint,
            )

    def test_clearing_the_revalidation_cache_grants_nothing(self):
        # The cache holds a baseline for drift comparison, so the worst a
        # wipe can do is force a fresh ``authorize()`` -- which is the
        # canonical path, and which still sees the revocation.
        sdk = _monitored()
        root, _ = _rooted(sdk)

        assert sdk.authorize_continuous(root, ACTION, dict(WITHIN)).allowed

        sdk.revoke(root, reason="containment")
        sdk.continuous_auth_engine.clear_cache()

        assert (
            sdk.authorize(root, ACTION, dict(WITHIN)).reason
            == "capability_revoked"
        )

        outcome = sdk.revalidate(
            root,
            ACTION,
            dict(WITHIN),
            trigger=RevalidationTrigger.CAPABILITY_REVOKED,
        )

        assert outcome.revalidated_allowed is False

        sdk.close()

    def test_removing_the_risk_veto_returns_the_decision_to_the_capability(
        self,
    ):
        # ``set_risk_context(None)`` is a real administrative widening --
        # it removes a veto. What it cannot do is widen the capability:
        # the request still has to be inside the namespace and under the
        # ceiling, which is the difference between lifting a veto and
        # granting authority.
        risk = RiskContext()
        sdk = FirewallSDK(risk_context=risk)
        root, _ = _rooted(sdk, agent="agent-risky")

        for _ in range(5):
            risk.record_critical("agent-risky")

        assert (
            sdk.authorize(root, ACTION, dict(WITHIN)).reason
            == "risk_state_revoked"
        )

        sdk.set_risk_context(None)

        assert sdk.authorize(
            _fresh(sdk, agent="agent-risky"), ACTION, dict(WITHIN)
        ).allowed is True
        assert (
            sdk.authorize(
                _fresh(sdk, agent="agent-risky"), "admin.wipe", dict(WITHIN)
            ).reason
            == "namespace_denied"
        )
        assert (
            sdk.authorize(
                _fresh(sdk, agent="agent-risky"), ACTION, {"amount": 5000}
            ).reason
            == "constraint_denied"
        )

    def test_resetting_risk_is_administrative_and_still_grants_nothing(self):
        risk = RiskContext()
        sdk = FirewallSDK(risk_context=risk)
        root, _ = _rooted(sdk, agent="agent-reset")

        for _ in range(5):
            risk.record_critical("agent-reset")
        risk.reset("agent-reset")

        assert risk.can_authorize("agent-reset") is True
        assert (
            sdk.authorize(root, "admin.wipe", dict(WITHIN)).reason
            == "namespace_denied"
        )

    def test_reconfiguring_a_budget_does_not_restore_spent_allowance(self):
        # The third bug this suite found. ``configure`` built a fresh
        # state object, so the consumed total went back to zero -- and
        # the *idempotent* call was the dangerous one: re-applying the
        # same limit on every startup meant the budget never bound.
        sdk = FirewallSDK()
        root, _ = _rooted(sdk)
        sdk.configure_delegation_budget(root, max_total_amount=100)

        assert sdk.authorize_with_delegation_budget(
            root, ACTION, {"amount": 100}
        ).allowed is True
        assert (
            sdk.authorize_with_delegation_budget(
                root, ACTION, {"amount": 1}
            ).reason
            == "delegation_budget_exceeded"
        )

        sdk.configure_delegation_budget(root, max_total_amount=100)

        assert sdk.delegation_budget_total(root) == 100.0
        assert (
            sdk.authorize_with_delegation_budget(
                root, ACTION, {"amount": 1}
            ).reason
            == "delegation_budget_exceeded"
        )

    def test_raising_a_budget_ceiling_grants_only_the_difference(self):
        # Reconfiguration is still useful -- an operator can raise a
        # limit. What they get is headroom above what was spent, not a
        # fresh allowance.
        sdk = FirewallSDK()
        root, _ = _rooted(sdk)
        sdk.configure_delegation_budget(root, max_total_amount=100)
        sdk.authorize_with_delegation_budget(root, ACTION, {"amount": 100})

        sdk.configure_delegation_budget(root, max_total_amount=150)

        assert sdk.delegation_budget_total(root) == 100.0
        assert sdk.delegation_budget_limit(root) == 150.0
        assert sdk.authorize_with_delegation_budget(
            root, ACTION, {"amount": 50}
        ).allowed is True
        assert (
            sdk.authorize_with_delegation_budget(
                root, ACTION, {"amount": 1}
            ).reason
            == "delegation_budget_exceeded"
        )

    def test_lowering_a_ceiling_below_the_spend_takes_effect(self):
        # Narrowing must never be rejected for being awkward. The state
        # is over its new limit and admits nothing further, including
        # zero-amount requests.
        sdk = FirewallSDK()
        root, _ = _rooted(sdk)
        sdk.configure_delegation_budget(root, max_total_amount=100)
        sdk.authorize_with_delegation_budget(root, ACTION, {"amount": 60})

        sdk.configure_delegation_budget(root, max_total_amount=10)

        assert sdk.delegation_budget_total(root) == 60.0
        assert sdk.delegation_budget_limit(root) == 10.0
        assert (
            sdk.authorize_with_delegation_budget(
                root, ACTION, {"amount": 0}
            ).reason
            == "delegation_budget_exceeded"
        )

    def test_a_non_finite_reservation_cannot_poison_the_ledger(self):
        # The same shape as the constraint bug in question 5. The ceiling
        # is enforced by negation, so ``total + nan > max`` is False and
        # a NaN reservation would be admitted -- after which
        # ``total_amount`` is NaN, every later comparison is False too,
        # and the budget admits everything forever. The SDK path already
        # refuses non-finite amounts; this pins the arithmetic itself so
        # the guarantee does not rest on a single caller.
        state = DelegationBudgetState(max_total_amount=100)

        for bad in (float("nan"), float("inf"), float("-inf")):
            with pytest.raises(ValueError, match="finite"):
                state.reserve(bad)

        assert state.total_amount == 0.0
        assert state.reserve(100) is None
        with pytest.raises(DelegationBudgetExceeded):
            state.reserve(1)

    def test_a_non_finite_ceiling_is_refused(self):
        for bad in (float("nan"), float("inf")):
            with pytest.raises(ValueError, match="non-negative"):
                DelegationBudgetState(max_total_amount=bad)

    def test_naming_an_issuer_as_trusted_does_not_import_its_keys(self):
        # The boundary of the threat model, pinned. Trusting an issuer
        # *name* is not trusting a key: a rogue SDK's capability names
        # the same default issuer and is still refused, because the
        # verifier was never given its public key.
        victim = FirewallSDK()
        rogue = FirewallSDK()
        rogue_root, _ = _rooted(rogue)

        assert (
            victim.authorize(rogue_root, ACTION, dict(WITHIN)).reason
            == "invalid_signature"
        )

        victim.trust_issuer(rogue_root.issuer)

        assert (
            victim.authorize(rogue_root, ACTION, dict(WITHIN)).reason
            == "invalid_signature"
        )

    def test_revoking_an_issuer_refuses_everything_signed_under_it(self):
        # The lever that does contain a compromised signer, including
        # capabilities it already handed out.
        sdk = FirewallSDK()
        root, _ = _rooted(sdk)

        assert sdk.authorize(root, ACTION, dict(WITHIN)).allowed is True

        sdk.revoke_issuer(root.issuer)

        assert (
            sdk.authorize(root, ACTION, dict(WITHIN)).reason
            == "untrusted_issuer"
        )

    def test_a_retired_key_still_verifies_and_that_is_not_containment(self):
        # The honest non-guarantee, and the one most likely to be
        # misread. Retirement removes a key from issuance -- ``issue``
        # refuses once no active key remains -- but an attacker holding
        # the private key can still sign a *wider* capability and this
        # SDK will accept it, because verification asks whether the
        # signature is genuine, not whether the key is still in
        # rotation. Rotation is why: retiring the outgoing key must not
        # invalidate the capabilities in flight at that moment.
        sdk = FirewallSDK()
        record = sdk.generate_key(KEY_ID)
        legitimate = sdk.issue(
            agent="agent-root",
            capability=CAP,
            constraints=dict(CEILING),
        )

        sdk.retire_key(KEY_ID)

        assert sdk.keys.is_active(KEY_ID) is False
        with pytest.raises(ValueError, match="no active key"):
            sdk.issue(
                agent="agent-root",
                capability=CAP,
                constraints=dict(CEILING),
            )

        # The stolen key, used directly rather than through the SDK.
        forged = sign_capability(
            record.private_key,
            "agent-root",
            "admin.*",
            constraints={},
            issuer=legitimate.issuer,
            key_id=KEY_ID,
        )

        assert sdk.authorize(forged, "admin.wipe", dict(WITHIN)).allowed is (
            True
        )

        # And the lever that does close it.
        sdk.revoke_issuer(legitimate.issuer)

        assert (
            sdk.authorize(forged, "admin.wipe", dict(WITHIN)).reason
            == "untrusted_issuer"
        )

    def test_rotation_leaves_capabilities_in_flight_valid(self):
        # The requirement that makes the behaviour above necessary rather
        # than merely convenient. If this failed, every rotation would be
        # an outage.
        sdk = FirewallSDK()
        sdk.generate_key(KEY_ID)
        in_flight = sdk.issue(
            agent="agent-root",
            capability=CAP,
            constraints=dict(CEILING),
        )

        sdk.rotate_key("rotated-key")

        assert sdk.active_key().key_id == "rotated-key"
        assert sdk.keys.is_active(KEY_ID) is False
        assert sdk.authorize(in_flight, ACTION, dict(WITHIN)).allowed is True
        assert sdk.authorize(
            sdk.issue(
                agent="agent-root",
                capability=CAP,
                constraints=dict(CEILING),
            ),
            ACTION,
            dict(WITHIN),
        ).allowed is True

    def test_the_control_plane_integrity_invariant_holds(self):
        # The structural half: no module outside ``firewall/sdk.py``
        # reaches the control-plane state at all, so the surfaces
        # attacked above are the whole attack surface.
        sdk = FirewallSDK()

        result = invariant("CONTROL_PLANE_INTEGRITY").check(sdk)

        assert result.status is InvariantStatus.HOLDS, result.reason


# ======================================================================
# The thirteen questions are all answered
# ======================================================================


#: Question number -> the class that answers it. Written out rather than
#: discovered so that deleting a section is a failing test rather than a
#: quietly smaller suite.
ANSWERED = {
    1: "TestQ1ModelOutputIsNotAuthority",
    2: "TestQ2DelegationCannotWiden",
    3: "TestQ3RevocationIsOneWay",
    4: "TestQ4PostureChangeUnderALiveDecision",
    5: "TestQ5MalformedStateCreatesNothing",
    6: "TestQ6PolicyWideningIsNotSilent",
    7: "TestQ7InferenceCannotBecomeObservation",
    8: "TestQ8SimulationTouchesNothing",
    9: "TestQ9CompromisedAgentCannotBypassTheBoundary",
    10: "TestQ10ToolOutputCannotCreateAuthority",
    11: "TestQ11CollusionAddsNothing",
    12: "TestQ12FailedDependenciesWithholdRatherThanWaive",
    13: "TestQ13TheControlPlaneIsNotAGrantingSurface",
}


def test_every_question_has_a_section_with_tests_in_it():
    here = globals()

    assert sorted(ANSWERED) == list(range(1, 14))

    for number, class_name in ANSWERED.items():
        section = here.get(class_name)

        assert section is not None, f"question {number}: {class_name} missing"

        tests = [
            name
            for name, member in inspect.getmembers(section, inspect.isfunction)
            if name.startswith("test_")
        ]

        assert tests, f"question {number}: {class_name} has no tests"
