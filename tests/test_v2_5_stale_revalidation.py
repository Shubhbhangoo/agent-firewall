"""v2.5 -- the stale allow that survived a suspension.

``revalidate()`` exists to answer one question: is a decision that was
allowed still allowed? Its fast path answers from the cached verdict when
``SecurityContextSnapshot.state_hash()`` has not moved, without calling
``authorize()``. That is sound only while the snapshot covers every input
the gate chain reads.

It did not. Aegis enforces through the restriction store, and no snapshot
field moved when a restriction was applied, so::

    sdk.authorize_continuous(cap, "payments.send", {"amount": 10})
    controller.suspend(fingerprint, key="incident-1", reason="...")

    sdk.authorize(cap, "payments.send", {"amount": 10})
    # -> False  aegis_suspended:incident-1
    sdk.revalidate(cap, "payments.send", {"amount": 10})
    # -> revalidated_allowed=True  state_changed=False
    #    authority_revoked=False   reason="no_material_state_change"

Both a suspension and a narrowing reproduced it. The boundary was never
wrong -- ``authorize()`` denied throughout, and nothing in the enforcement
path consumes ``revalidated_allowed`` as permission -- but the surface
whose entire purpose is to notice withdrawn authority reported an allow,
and ``authority_revoked``, documented as "the case that matters
operationally", reported ``False``. A periodic monitor sweep would have
found nothing to act on while Aegis had suspended the grant.

The fix is one snapshot field, ``aegis_restrictions``: a digest of the
restrictions binding the capability's chain. It creates no authorization
path. A moved digest does exactly one thing -- route revalidation into the
slow path that already calls ``FirewallSDK.authorize()`` -- so the verdict
still comes from the canonical boundary, and the change can only cause
*more* canonical authorizations, never fewer.

``state_hash()`` has a second consumer, and it had the same blindness.
``firewall.aegis.response.classify`` contributes ``state_hash_changed`` when
the hash moves across an event, and ``KEEP`` -- documented as the response
that "requires positive evidence" -- is returned only when it did not move.
Before the fix, a suspension applied between the two snapshots classified
as ``KEEP`` under ``ENVIRONMENT_CHANGED``. ``TestTheClassifierSawTheSameHole``
pins that it now escalates. The direction is safe by construction: the
classifier takes the maximum over contributions, so a new contribution can
only raise the response.

What these tests do NOT establish:

* That the digest and ``_gate_aegis`` read identical chains under every
  lineage shape. They are separately derived -- the gate walks
  ``ctx.delegation_authority``, the probe walks ``delegation_lineage`` --
  and this file pins their agreement only at depths one through three
  (``TestRestrictionsBindTheWholeChain``). A lineage the gate can see and
  the registry cannot would deny without moving the digest.
* That no *other* gate input is missing from the snapshot. Five were
  measured (Aegis suspend, Aegis narrow, capability revocation, issuer
  revocation, key retirement); the first two were holes, and
  ``TestTheOtherGateInputsWereMeasured`` pins what the other three do.
  ``_gate_refusal`` state is still unrepresented.
* That the digest is cheap. It reads the store once per snapshot and
  hashes; no benchmark here bounds that.
"""

from __future__ import annotations

from typing import Any, Optional

import pytest

from firewall.aegis import AegisController
from firewall.aegis.response import AdaptiveResponse, classify, severity
from firewall.continuous_auth.engine import (
    PROBE_FAILED,
    UNKNOWN,
    RevalidationTrigger,
    SecurityContextSnapshot,
    _HASH_EXCLUDED_FIELDS,
)
from firewall.continuous_auth.monitor import MonitoringConfig
from firewall.invariants import (
    InvariantStatus,
    check_all,
    control_plane_snapshot,
    invariant,
)
from firewall.invariants.runtime import check_revalidation_consistency
from firewall.sdk import FirewallSDK

ACTION = "payments.send"
REQUEST = {"amount": 10}


def build(*, aegis: bool = True) -> tuple[FirewallSDK, Optional[AegisController]]:
    """An SDK with continuous authorization wired, Aegis optional.

    Periodic revalidation is off so that every revalidation in this file is
    one the test asked for: a background sweep would repopulate the cache
    and the fast path under test would stop being the path taken.
    """

    controller = AegisController() if aegis else None
    sdk = FirewallSDK(
        aegis=controller,
        continuous_auth_config=MonitoringConfig(
            enable_periodic_revalidation=False,
        ),
    )
    sdk.generate_key("v25-stale")

    return sdk, controller


def issue(sdk: FirewallSDK, controller: Optional[AegisController]) -> Any:
    capability = sdk.issue(
        agent="probe-agent",
        capability="payments.*",
        constraints={"amount_max": 100},
    )

    if controller is not None:
        controller.register(
            sdk.fingerprint(capability),
            agent_id=capability.agent_id,
            capability=capability.capability,
        )

    return capability


def cached(sdk: FirewallSDK, capability: Any) -> None:
    """Take the decision the fast path will later answer from."""

    first = sdk.authorize_continuous(capability, ACTION, REQUEST)

    assert first.allowed, first.reason


def digest(sdk: FirewallSDK, capability: Any) -> str:
    snapshot = sdk.continuous_auth_engine._capture_snapshot(
        capability,
        ACTION,
        REQUEST,
    )

    return snapshot.aegis_restrictions


def digest_refusal(sdk: FirewallSDK, capability: Any) -> str:
    """The refusal digest for the same decision ``digest`` reports on."""

    snapshot = sdk.continuous_auth_engine._capture_snapshot(
        capability,
        ACTION,
        REQUEST,
    )

    return snapshot.refusal_state


class TestTheStaleAllow:
    """The finding, one test per restriction kind that produced it."""

    def test_a_suspension_after_a_cached_allow_is_noticed(self) -> None:
        sdk, controller = build()
        capability = issue(sdk, controller)
        cached(sdk, capability)

        controller.suspend(
            sdk.fingerprint(capability),
            key="incident-1",
            reason="probe",
        )

        direct = sdk.authorize(capability, ACTION, REQUEST)
        result = sdk.revalidate(capability, ACTION, REQUEST)

        assert direct.allowed is False
        assert direct.reason == "aegis_suspended:incident-1"
        assert result.revalidated_allowed is False
        assert result.state_changed is True
        assert result.authority_revoked is True
        assert "aegis_restrictions" in result.reason

        sdk.close()

    def test_a_narrowing_that_excludes_the_request_is_noticed(self) -> None:
        """The second instance of the same hole.

        A narrowing denies through a different branch of
        ``restriction_reason`` than a suspension, and the digest is not
        derived from either -- it is derived from the store's contents, so
        both move it.
        """

        sdk, controller = build()
        capability = issue(sdk, controller)
        cached(sdk, capability)

        controller.narrow(
            sdk.fingerprint(capability),
            key="tighten",
            constraints={"amount_max": 1},
            reason="probe",
        )

        direct = sdk.authorize(capability, ACTION, REQUEST)
        result = sdk.revalidate(capability, ACTION, REQUEST)

        assert direct.allowed is False
        assert direct.reason == "aegis_constraint_denied:tighten"
        assert result.revalidated_allowed is False
        assert result.authority_revoked is True

        sdk.close()

    def test_the_two_surfaces_agree(self) -> None:
        """The property, stated as a property rather than as two verdicts.

        Phase 2(A)'s target is "inconsistent decisions between initial
        authorization and revalidation". Asserting the conjunction pins
        that, where asserting each verdict separately would still pass if
        both moved together in the wrong direction.
        """

        sdk, controller = build()
        capability = issue(sdk, controller)
        cached(sdk, capability)
        fingerprint = sdk.fingerprint(capability)

        for change in (
            lambda: controller.suspend(fingerprint, key="s", reason="p"),
            lambda: controller.lift(fingerprint, "s", reason="p"),
            lambda: controller.narrow(
                fingerprint,
                key="n",
                constraints={"amount_max": 1},
                reason="p",
            ),
            lambda: controller.lift(fingerprint, "n", reason="p"),
        ):
            change()

            direct = sdk.authorize(capability, ACTION, REQUEST)
            result = sdk.revalidate(capability, ACTION, REQUEST)

            assert not (
                result.revalidated_allowed and not direct.allowed
            ), f"revalidate allowed what authorize denied: {result.reason}"

        sdk.close()


class TestTheSnapshotFieldIsActuallyHashed:
    """A field the hash ignores would fix nothing."""

    def test_the_field_is_material(self) -> None:
        assert "aegis_restrictions" not in _HASH_EXCLUDED_FIELDS
        assert "aegis_restrictions" in SecurityContextSnapshot(
            timestamp=0.0,
            capability_fingerprint="a" * 64,
            agent_id="probe",
            action=ACTION,
            request_hash="b" * 32,
            identity_status="active",
            identity_version=1,
            capability_revoked=False,
            capability_expired=False,
            delegation_chain_valid=True,
            delegation_depth=0,
            max_delegation_depth=3,
            posture="normal",
            trust_findings=0,
            risk_level="low",
            policy_version="v1",
            environment="{}",
            provenance_state="observed",
            incident_active=False,
        ).to_dict()

    def test_the_field_moves_the_hash(self) -> None:
        base = dict(
            timestamp=0.0,
            capability_fingerprint="a" * 64,
            agent_id="probe",
            action=ACTION,
            request_hash="b" * 32,
            identity_status="active",
            identity_version=1,
            capability_revoked=False,
            capability_expired=False,
            delegation_chain_valid=True,
            delegation_depth=0,
            max_delegation_depth=3,
            posture="normal",
            trust_findings=0,
            risk_level="low",
            policy_version="v1",
            environment="{}",
            provenance_state="observed",
            incident_active=False,
        )

        unrestricted = SecurityContextSnapshot(
            **base,
            aegis_restrictions="none",
        )
        restricted = SecurityContextSnapshot(
            **base,
            aegis_restrictions="c" * 32,
        )

        assert unrestricted.state_hash() != restricted.state_hash()

    def test_the_default_keeps_a_hand_built_snapshot_valid(self) -> None:
        """The field is defaulted and last, so older constructions work.

        ``UNKNOWN`` is the same value an unwired controller produces, which
        is the honest reading of a snapshot that never consulted Aegis.
        """

        snapshot = SecurityContextSnapshot(
            timestamp=0.0,
            capability_fingerprint="a" * 64,
            agent_id="probe",
            action=ACTION,
            request_hash="b" * 32,
            identity_status="active",
            identity_version=1,
            capability_revoked=False,
            capability_expired=False,
            delegation_chain_valid=True,
            delegation_depth=0,
            max_delegation_depth=3,
            posture="normal",
            trust_findings=0,
            risk_level="low",
            policy_version="v1",
            environment="{}",
            provenance_state="observed",
            incident_active=False,
        )

        assert snapshot.aegis_restrictions == UNKNOWN


class TestTheProbeIsFailClosed:
    """Three states, and only one of them is "no restrictions"."""

    def test_no_controller_reads_unknown_and_is_not_a_degradation(self) -> None:
        """Unwired is not the same as broken.

        Every other probe distinguishes these, and it matters: a
        deployment that never ran Aegis has no Aegis state to be blind to,
        and marking it degraded would make ``revalidate()`` refuse to
        confirm any authority anywhere.
        """

        sdk, _ = build(aegis=False)
        capability = issue(sdk, None)
        cached(sdk, capability)

        snapshot = sdk.continuous_auth_engine._capture_snapshot(
            capability,
            ACTION,
            REQUEST,
        )

        assert snapshot.aegis_restrictions == UNKNOWN
        assert "aegis" not in snapshot.degraded_dependencies
        assert snapshot.degraded is False

        sdk.close()

    def test_a_wired_controller_with_nothing_applied_reads_none(self) -> None:
        sdk, controller = build()
        capability = issue(sdk, controller)

        assert digest(sdk, capability) == "none"

        sdk.close()

    def test_an_unreadable_store_degrades_and_withholds_the_allow(self) -> None:
        """The direction that matters when the probe itself fails.

        Only ``restrictions_for`` is broken here, so ``_gate_aegis`` still
        answers and ``authorize()`` still allows. That isolation is the
        point: the divergence measured is the *probe's* blindness, not the
        gate's. Revalidation must refuse to report the allow it cannot
        confirm -- and refusing is a subtraction from a canonical verdict,
        which is the only direction the engine is permitted to move.
        """

        sdk, controller = build()
        capability = issue(sdk, controller)
        cached(sdk, capability)

        class UnreadableStore:
            def restrictions_for(self, fingerprint: str) -> tuple:
                raise RuntimeError("store unreadable")

            def any_suspended(self, fingerprints: Any) -> None:
                return None

            def excludes(
                self,
                fingerprints: Any,
                action: str,
                request: Any,
            ) -> None:
                return None

        object.__setattr__(controller, "_store", UnreadableStore())

        snapshot = sdk.continuous_auth_engine._capture_snapshot(
            capability,
            ACTION,
            REQUEST,
        )

        assert snapshot.aegis_restrictions == PROBE_FAILED
        assert "aegis" in snapshot.degraded_dependencies

        direct = sdk.authorize(capability, ACTION, REQUEST)
        result = sdk.revalidate(capability, ACTION, REQUEST)

        assert direct.allowed is True
        assert result.revalidated_allowed is False
        assert result.reason == "security_dependency_unavailable: aegis"

        sdk.close()


class TestTheDigestDoesNotInvalidateSpuriously:
    """Precision, so that ``no_material_state_change`` keeps its meaning."""

    def test_an_unrelated_grants_suspension_is_not_a_change(self) -> None:
        sdk, controller = build()
        capability = issue(sdk, controller)

        unrelated = sdk.issue(
            agent="other-agent",
            capability="storage.*",
        )
        controller.register(
            sdk.fingerprint(unrelated),
            agent_id=unrelated.agent_id,
            capability=unrelated.capability,
        )

        cached(sdk, capability)
        before = digest(sdk, capability)

        controller.suspend(
            sdk.fingerprint(unrelated),
            key="elsewhere",
            reason="probe",
        )

        result = sdk.revalidate(capability, ACTION, REQUEST)

        assert digest(sdk, capability) == before
        assert result.state_changed is False
        assert result.revalidated_allowed is True

        sdk.close()

    def test_re_applying_an_identical_restriction_is_not_a_change(self) -> None:
        """``Restriction.identity()`` is "what it does, not when".

        A digest built from ``applied_at`` or ``sequence`` would move on
        every idempotent re-apply, and a monitor that re-applies a standing
        restriction on each sweep would force a canonical authorization
        every time while reporting a state change that did not happen.
        """

        sdk, controller = build()
        capability = issue(sdk, controller)
        fingerprint = sdk.fingerprint(capability)

        controller.narrow(
            fingerprint,
            key="tighten",
            constraints={"amount_max": 5},
            reason="probe",
        )
        before = digest(sdk, capability)

        controller.narrow(
            fingerprint,
            key="tighten",
            constraints={"amount_max": 5},
            reason="probe again",
        )

        assert digest(sdk, capability) == before

        sdk.close()

    def test_a_different_constraint_under_the_same_key_is_a_change(self) -> None:
        """The negative control on the test above."""

        sdk, controller = build()
        capability = issue(sdk, controller)
        fingerprint = sdk.fingerprint(capability)

        controller.narrow(
            fingerprint,
            key="tighten",
            constraints={"amount_max": 5},
            reason="probe",
        )
        before = digest(sdk, capability)

        controller.narrow(
            fingerprint,
            key="tighten",
            constraints={"amount_max": 4},
            reason="probe",
        )

        assert digest(sdk, capability) != before

        sdk.close()


def chain_of_three() -> tuple[FirewallSDK, AegisController, Any, tuple[str, ...]]:
    """Root, middle, leaf -- each registered, each narrower than its parent."""

    sdk, controller = build()
    key = sdk.active_key().private_key

    root = sdk.issue(
        agent="root-agent",
        capability="payments.*",
        constraints={"amount_max": 100},
    )
    middle = sdk.delegate(
        root,
        key,
        delegatee="middle-agent",
        constraints={"amount_max": 80},
    ).child
    leaf = sdk.delegate(
        middle,
        key,
        delegatee="leaf-agent",
        constraints={"amount_max": 50},
    ).child

    names = []
    for capability in (root, middle, leaf):
        fingerprint = sdk.fingerprint(capability)
        controller.register(
            fingerprint,
            agent_id=capability.agent_id,
            capability=capability.capability,
        )
        names.append(fingerprint)

    return sdk, controller, leaf, tuple(names)


class TestRestrictionsBindTheWholeChain:
    """A restriction on an ancestor must move a descendant's digest.

    ``_gate_aegis`` checks the requested fingerprint plus every delegation
    ancestor, because a restriction on a parent has to refuse a child --
    otherwise suspending a parent leaves its children usable. The digest
    has to cover at least the same set, or suspending an ancestor denies at
    the boundary while revalidation reports no change.

    The two are derived independently: the gate walks
    ``ctx.delegation_authority``, the probe walks ``delegation_lineage``.
    These tests pin their agreement at depth three, which is where the
    divergence would show if the registry omitted an intermediate member.
    """

    @pytest.mark.parametrize("position,role", [(0, "root"), (1, "middle"), (2, "leaf")])
    def test_suspending_any_member_denies_the_leaf(
        self,
        position: int,
        role: str,
    ) -> None:
        sdk, controller, leaf, names = chain_of_three()
        cached(sdk, leaf)
        before = digest(sdk, leaf)

        controller.suspend(names[position], key=f"sus-{role}", reason="probe")

        direct = sdk.authorize(leaf, ACTION, REQUEST)
        result = sdk.revalidate(leaf, ACTION, REQUEST)

        assert direct.reason == f"aegis_suspended:sus-{role}"
        assert digest(sdk, leaf) != before
        assert result.state_changed is True
        assert result.revalidated_allowed is False
        assert result.authority_revoked is True

        sdk.close()

    def test_each_member_produces_a_distinct_digest(self) -> None:
        """Position is in the digest, so two members cannot alias.

        A digest that hashed only the restriction identities would collide
        when the same key were applied to a parent and to a child, and a
        move of a restriction from one to the other would read as no
        change.
        """

        digests = set()

        for position in range(3):
            sdk, controller, leaf, names = chain_of_three()
            controller.suspend(names[position], key="same-key", reason="probe")
            digests.add(digest(sdk, leaf))
            sdk.close()

        assert len(digests) == 3


class TestTheResumePathStillGoesThroughTheBoundary:
    """Lifting a restriction widens. The widening must be authorize()'s."""

    def test_a_lift_is_detected_and_revalidated_canonically(self) -> None:
        sdk, controller = build()
        capability = issue(sdk, controller)
        fingerprint = sdk.fingerprint(capability)
        cached(sdk, capability)

        controller.suspend(fingerprint, key="incident", reason="probe")
        suspended = sdk.revalidate(capability, ACTION, REQUEST)

        assert suspended.revalidated_allowed is False

        controller.lift(fingerprint, "incident", reason="resolved")
        resumed = sdk.revalidate(capability, ACTION, REQUEST)

        assert resumed.state_changed is True
        assert resumed.revalidated_allowed is True
        assert resumed.authority_widened is True
        assert resumed.details["revalidated_reason"] == "authorized"
        assert sdk.authorize(capability, ACTION, REQUEST).allowed is True

        sdk.close()

    def test_a_suspension_lifted_before_any_revalidation_is_not_a_change(
        self,
    ) -> None:
        """Net-zero state, but no longer a net-zero digest.

        v2.5 recorded this as the fast path serving the cached allow: the
        restriction digest returned to its cached value, so nothing looked
        different, and ``authorize()`` agreed because the restriction really
        was gone. The property was that the two surfaces agree.

        v2.6 keeps that property and drops the fast path here. The lift is an
        authority-widening write, so it moves the snapshot's
        ``authority_epoch`` -- which is monotonic and therefore cannot return
        to a cached value the way the restriction digest can. The
        revalidation now re-asks ``authorize()`` and gets the same allow.

        The change is deliberate and it is narrowing: a net-zero *state* is
        not a net-zero *history*, and the digest could only ever say the
        former. Reporting a change costs one extra call to the canonical
        boundary; not reporting it is what the v2.5 ``aegis_restrictions``
        and ``refusal_state`` defects both looked like from the outside.
        """

        sdk, controller = build()
        capability = issue(sdk, controller)
        fingerprint = sdk.fingerprint(capability)
        cached(sdk, capability)

        controller.suspend(fingerprint, key="brief", reason="probe")
        controller.lift(fingerprint, "brief", reason="resolved")

        direct = sdk.authorize(capability, ACTION, REQUEST)
        result = sdk.revalidate(capability, ACTION, REQUEST)

        # The property, unchanged: the two surfaces agree.
        assert direct.allowed is True
        assert result.revalidated_allowed is True

        # And the reason they agree is that the boundary was re-asked.
        assert result.state_changed is True
        assert result.reason != "no_material_state_change"

        # Only the epoch moved. The restriction digest did return to its
        # cached value, which is exactly why it could not carry this.
        drift = result.details["change_reasons"]
        assert any(item.startswith("authority_epoch:") for item in drift)
        assert not any(
            item.startswith("aegis_restrictions:") for item in drift
        )

        sdk.close()


class TestTheOtherGateInputsWereMeasured:
    """What the same probe shape found for the neighbouring mechanisms.

    Recorded as tests rather than as prose because each is a claim about
    current behaviour that a later change could invalidate silently. Two of
    the three are caught by fields that already existed; the third is a
    non-divergence, and pinning it stops a future reader from assuming it
    was overlooked.
    """

    def test_capability_revocation_was_already_covered(self) -> None:
        sdk, controller = build()
        capability = issue(sdk, controller)
        cached(sdk, capability)

        sdk.revoke(capability, reason="probe")

        result = sdk.revalidate(capability, ACTION, REQUEST)

        assert result.revalidated_allowed is False
        assert "capability_revoked" in result.reason

        sdk.close()

    def test_issuer_revocation_is_caught_by_the_policy_version(self) -> None:
        """Caught, but incidentally: there is no issuer-trust field.

        The SDK's policy version digests the trusted-issuer set, so revoking
        an issuer moves ``policy_version``. That is real detection and the
        surfaces agree -- but it is a consequence of what the policy version
        happens to cover, not of a field that names the mechanism, so it is
        pinned here to make the dependency visible.
        """

        sdk, controller = build()
        capability = issue(sdk, controller)
        cached(sdk, capability)

        sdk.revoke_issuer(capability.issuer)

        direct = sdk.authorize(capability, ACTION, REQUEST)
        result = sdk.revalidate(capability, ACTION, REQUEST)

        assert direct.reason == "untrusted_issuer"
        assert result.revalidated_allowed is False
        assert "policy_version" in result.reason

        sdk.close()

    def test_retiring_a_signing_key_diverges_from_neither_surface(self) -> None:
        """No divergence, because retirement does not deny.

        Retiring a key stops it signing new capabilities; signatures already
        issued stay verifiable, so ``authorize()`` still allows and the
        cached allow is not stale. The snapshot carries no key-retirement
        field and does not need one *for this property* -- which is worth
        pinning, because "no field" and "no divergence" are easy to confuse
        with each other in a review.
        """

        sdk, controller = build()
        capability = issue(sdk, controller)
        cached(sdk, capability)

        sdk.retire_key(sdk.active_key().key_id)

        direct = sdk.authorize(capability, ACTION, REQUEST)
        result = sdk.revalidate(capability, ACTION, REQUEST)

        assert direct.allowed is True
        assert result.revalidated_allowed is True
        assert result.state_changed is False

        sdk.close()


class TestTheSameHoleOnTheFirstGate:
    """A latched refusal was invisible to the snapshot too.

    Found by checking this file's own coverage claim rather than by a new
    attack. The v2.5 boundary document had asserted that refusal state could
    not produce a stale allow "because latching only ever subtracts". That
    argument is true of ``authorize()`` and false of the surface here: the
    boundary denies, and the cache goes on reporting the verdict it took
    before the refusal existed.

    Three things make it worse than the Aegis case it mirrors, which is why
    it is pinned separately rather than folded into the class above:

    * **No injected component.** ``_apply_denial`` records the refusal
      itself, for every ``constraint_denied`` and ``policy_denied``. The
      whole sequence is ordinary API use.
    * **The refused request is not the cached one.** The over-ceiling request
      is a different request; ``check_action`` matches on the *action*, so it
      latches against the in-range request that was already allowed.
    * **It is the first gate.** ``_gate_refusal`` runs before everything,
      so the denial it produces is the one that reaches the caller.
    """

    OVER = {"amount": 10_000}

    def test_a_latched_refusal_after_a_cached_allow_is_noticed(self) -> None:
        sdk, controller = build()
        capability = issue(sdk, controller)
        cached(sdk, capability)

        over = sdk.authorize(capability, ACTION, dict(self.OVER))

        assert over.allowed is False
        assert over.reason == "constraint_denied"

        # The boundary now denies the request that was cached as allowed,
        # for a reason that has nothing to do with the request itself.
        direct = sdk.authorize(capability, ACTION, REQUEST)

        assert direct.allowed is False
        assert direct.reason == "refusal_state"

        result = sdk.revalidate(capability, ACTION, REQUEST)

        assert result.revalidated_allowed is False
        assert result.authority_revoked is True
        assert result.state_changed is True
        assert "refusal_state" in result.reason

        sdk.close()

    def test_the_two_surfaces_agree_on_the_refusal(self) -> None:
        """Both answers come from the boundary, and they match.

        The fix routes revalidation into ``authorize()`` rather than teaching
        the engine what a refusal means -- so the reason the caller sees is
        the gate's own, and there is no second interpretation of refusal
        state to drift out of step with the first.
        """

        sdk, controller = build()
        capability = issue(sdk, controller)
        cached(sdk, capability)

        sdk.authorize(capability, ACTION, dict(self.OVER))

        direct = sdk.authorize(capability, ACTION, REQUEST)
        result = sdk.revalidate(capability, ACTION, REQUEST)

        assert direct.allowed == result.revalidated_allowed
        assert direct.reason == "refusal_state"

        sdk.close()

    def test_the_digest_is_material_and_moves(self) -> None:
        engine_field = "refusal_state"

        sdk, controller = build()
        capability = issue(sdk, controller)
        engine = sdk.continuous_auth_engine

        before = engine._capture_snapshot(capability, ACTION, REQUEST)

        assert engine_field in before.to_dict()
        assert engine_field not in _HASH_EXCLUDED_FIELDS
        assert before.refusal_state == "none"

        sdk.authorize(capability, ACTION, dict(self.OVER))

        after = engine._capture_snapshot(capability, ACTION, REQUEST)

        assert after.refusal_state != before.refusal_state
        assert after.state_hash() != before.state_hash()

        sdk.close()

    def test_an_unreadable_refusal_store_degrades_and_withholds(self) -> None:
        """Blind here means degraded, not unchanged.

        The mirror of the Aegis probe's fail-closed test, and the reason it is
        not redundant with FAIL_CLOSED's two refusal probes: those establish
        that ``authorize()`` denies. This establishes that the *monitoring*
        surface does not answer "nothing has changed" from a store it could
        not read.
        """

        class Blind:
            def snapshot(self):
                raise RuntimeError("refusal store unavailable")

            def check_action(self, **kwargs):
                raise RuntimeError("refusal store unavailable")

            def check(self, **kwargs):
                raise RuntimeError("refusal store unavailable")

            def record(self, **kwargs):
                return None

        sdk, controller = build()
        capability = issue(sdk, controller)
        cached(sdk, capability)

        sdk.refusal_state = Blind()

        snapshot = sdk.continuous_auth_engine._capture_snapshot(
            capability, ACTION, REQUEST
        )

        assert snapshot.refusal_state == PROBE_FAILED
        assert "refusal_state" in snapshot.degraded_dependencies
        assert snapshot.degraded is True

        result = sdk.revalidate(capability, ACTION, REQUEST)

        assert result.revalidated_allowed is False
        assert "refusal_state" in result.reason

        direct = sdk.authorize(capability, ACTION, REQUEST)

        assert direct.allowed is False
        assert direct.reason == "refusal_state_unavailable:RuntimeError"

        sdk.close()

    def test_the_digest_does_not_invalidate_spuriously(self) -> None:
        """Scoped to this agent and this capability, and no wider.

        The digest is deliberately coarser than the gate on action and
        request -- coarse costs a redundant canonical call, fine would
        reintroduce the stale allow -- but it is not coarser on identity.
        A refusal latched against a *different* capability must not
        invalidate this one's cache, and the boundary is asked to confirm
        that this is agreement rather than a matching pair of mistakes.
        """

        sdk, controller = build()
        capability = issue(sdk, controller)
        other = issue(sdk, controller)
        cached(sdk, capability)

        before = digest_refusal(sdk, capability)
        refused = sdk.authorize(other, ACTION, dict(self.OVER))

        assert refused.reason == "constraint_denied"
        assert digest_refusal(sdk, capability) == before

        direct = sdk.authorize(capability, ACTION, REQUEST)
        result = sdk.revalidate(capability, ACTION, REQUEST)

        assert direct.allowed is True
        assert result.revalidated_allowed is True
        assert result.state_changed is False

        sdk.close()

    def test_clearing_the_refusal_returns_to_the_baseline(self) -> None:
        """And the two surfaces agree there too.

        ``clear_all()`` is the only way back, and it must land the digest on
        the value the baseline snapshot recorded -- otherwise every later
        revalidation slow-paths forever, which is safe but would hide a
        genuine drift behind permanent churn.
        """

        sdk, controller = build()
        capability = issue(sdk, controller)
        cached(sdk, capability)

        baseline = digest_refusal(sdk, capability)

        sdk.authorize(capability, ACTION, dict(self.OVER))

        assert digest_refusal(sdk, capability) != baseline

        sdk.refusal_state.clear_all()

        assert digest_refusal(sdk, capability) == baseline

        direct = sdk.authorize(capability, ACTION, REQUEST)
        result = sdk.revalidate(capability, ACTION, REQUEST)

        assert direct.allowed is True
        assert result.revalidated_allowed is True

        sdk.close()

    def test_a_parent_refusal_does_not_bind_a_delegated_child(self) -> None:
        """Not widened to the chain, because the gate does not widen either.

        ``_probe_aegis`` covers the whole delegation chain because a
        restriction on an ancestor binds every descendant. ``check_action``
        compares ``key.capability_fingerprint`` exactly, so a refusal does
        not -- and a digest that covered the chain would invalidate a child's
        cache for a denial the child never receives. Pinned because the
        asymmetry between the two probes is deliberate and looks like an
        oversight.
        """

        sdk, controller = build()
        parent = issue(sdk, controller)
        child = sdk.delegate(
            parent,
            sdk.keys.active().private_key,
            delegatee="delegated-agent",
            constraints={"amount_max": 100},
        ).child

        assert sdk.authorize(child, ACTION, REQUEST).allowed is True

        sdk.authorize(parent, ACTION, dict(self.OVER))

        assert sdk.authorize(parent, ACTION, REQUEST).reason == "refusal_state"
        assert sdk.authorize(child, ACTION, REQUEST).allowed is True

        sdk.close()
    """``state_hash()``'s other consumer, and the ``KEEP`` it used to return.

    ``firewall.aegis.response.classify`` is the second reader of the hash.
    It contributes ``state_hash_changed`` when the hash moves, and ``KEEP``
    -- documented in ``docs/v2.4-aegis-design.md`` as the one response that
    "requires positive evidence" -- is reachable only when it did not.
    Before ``aegis_restrictions`` existed, a suspension applied between the
    two snapshots produced no contribution, so the positive evidence was
    an absence of information rather than an absence of change.

    Pinned separately from the revalidation tests because it is a different
    surface with a different failure: no stale allow here, since ``classify``
    returns an advisory response and not a verdict, but a ``KEEP`` on a
    suspended grant is Aegis declining to act on its own restriction.
    """

    @staticmethod
    def _around_a_suspension(
        sdk: FirewallSDK,
        controller: AegisController,
        capability: Any,
    ) -> tuple[SecurityContextSnapshot, SecurityContextSnapshot]:
        engine = sdk.continuous_auth_engine
        before = engine._capture_snapshot(capability, ACTION, REQUEST)
        controller.suspend(
            sdk.fingerprint(capability),
            key="incident-1",
            reason="probe",
        )
        after = engine._capture_snapshot(capability, ACTION, REQUEST)

        return before, after

    def test_a_suspension_is_no_longer_classified_as_keep(self) -> None:
        sdk, controller = build()
        capability = issue(sdk, controller)
        assert controller is not None

        before, after = self._around_a_suspension(sdk, controller, capability)

        assert before.state_hash() != after.state_hash()

        analysis = classify(
            RevalidationTrigger.ENVIRONMENT_CHANGED,
            before=before,
            after=after,
        )

        assert analysis.response is not AdaptiveResponse.KEEP
        assert analysis.response is AdaptiveResponse.REVALIDATE
        assert "state_hash_changed" in {
            contribution.rule for contribution in analysis.contributions
        }

        sdk.close()

    def test_the_new_contribution_can_only_escalate(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The pre-fix response, and that the fix moved it upward.

        ``classify`` takes the maximum over contributions, so an added
        contribution cannot lower a response -- but "cannot" is an argument
        about the join, and this measures it on the case that changed. The
        pre-fix ``KEEP`` is reconstructed the same way the invariant's
        negative control reconstructs its defect.
        """

        original = SecurityContextSnapshot.to_dict

        def blind(self: SecurityContextSnapshot) -> dict:
            fields = original(self)
            fields.pop("aegis_restrictions", None)
            return fields

        sdk, controller = build()
        capability = issue(sdk, controller)
        assert controller is not None

        monkeypatch.setattr(SecurityContextSnapshot, "to_dict", blind)
        before, after = self._around_a_suspension(sdk, controller, capability)

        assert before.state_hash() == after.state_hash()

        blinded = classify(
            RevalidationTrigger.ENVIRONMENT_CHANGED,
            before=before,
            after=after,
        )
        assert blinded.response is AdaptiveResponse.KEEP

        # The same two snapshot objects, read with the field visible again.
        # Re-capturing "before" here would sample the state *after* the
        # suspension and compare it with itself.
        monkeypatch.undo()

        assert before.state_hash() != after.state_hash()

        seeing = classify(
            RevalidationTrigger.ENVIRONMENT_CHANGED,
            before=before,
            after=after,
        )

        # Same event, same trigger: the response the classifier reaches is
        # strictly higher now. Compared through ``severity`` rather than
        # ``>``, because ``AdaptiveResponse`` is a ``str`` enum and its
        # lexical order agrees with the lattice only by coincidence.
        assert severity(seeing.response) > severity(blinded.response)

        sdk.close()


class TestTheInvariantHasTeeth:
    """REVALIDATION_CONSISTENCY, positive and negative control.

    The invariant is what makes this finding a standing claim rather than
    a fixed bug: the tests above pin the two restriction kinds that
    reproduced it, the invariant probes a grid on every CI run. But an
    invariant is only worth registering if it can fail, and the way it
    could quietly stop being able to fail is specific -- ``check_all``
    converts a raising checker into ``UNVERIFIABLE``, and the fifteen
    invariants that shipped in v2.4 were all green while the defect was
    live. So both directions are pinned here.

    The negative control reproduces the original blindness through its
    original mechanism rather than by monkeypatching the check: the
    snapshot's ``to_dict`` is made to drop ``aegis_restrictions``, which
    is exactly the pre-fix state, since ``state_hash()`` and
    ``_diff_snapshots`` are both driven off ``to_dict``. An invariant that
    survived that would be reporting on something other than the property
    it names.
    """

    def test_it_holds_against_the_shipped_package(self) -> None:
        result = check_revalidation_consistency()

        assert result.status is InvariantStatus.HOLDS, (
            result.reason,
            result.findings,
        )
        assert result.findings == ()
        # The probe grid is not decoration: a check that examined nothing
        # and reported HOLDS is the fail-open shape this suite exists to
        # prevent, and ``holds`` alone cannot distinguish the two.
        assert result.details["probes"] >= 5

    def test_removing_the_field_makes_the_invariant_fail(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The pre-fix package, reconstructed, is reported as VIOLATED.

        Not ``UNVERIFIABLE``: the check reaches its comparison, both
        surfaces answer, and they disagree. A defect that arrived as an
        unverifiable would still fail ``--strict``, but it would be
        indistinguishable from a wiring gap, and the two need different
        responses.
        """

        original = SecurityContextSnapshot.to_dict

        def blind(self: SecurityContextSnapshot) -> dict:
            fields = original(self)
            fields.pop("aegis_restrictions", None)
            return fields

        monkeypatch.setattr(SecurityContextSnapshot, "to_dict", blind)

        result = check_revalidation_consistency()

        assert result.status is InvariantStatus.VIOLATED
        assert len(result.findings) == 2

        findings = " | ".join(result.findings)
        assert "aegis suspension" in findings
        assert "aegis narrowing" in findings
        # The stale allow, named in the finding: the engine reported an
        # authority while the boundary gave a reason for refusing it.
        assert "aegis_suspended" in findings
        assert "aegis_constraint_denied" in findings
        assert "state_changed=False" in findings

    def test_removing_the_refusal_field_makes_the_invariant_fail(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The second field has its own negative control.

        Blinding ``aegis_restrictions`` leaves the refusal probe covered and
        vice versa, so one control cannot stand in for the other. Both are
        reconstructed through ``to_dict`` rather than by monkeypatching the
        check, because that is the mechanism the defect actually had.
        """

        original = SecurityContextSnapshot.to_dict

        def blind(self: SecurityContextSnapshot) -> dict:
            fields = original(self)
            fields.pop("refusal_state", None)
            return fields

        monkeypatch.setattr(SecurityContextSnapshot, "to_dict", blind)

        result = check_revalidation_consistency()

        assert result.status is InvariantStatus.VIOLATED
        assert len(result.findings) == 1

        finding = result.findings[0]

        assert "latched refusal" in finding
        assert "refusal_state" in finding
        assert "state_changed=False" in finding

    def test_the_registry_carries_it(self) -> None:
        """Registered, so the CI gate runs it.

        A check function nothing calls is the failure mode the registry
        exists to prevent, and this one is reachable from a source-only
        run -- ``--exercise`` is not required, which matters because the
        canonical estate does not configure continuous authorization.
        """

        entry = invariant("REVALIDATION_CONSISTENCY")

        assert entry.needs_state is False

        report = check_all()
        result = report.get("REVALIDATION_CONSISTENCY")

        assert result is not None
        assert result.status is InvariantStatus.HOLDS

    def test_it_is_not_an_authorization_authority(self) -> None:
        """Running the check grants nothing and revokes nothing.

        It mints capabilities, suspends them and calls ``authorize()`` on
        scratch SDKs. If any of that reached a supplied SDK's containers,
        a CI run would be mutating the estate it audits.
        """

        sdk, controller = build()
        capability = issue(sdk, controller)
        before = control_plane_snapshot(sdk)

        assert check_revalidation_consistency().status is InvariantStatus.HOLDS

        assert control_plane_snapshot(sdk) == before

        within = sdk.authorize(capability, ACTION, REQUEST)
        assert within.allowed is True

        over = sdk.authorize(capability, ACTION, {"amount": 10_000})
        assert over.allowed is False

        sdk.close()