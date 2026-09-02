"""v2.4: the Aegis state machine, and what its one widening edge demands.

Aegis is an *advisory* layer over the canonical boundary, so the property
that matters most here is negative: no sequence of Aegis operations may
hand back authority a previous one removed. The machine enforces that
with three rules -- terminal states have no outgoing edges, a transition
may not increase residual authority, and the single exception
(``REVALIDATING -> ACTIVE``) requires an ``AuthorizationResult`` that the
canonical boundary produced.

The evidence predicate is the load-bearing part, and it is tested here
against shapes the boundary *cannot* emit -- an allow with no trace, an
allow whose trace is a list, an allow carrying a non-canonical reason.
Those cannot be probed from inside ``firewall/`` at all:
AUTHORIZATION_UNIQUENESS forbids constructing an ``AuthorizationResult``
outside the authorization boundary, and the invariant suite is not exempt
from the invariants it ships. Fabricating an adversarial input is exactly
what a test file is for, and ``tests/`` is not scanned by that check --
so the shipped module obtains its hostile verdicts from the boundary and
these three live here.
"""

from __future__ import annotations

import pytest

from firewall.aegis.state import (
    EVIDENCED_EDGES,
    LIFT_EDGES,
    RESIDUAL_AUTHORITY,
    TERMINAL_STATES,
    AegisGrant,
    AegisState,
    IllegalTransition,
    Transition,
    canonical_allow_for,
    history_violations,
    residual_authority,
    transition_is_legal,
)
from firewall.authorization import AuthorizationResult
from firewall.sdk import FirewallSDK

FINGERPRINT = "a" * 64
OTHER_FINGERPRINT = "b" * 64

#: Distinguishes "trace not supplied" from "trace is explicitly None",
#: which is one of the hostile shapes under test.
_DEFAULT = object()


def _grant(state: AegisState = AegisState.ISSUED) -> AegisGrant:
    return AegisGrant(
        fingerprint=FINGERPRINT,
        agent_id="agent-a",
        capability="payments.send",
        state=state,
    )


def _forged_allow(
    *,
    allowed: bool = True,
    reason: str = "authorized",
    trace=_DEFAULT,
) -> AuthorizationResult:
    """An ``AuthorizationResult`` built by hand, for the hostile grid.

    Legitimate here and nowhere in ``firewall/``: the point is to present
    the predicate with field combinations the boundary never emits, which
    means not going through the boundary.
    """

    if trace is _DEFAULT:
        trace = {"capability_id": FINGERPRINT}

    return AuthorizationResult(allowed=allowed, reason=reason, trace=trace)


# ======================================================================
# The shape of the machine
# ======================================================================


class TestResidualOrdering:
    def test_revalidating_sits_at_the_bottom_with_the_terminals(self):
        """Unknown is not trusted, so in-flight knowledge withholds.

        If ``REVALIDATING`` outranked ``SUSPENDED``, then
        ``SUSPENDED -> REVALIDATING`` would be a widening edge -- and it
        is the edge a lift takes, which would make lifting a restriction a
        way to gain authority without a verdict.
        """

        assert residual_authority(AegisState.REVALIDATING) == 0
        assert residual_authority(AegisState.REVOKED) == 0
        assert residual_authority(AegisState.EXPIRED) == 0

        assert (
            residual_authority(AegisState.REVALIDATING)
            < residual_authority(AegisState.SUSPENDED)
            < residual_authority(AegisState.NARROWED)
            < residual_authority(AegisState.ACTIVE)
        )
        assert residual_authority(AegisState.ISSUED) == residual_authority(
            AegisState.ACTIVE
        )

    def test_every_state_is_ordered(self):
        # A state with no residual entry would make transition_is_legal
        # raise KeyError, and a raising checker inside the gate is a
        # fail-open shape rather than a decision.
        assert set(RESIDUAL_AUTHORITY) == set(AegisState)

    def test_exactly_one_edge_may_widen(self):
        """Every widening pair is either illegal or the evidenced edge.

        Enumerated over the full 7x7 cross-product rather than asserted
        about ``EVIDENCED_EDGES`` directly: the claim is about the
        machine's behaviour, and deriving it from the same constant the
        machine reads would be circular.
        """

        widening = {
            (from_state, to_state)
            for from_state in AegisState
            for to_state in AegisState
            if residual_authority(to_state) > residual_authority(from_state)
            and transition_is_legal(from_state, to_state)
        }

        assert widening == {(AegisState.REVALIDATING, AegisState.ACTIVE)}
        assert widening == set(EVIDENCED_EDGES)

    def test_no_terminal_state_has_an_outgoing_edge(self):
        for from_state in TERMINAL_STATES:
            for to_state in AegisState:
                assert transition_is_legal(from_state, to_state) is False, (
                    from_state,
                    to_state,
                )

    def test_terminality_is_checked_before_the_residual_rule(self):
        """``REVOKED -> REVALIDATING`` is residual-equal, and still refused.

        Both states have residual 0, so the ordering rule alone would
        permit it -- and it is step one of an authority resurrection:
        ``REVOKED -> REVALIDATING -> ACTIVE`` would need only a verdict
        the boundary is willing to produce for a capability it has not yet
        been told is revoked.
        """

        assert (
            residual_authority(AegisState.REVALIDATING)
            == residual_authority(AegisState.REVOKED)
        )
        assert (
            transition_is_legal(
                AegisState.REVOKED,
                AegisState.REVALIDATING,
            )
            is False
        )

        with pytest.raises(IllegalTransition) as caught:
            _grant(AegisState.REVOKED).transition(
                AegisState.REVALIDATING,
                "resurrect",
            )

        assert "terminal" in str(caught.value)

    def test_a_self_edge_is_legal(self):
        # Re-observing a state is not a transition to refuse; refusing it
        # would push callers into guarding every observation.
        for state in AegisState:
            expected = state not in TERMINAL_STATES
            assert transition_is_legal(state, state) is expected, state


# ======================================================================
# The grant is not a decision
# ======================================================================


class TestGrantIsNotAVerdict:
    def test_truth_testing_a_grant_raises(self):
        """``if grant:`` must not be a way to read authority.

        An Aegis grant in any state -- including ``REVOKED`` -- would be
        truthy as an ordinary object, so a caller writing
        ``if sdk.aegis.grant(fp):`` would branch the permissive way on a
        revoked grant. Raising makes the mistake a crash at the call site
        instead of a silent allow.
        """

        with pytest.raises(TypeError) as caught:
            bool(_grant(AegisState.REVOKED))

        assert "not a decision" in str(caught.value)
        assert "authorize" in str(caught.value)

    def test_transition_returns_a_new_grant(self):
        """Immutability is what stops a stale handle writing back a state.

        A caller holding the pre-suspension grant must not be able to
        observe -- or restore -- the state the grant has since left.
        """

        before = _grant(AegisState.ACTIVE)
        after = before.transition(AegisState.SUSPENDED, "environmental change")

        assert before.state is AegisState.ACTIVE
        assert before.history == ()
        assert after is not before
        assert after.state is AegisState.SUSPENDED
        assert len(after.history) == 1

    def test_an_illegal_transition_raises_rather_than_no_op(self):
        """A refused narrowing must not look like a successful one.

        Returning the unchanged grant would let a caller that believes it
        suspended a grant carry on as if it had.
        """

        grant = _grant(AegisState.SUSPENDED)

        with pytest.raises(IllegalTransition):
            grant.transition(AegisState.ACTIVE, "widen without evidence")

        assert grant.state is AegisState.SUSPENDED

    def test_a_non_state_target_is_refused(self):
        for target in (None, "active", 3, AegisState):
            with pytest.raises(IllegalTransition):
                _grant().transition(target, "junk")


# ======================================================================
# The evidenced edge
# ======================================================================


class TestEvidencedEdge:
    def test_a_genuine_allow_traverses_it(self):
        """The positive control.

        Without it, every refusal below is satisfiable by a predicate that
        refuses everything -- which would make ``REVALIDATING`` a state no
        grant can leave, and Aegis a one-way ratchet to unusability rather
        than an adaptive layer.
        """

        sdk = FirewallSDK()
        try:
            sdk.generate_key("k")
            capability = sdk.issue(
                agent="agent-a",
                capability="payments.send",
                constraints={"amount_max": 100},
            )
            fingerprint = sdk.fingerprint(capability)
            allow = sdk.authorize(
                capability,
                action="payments.send",
                request={"amount": 10},
            )

            assert allow.allowed is True
            assert canonical_allow_for(fingerprint, allow) is True

            grant = AegisGrant(
                fingerprint=fingerprint,
                agent_id="agent-a",
                capability="payments.send",
                state=AegisState.REVALIDATING,
            ).transition(
                AegisState.ACTIVE,
                "revalidated",
                evidence=allow,
            )

            assert grant.state is AegisState.ACTIVE
            # The fingerprint is recorded, not the verdict object: the
            # history is evidence *that* a verdict existed, and must not
            # become a handle to replay one.
            assert grant.history[-1].evidence == fingerprint
        finally:
            sdk.close()

    @pytest.mark.parametrize(
        "label,evidence",
        [
            ("None", None),
            ("True", True),
            ("the integer 1", 1),
            ("the string 'authorized'", "authorized"),
            ("an empty mapping", {}),
            ("a mapping that looks like a verdict", {"allowed": True}),
        ],
    )
    def test_a_non_verdict_is_not_evidence(self, label, evidence):
        assert canonical_allow_for(FINGERPRINT, evidence) is False, label

    def test_a_duck_typed_look_alike_is_not_evidence(self):
        """Structural typing is refused: the check is on the class.

        A recommendation object, a monitoring result or a simulation
        outcome could each grow ``allowed``, ``reason`` and ``trace``
        attributes without becoming a verdict the boundary reached.
        """

        class _Forgery:
            allowed = True
            reason = "authorized"
            trace = {"capability_id": FINGERPRINT}

        assert canonical_allow_for(FINGERPRINT, _Forgery()) is False

    def test_an_allow_with_no_trace_is_not_evidence(self):
        """The boundary cannot emit this, so only a test can present it.

        A ``trace`` of ``None`` names no capability, so accepting it would
        make one allow good for every grant -- the replay attack with no
        replay needed.
        """

        assert (
            canonical_allow_for(FINGERPRINT, _forged_allow(trace=None))
            is False
        )

    def test_an_allow_whose_trace_is_not_a_mapping_is_not_evidence(self):
        """``trace.get`` on a list would raise inside the state machine.

        A raising predicate is not a refusing one: ``transition`` would
        propagate an ``AttributeError`` instead of ``IllegalTransition``,
        and a caller catching only the latter would see a crash where it
        expected a decision.
        """

        for hostile in ([("capability_id", FINGERPRINT)], (FINGERPRINT,), ""):
            assert (
                canonical_allow_for(FINGERPRINT, _forged_allow(trace=hostile))
                is False
            ), hostile

    def test_an_allow_with_a_non_canonical_reason_is_not_evidence(self):
        """Only ``"authorized"`` counts, and the reason is checked alone.

        Any other reason means the verdict was reached by some other
        route. ``"aegis_allowed"`` is the specific shape worth pinning: it
        is what a future Aegis-side allow would be spelled, and accepting
        it here is precisely how Aegis would become a second
        authorization engine feeding itself its own evidence.
        """

        for reason in ("aegis_allowed", "authorised", "allowed", ""):
            assert (
                canonical_allow_for(FINGERPRINT, _forged_allow(reason=reason))
                is False
            ), reason

    def test_a_denial_is_not_evidence(self):
        assert (
            canonical_allow_for(
                FINGERPRINT,
                _forged_allow(allowed=False, reason="constraint_denied"),
            )
            is False
        )

    def test_a_truthy_non_true_allowed_is_not_evidence(self):
        # ``allowed is not True`` rather than ``not allowed``: 1 is truthy
        # and would otherwise pass, and a JSON round-trip is one plausible
        # way an integer arrives where a bool is expected.
        for allowed in (1, "yes", [1]):
            assert (
                canonical_allow_for(FINGERPRINT, _forged_allow(allowed=allowed))
                is False
            ), allowed

    def test_another_capabilitys_allow_is_not_evidence(self):
        """Replay in its real form: a genuine, current allow for someone else.

        This is the case the shipped invariant probe obtains from the
        boundary rather than fabricating, because a boundary-written trace
        is the strongest version of it.
        """

        assert (
            canonical_allow_for(
                OTHER_FINGERPRINT,
                _forged_allow(trace={"capability_id": FINGERPRINT}),
            )
            is False
        )

    def test_the_edge_refuses_to_traverse_without_evidence(self):
        grant = _grant(AegisState.REVALIDATING)

        for evidence in (None, True, _forged_allow(reason="aegis_allowed")):
            with pytest.raises(IllegalTransition) as caught:
                grant.transition(
                    AegisState.ACTIVE,
                    "revalidated",
                    evidence=evidence,
                )

            assert "canonical allow" in str(caught.value)
            assert "Aegis does not" in str(caught.value)


# ======================================================================
# The lift edges
# ======================================================================


class TestLiftEdges:
    def test_a_lift_must_name_the_restriction(self):
        """A caller cannot clear a restriction it does not know exists.

        Without the key, "lift" degenerates into "return to
        ``REVALIDATING``", which any caller could do for any reason and
        which discards the record of what was removed -- the record §17
        needs to explain what authority came back and why.
        """

        for state in (AegisState.NARROWED, AegisState.SUSPENDED):
            with pytest.raises(IllegalTransition) as caught:
                _grant(state).transition(
                    AegisState.REVALIDATING,
                    "lift",
                )

            assert "naming the restriction" in str(caught.value)

            lifted = _grant(state).transition(
                AegisState.REVALIDATING,
                "lift",
                lifted="restriction:key",
            )

            assert lifted.state is AegisState.REVALIDATING
            assert lifted.history[-1].lifted == "restriction:key"

    def test_a_lift_does_not_restore_active(self):
        """The lift lands in ``REVALIDATING``, one edge short of ``ACTIVE``.

        This is the whole design: removing the obstacle is not the same as
        re-establishing standing, and the remaining edge is the one that
        demands a verdict.
        """

        lifted = _grant(AegisState.NARROWED).transition(
            AegisState.REVALIDATING,
            "obstacle removed",
            lifted="restriction:key",
        )

        assert lifted.state is AegisState.REVALIDATING
        assert lifted.residual < residual_authority(AegisState.NARROWED)

        with pytest.raises(IllegalTransition):
            lifted.transition(AegisState.ACTIVE, "assume standing")

    def test_the_lift_edges_are_exactly_the_restriction_bearing_states(self):
        assert set(LIFT_EDGES) == {
            (AegisState.NARROWED, AegisState.REVALIDATING),
            (AegisState.SUSPENDED, AegisState.REVALIDATING),
        }


# ======================================================================
# The history audits as data
# ======================================================================


class TestHistoryViolations:
    def test_a_legal_history_yields_no_findings(self):
        grant = (
            _grant(AegisState.ACTIVE)
            .transition(AegisState.NARROWED, "narrowed")
            .transition(
                AegisState.REVALIDATING,
                "lifted",
                lifted="restriction:key",
            )
        )

        assert history_violations(grant) == ()

    def test_a_forged_widening_is_named(self):
        """The audit reads history as data, not by re-running ``transition``.

        An invariant that re-ran the transition to decide whether the
        history was legal would be testing the checker against itself --
        and would be blind to a history written by anything other than
        ``transition``, which is the only way an illegal one can exist.
        """

        forged = AegisGrant(
            fingerprint=FINGERPRINT,
            agent_id="agent-a",
            capability="payments.send",
            state=AegisState.ACTIVE,
            history=(
                Transition(
                    from_state=AegisState.SUSPENDED,
                    to_state=AegisState.ACTIVE,
                    at=0.0,
                    reason="forged",
                ),
            ),
        )

        findings = history_violations(forged)

        assert findings
        joined = " ".join(findings)
        assert "widens residual authority" in joined

    def test_a_forged_departure_from_a_terminal_state_is_named(self):
        forged = AegisGrant(
            fingerprint=FINGERPRINT,
            agent_id="agent-a",
            capability="payments.send",
            state=AegisState.NARROWED,
            history=(
                Transition(
                    from_state=AegisState.REVOKED,
                    to_state=AegisState.NARROWED,
                    at=0.0,
                    reason="forged",
                ),
            ),
        )

        joined = " ".join(history_violations(forged))

        assert "leaves the terminal state revoked" in joined

    def test_an_evidenced_edge_recording_another_fingerprint_is_named(self):
        forged = AegisGrant(
            fingerprint=FINGERPRINT,
            agent_id="agent-a",
            capability="payments.send",
            state=AegisState.ACTIVE,
            history=(
                Transition(
                    from_state=AegisState.REVALIDATING,
                    to_state=AegisState.ACTIVE,
                    at=0.0,
                    reason="forged",
                    evidence=OTHER_FINGERPRINT,
                ),
            ),
        )

        joined = " ".join(history_violations(forged))

        assert "not this grant's fingerprint" in joined

    def test_a_discontinuous_history_is_named(self):
        forged = AegisGrant(
            fingerprint=FINGERPRINT,
            agent_id="agent-a",
            capability="payments.send",
            state=AegisState.SUSPENDED,
            history=(
                Transition(
                    from_state=AegisState.ACTIVE,
                    to_state=AegisState.NARROWED,
                    at=0.0,
                    reason="narrowed",
                ),
                Transition(
                    from_state=AegisState.ACTIVE,
                    to_state=AegisState.SUSPENDED,
                    at=1.0,
                    reason="skips a state",
                ),
            ),
        )

        joined = " ".join(history_violations(forged))

        assert "previous transition ended at" in joined

    def test_a_state_that_disagrees_with_the_history_is_named(self):
        forged = AegisGrant(
            fingerprint=FINGERPRINT,
            agent_id="agent-a",
            capability="payments.send",
            state=AegisState.ACTIVE,
            history=(
                Transition(
                    from_state=AegisState.ACTIVE,
                    to_state=AegisState.SUSPENDED,
                    at=0.0,
                    reason="suspended",
                ),
            ),
        )

        joined = " ".join(history_violations(forged))

        assert "history ends at suspended" in joined

    def test_a_lift_with_no_key_is_named(self):
        forged = AegisGrant(
            fingerprint=FINGERPRINT,
            agent_id="agent-a",
            capability="payments.send",
            state=AegisState.REVALIDATING,
            history=(
                Transition(
                    from_state=AegisState.NARROWED,
                    to_state=AegisState.REVALIDATING,
                    at=0.0,
                    reason="forged",
                ),
            ),
        )

        joined = " ".join(history_violations(forged))

        assert "names no restriction" in joined

    def test_an_empty_history_is_not_a_violation(self):
        # A registered grant that has done nothing yet is legal, and
        # reporting it would make every fresh registration a finding.
        assert history_violations(_grant()) == ()
