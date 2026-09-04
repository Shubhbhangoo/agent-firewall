"""v2.6: why the Aegis state machine is absent from the widening census.

:data:`firewall.authority_epoch.WIDENING_WRITES` claims to name every
write that can widen authority. The AUTHORITY_EPOCH_COVERAGE invariant
checks that claim against brackets in the source, and
``test_v2_6_mutator_census.py`` checks it against the methods on every
bound store. Neither reaches the case this file covers.

``AegisGrant.transition`` has widening edges. ``SUSPENDED ->
REVALIDATING`` is one, and ``REVALIDATING -> ACTIVE`` is the single
evidenced edge in the machine -- ``Transition.widens`` says so, by
comparing residual authority. Those transitions are published by three
writes to ``AegisController._grants``, and not one of them is bracketed or
listed in the census.

That is deliberate, and the justification is a claim about what the
boundary reads: **the restriction store is the enforcement and the grant
state is a label following it.** A widening of the label is invisible to
every canonical gate, so bracketing it would open an interval that denies
requests over a value no gate consulted.

A claim about what the boundary reads is exactly the kind that decays. A
later change that made ``_gate_aegis`` deny on ``grant.state is
SUSPENDED`` would be reasonable-looking, would pass every existing test,
and would silently make the census incomplete -- the grant writes would
then widen something a gate reads, with no bracket and no entry. So the
claim is pinned here rather than left in a comment: the authorization path
may touch only a declared set of controller members, and none of them
exposes grant state.

The tests are one-directional in the useful way. They cannot prove the
grant state is unreachable through some future call; they fail the moment
the *existing* path starts reading it.
"""

from __future__ import annotations

import ast
import dataclasses
import pathlib

from firewall.aegis import AegisController
from firewall.aegis.state import AegisState
from firewall.authority_epoch import WIDENING_WRITES
from firewall.continuous_auth.monitor import MonitoringConfig
from firewall.sdk import FirewallSDK

ACTION = "payments.transfer"
REQUEST = {"amount": 10}

#: Controller members a *gate* is allowed to touch.
#:
#: This is the security-relevant set: everything here runs while the
#: verdict is still being decided, so a widening of anything one of these
#: reads is a widening the census must cover.
#:
#: * ``tracked`` -- an emptiness check used to abstain cheaply. It reads
#:   ``_grants`` but only for truthiness, never for state, and
#:   ``test_no_controller_method_removes_a_grant`` pins that the dict never
#:   shrinks, so this cannot flip from tracked to untracked.
#: * ``restriction_reason`` -- reads ``_store``. The gate's denial.
#: * ``suspended_in`` -- reads ``_store``. The commit-time re-check.
#:
#: ``grant`` and ``grants`` are deliberately absent. They are the only way
#: to read a grant's state, and the census's completeness depends on no
#: gate calling them.
PERMITTED_GATE_READS = frozenset(
    {
        "restriction_reason",
        "suspended_in",
        "tracked",
    }
)

#: Controller members reachable *after* a verdict exists.
#:
#: ``observe_authorization`` is the only supplier of the evidenced edge and
#: runs from ``FirewallSDK._observe_aegis``, which is called once a
#: decision has been returned. It reads ``grant`` -- on the path where the
#: result is not a canonical allow it returns the current grant unchanged
#: -- and that read is harmless for the same reason the write is: nothing
#: downstream of it can alter a verdict that already exists.
PERMITTED_POST_VERDICT_READS = frozenset(
    {
        "grant",
        "observe_authorization",
    }
)

#: Every public controller member, recorded so the probe below can watch
#: all of them rather than only the ones already expected.
WATCHED = tuple(
    sorted(
        name
        for name in vars(AegisController)
        if not name.startswith("_")
    )
)


class Recording(AegisController):
    """A real controller that records which members were looked up.

    A subclass rather than a proxy: ``FirewallSDK.__init__`` requires an
    ``AegisController`` instance, so a ``__getattr__`` wrapper is rejected
    with a ``TypeError`` before any recording could happen.

    ``__getattribute__`` rather than wrapping each method, because the
    question is what the boundary *reaches for*. A read of ``grant`` that
    discarded its result would still be a read of grant state, and would
    still mean a later edit could branch on it.
    """

    def __init__(self) -> None:
        super().__init__()
        object.__setattr__(self, "touched", [])

    def __getattribute__(self, name):
        if name in WATCHED:
            object.__getattribute__(self, "touched").append(name)
        return object.__getattribute__(self, name)


def build() -> tuple[FirewallSDK, Recording, object, str]:
    controller = Recording()
    sdk = FirewallSDK(
        aegis=controller,
        continuous_auth_config=MonitoringConfig(
            enable_periodic_revalidation=False,
        ),
    )
    key = sdk.generate_key("v26-grant-state")
    capability = sdk.issue(
        agent="probe-agent",
        capability="payments.*",
        private_key=key.private_key,
        constraints={"amount_max": 100},
    )
    fingerprint = sdk.fingerprint(capability)
    controller.register(
        fingerprint,
        agent_id=capability.agent_id,
        capability=capability.capability,
    )

    return sdk, controller, capability, fingerprint


def gate_reads(sdk, controller, capability, action=ACTION, request=REQUEST):
    """Controller members touched *before* the verdict exists.

    The split matters. ``observe_authorization`` reads ``grant`` on the
    path where the result is not a canonical allow, and that read is not a
    gate read: ``FirewallSDK._observe_aegis`` runs after a decision has
    been made and cannot change it. Lumping the two together would either
    force ``grant`` into the gate allowlist -- defeating the point -- or
    fail on a read that is provably harmless.

    The boundary is taken from ``_observe_aegis`` itself rather than from a
    guess about ordering: the wrapper marks the recorder's high-water mark
    at the moment the observer is entered.
    """

    mark: list[int] = []
    original = sdk._observe_aegis

    def observe(ctx, outcome):
        mark.append(len(controller.touched))
        return original(ctx, outcome)

    sdk._observe_aegis = observe
    controller.touched.clear()
    outcome = sdk.authorize(capability, action, request)
    sdk._observe_aegis = original

    assert mark, (
        "_observe_aegis was never called, so the pre-verdict boundary is "
        "unknown and this probe establishes nothing"
    )

    return outcome, set(controller.touched[: mark[0]]), set(
        controller.touched[mark[0]:]
    )


class TestTheBoundaryNeverReadsGrantState:
    """The allowlist, checked against what one authorization actually does."""

    def test_only_permitted_controller_members_are_touched(self) -> None:
        sdk, controller, capability, _ = build()

        outcome, before, after = gate_reads(sdk, controller, capability)
        sdk.close()

        assert outcome.allowed, outcome.reason

        unexpected = sorted(before - PERMITTED_GATE_READS)

        assert not unexpected, (
            "a gate reached for "
            f"{unexpected} on the Aegis controller. If one of these reads "
            "grant state, WIDENING_WRITES is now incomplete: the three "
            "writes to AegisController._grants can widen a grant's "
            "residual authority and are neither bracketed nor declared."
        )
        assert not sorted(
            after - PERMITTED_GATE_READS - PERMITTED_POST_VERDICT_READS
        )

    def test_grant_state_is_not_read_on_the_denying_path_either(
        self,
    ) -> None:
        """A denial takes a different route through the gate.

        ``restriction_reason`` returning a string short-circuits before
        the later gates, so the allow path above does not cover it. It also
        changes what the observer does: a denial is not a canonical allow,
        so ``observe_authorization`` returns ``self.grant(fingerprint)``
        and that ``grant`` read appears -- after the verdict, which is why
        the split exists.
        """

        sdk, controller, capability, fingerprint = build()
        controller.suspend(fingerprint, key="incident", reason="probe")

        outcome, before, after = gate_reads(sdk, controller, capability)
        sdk.close()

        assert outcome.allowed is False
        assert not sorted(before - PERMITTED_GATE_READS)
        assert "grant" in after, (
            "the premise of the split is that the denial path reads grant "
            "after the verdict; if it no longer does, the split is "
            "untested rather than satisfied"
        )

    def test_the_allowlist_names_nothing_that_reads_grant_state(
        self,
    ) -> None:
        """``grant`` and ``grants`` must stay out of the gate allowlist.

        Without this, the test above could be satisfied by widening the
        allowlist -- which is the change it exists to catch.
        """

        assert "grant" not in PERMITTED_GATE_READS
        assert "grants" not in PERMITTED_GATE_READS
        assert not (PERMITTED_GATE_READS & PERMITTED_POST_VERDICT_READS)
        assert PERMITTED_GATE_READS <= set(WATCHED)
        assert PERMITTED_POST_VERDICT_READS <= set(WATCHED)


class TestGrantStateIsNotEnforcement:
    """The behavioural half: a widened label changes no verdict."""

    def test_a_revalidating_grant_under_a_live_suspension_is_denied(
        self,
    ) -> None:
        """The store outranks the label.

        ``AegisController.lift`` is the only route from ``SUSPENDED`` to
        ``REVALIDATING`` and it refuses to move while a suspension stands,
        so the state is forced directly here. That is not a supported
        operation -- it is the hostile case: even a grant whose label says
        its authority is being restored is denied while the store still
        holds the suspension.
        """

        sdk, controller, capability, fingerprint = build()
        controller.suspend(fingerprint, key="incident", reason="probe")

        with controller._lock:
            grant = controller._grants[fingerprint]
            controller._grants[fingerprint] = grant.transition(
                AegisState.REVALIDATING,
                "forced for the test",
                lifted="incident",
            )

        outcome = sdk.authorize(capability, ACTION, REQUEST)
        state = controller.grant(fingerprint).state
        sdk.close()

        assert state is AegisState.REVALIDATING
        assert outcome.allowed is False
        assert outcome.reason.startswith("aegis_suspended")

    def test_an_active_grant_under_a_live_suspension_is_denied(
        self,
    ) -> None:
        """The same at the top of the order.

        ``ACTIVE`` is the most permissive state the machine has, and it is
        unreachable here by any legal route: ``REVALIDATING -> ACTIVE`` is
        the evidenced edge and the only admissible evidence is a canonical
        allow for this fingerprint, which a suspended capability cannot
        produce. So the grant is replaced structurally, bypassing
        ``transition`` altogether.

        That is the point. The claim being tested is not "the machine
        refuses to widen" -- ``AEGIS_STATE_TRANSITIONS`` already covers
        that -- but "widening it would not matter", which needs a state the
        machine would never issue.
        """

        sdk, controller, capability, fingerprint = build()
        controller.suspend(fingerprint, key="incident", reason="probe")

        with controller._lock:
            controller._grants[fingerprint] = dataclasses.replace(
                controller._grants[fingerprint],
                state=AegisState.ACTIVE,
            )

        outcome = sdk.authorize(capability, ACTION, REQUEST)
        state = controller.grant(fingerprint).state
        sdk.close()

        assert state is AegisState.ACTIVE
        assert outcome.allowed is False
        assert outcome.reason.startswith("aegis_suspended")

    def test_lifting_the_restriction_is_what_changes_the_verdict(
        self,
    ) -> None:
        """The control, and the reason the census is still complete.

        ``AegisController.lift`` widens, and it does so through
        ``RestrictionStore.lift`` -- which is declared in the census and
        bracketed. So the widening that *does* matter is counted, and the
        epoch moves.

        The state ends at ``ACTIVE`` rather than at the ``REVALIDATING``
        that ``lift`` set: the allow below is observed by
        ``_observe_aegis``, which supplies the evidence for the one widening
        edge. The label following the verdict is the intended direction.
        """

        sdk, controller, capability, fingerprint = build()
        controller.suspend(fingerprint, key="incident", reason="probe")

        assert sdk.authorize(capability, ACTION, REQUEST).allowed is False
        assert controller.grant(fingerprint).state is AegisState.SUSPENDED

        before = sdk.authority_epoch.sample().finished
        removed = controller.lift(fingerprint, "incident")
        after_epoch = sdk.authority_epoch.sample().finished
        lifted_state = controller.grant(fingerprint).state

        outcome = sdk.authorize(capability, ACTION, REQUEST)
        state = controller.grant(fingerprint).state
        sdk.close()

        assert len(removed) == 1
        assert after_epoch > before, (
            "AegisController.lift widened authority without moving the "
            "epoch; RestrictionStore.lift's bracket is what makes the "
            "grant writes safe to leave unbracketed"
        )
        assert lifted_state is AegisState.REVALIDATING
        assert outcome.allowed is True
        assert state is AegisState.ACTIVE

    def test_a_forged_allow_does_not_move_the_grant(self) -> None:
        """Evidence must be a canonical verdict, not an allow-shaped object.

        Not strictly about the census, but it is the other half of why the
        grant writes are safe: the one widening edge in the machine accepts
        nothing this test can construct.
        """

        sdk, controller, capability, fingerprint = build()
        controller.suspend(fingerprint, key="incident", reason="probe")

        class Forged:
            allowed = True
            reason = "forged"
            capability_fingerprint = fingerprint

        before = controller.grant(fingerprint).state
        moved = controller.observe_authorization(fingerprint, Forged())
        sdk.close()

        assert before is AegisState.SUSPENDED
        assert moved.state is AegisState.SUSPENDED


class TestTheSourceSupportsTheClaim:
    """Two structural facts the behavioural tests rely on."""

    def test_no_controller_method_removes_a_grant(self) -> None:
        """``tracked()`` can only become more true.

        It reads ``_grants`` for truthiness, and the gate treats ``True``
        as "run the Aegis checks". A shrinking dict could flip it to
        ``False`` and skip them, which would be a widening -- so the
        absence of any removal is what makes reading ``_grants`` at all
        acceptable from the authorization path.
        """

        path = (
            pathlib.Path(AegisController.__module__.replace(".", "/"))
            .with_suffix(".py")
        )
        tree = ast.parse(path.read_text(encoding="utf-8"))

        removals: list[str] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Delete):
                for target in node.targets:
                    if "_grants" in ast.unparse(target):
                        removals.append(ast.unparse(node))
            if isinstance(node, ast.Call):
                rendered = ast.unparse(node)
                if "_grants.clear" in rendered or "_grants.pop" in rendered:
                    removals.append(rendered)

        assert not removals, removals

    def test_the_census_does_not_name_a_grant_write(self) -> None:
        """The absence this file justifies, asserted rather than assumed.

        If someone later declares one of the grant writes in the census,
        the invariant will demand a bracket for it and this file's
        reasoning no longer describes the code -- so the mismatch should
        surface here as a prompt to re-read it.
        """

        named = {
            name
            for module, name in WIDENING_WRITES
            if "aegis" in module
        }

        assert named == {
            "RestrictionStore.lift",
            "RestrictionStore.clear",
        }, named

