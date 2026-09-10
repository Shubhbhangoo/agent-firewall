"""v2.6: the boundary returns a verdict, or it is not a boundary.

``authorize()`` is a function that returns an ``AuthorizationResult``.
That is not a style preference -- it is the whole interface between a
caller and the firewall's judgement. An exception in its place is not a
denial. It is the *absence* of a decision, and the difference shows up in
two places at once:

* The caller has no verdict. A caller that wraps the boundary in
  ``except Exception`` and continues has been handed an unauthorized
  request with nothing attached saying so.
* The firewall has no record. Every write ``_apply_denial`` performs --
  the audit trace, the security context's denial counter, the risk
  context's ``record_denial``, the DENIED lifecycle event -- is skipped.

The second is the security consequence, and it is easy to miss because the
first looks like fail-closed. Nothing is allowed, so nothing is widened.
But risk escalation is *driven* by accumulated denials: enough of them and
``RiskContext.can_authorize`` starts refusing on its own. A failure mode
that refuses a request without counting it is a way to be refused
indefinitely and never accumulate the state those refusals owe the next
request. The narrowing that should have happened did not.

This file was written after a sweep found two such escapes. The sweep
sabotaged one public method at a time on every store the boundary reads
and asked whether a verdict still came back:

* ``SemanticChainContext.begin_authorization`` raising
  ``SemanticBudgetExceeded`` -- the cumulative amount ceiling, on the
  bundled class.
* ``SecurityContext.authorize_and_record`` raising
  ``SecurityContextError`` -- **on the shipped path, with no subclassing
  at all.** It reloads persisted budget state from disk inside the
  terminal gate, and a truncated file, a failed integrity hash, or an
  ``OSError`` on the atomic replace all raise. ``SecurityBudgetExceeded``
  is a subclass of ``SecurityContextError``, so the gate caught the one
  member of the family somebody had in mind and let the rest out.

Both are now denials. The tests below are in two halves: the specific
cases that were found, pinned by the concrete attack that found them, and
a total sweep that fails on a *new* escape rather than only on these two.
"""

from __future__ import annotations

import inspect
import json
import os

import pytest

from firewall.aegis import AegisController
from firewall.aegis.restriction import RestrictionStore
from firewall.continuous_auth.monitor import MonitoringConfig
from firewall.key_management import IssuerTrustStore
from firewall.refusal_state import RefusalState
from firewall.risk_context import RiskContext
from firewall.sdk import FirewallSDK
from firewall.security_context import SecurityContext
from firewall.semantic_chain import SemanticChainContext

ACTION = "payments.transfer"
REQUEST = {"amount": 1}

#: Every store the boundary reads while a verdict is still being decided.
#:
#: Swept by class, but sabotaged on the *live instance* the SDK wired --
#: see :func:`sabotage`. Substituting a subclass at construction time would
#: have meant guessing each store's constructor, and worse, would have
#: tested a wiring nobody ships. ``IssuerTrustStore`` is the case that
#: makes the difference: it is reached through the SDK's own accessor, not
#: passed to a gate, so a constructor-substitution sweep would have missed
#: it entirely.
SWEPT = (
    RestrictionStore,
    RefusalState,
    RiskContext,
    SecurityContext,
    SemanticChainContext,
    AegisController,
    IssuerTrustStore,
)


class Boom(RuntimeError):
    """Caught by name nowhere in the authorization path."""


def public_methods(cls):
    return sorted(
        name
        for name, value in vars(cls).items()
        if not name.startswith("_") and inspect.isfunction(value)
    )


def sabotage(instance, method) -> None:
    """Make one method of one live store raise, in place.

    ``__class__`` assignment rather than ``setattr``, because several of
    these stores are frozen dataclasses or use ``__slots__``, and because
    the point is to leave the SDK's wiring exactly as it was built. The
    replacement declares ``__slots__ = ()`` so the object layout is
    unchanged and the assignment is legal.
    """

    cls = type(instance)

    def explode(self, *args, **kwargs):
        raise Boom(f"{cls.__name__}.{method} is unreadable")

    instance.__class__ = type(
        f"Raising{cls.__name__}",
        (cls,),
        {method: explode, "__slots__": ()},
    )


def estate(*, state_path=None):
    """A fully wired, working SDK, plus the stores it wired.

    Every optional context is attached, because a store the SDK never
    holds cannot be swept -- and an unattached context makes its gate
    abstain, which would turn the sweep green for the wrong reason.
    """

    controller = AegisController()
    sdk = FirewallSDK(
        aegis=controller,
        continuous_auth_config=MonitoringConfig(
            enable_periodic_revalidation=False,
        ),
    )
    sdk.set_risk_context(RiskContext())
    sdk.set_semantic_context(
        SemanticChainContext(agent="probe-agent")
    )
    sdk.set_security_context(
        SecurityContext(agent="probe-agent", state_path=state_path)
    )

    key = sdk.generate_key("v26-totality")
    capability = sdk.issue(
        agent="probe-agent",
        capability="payments.*",
        private_key=key.private_key,
        constraints={"amount_max": 1000},
    )
    controller.register(
        sdk.fingerprint(capability),
        agent_id=capability.agent_id,
        capability=capability.capability,
    )

    wired = {
        RestrictionStore: controller._store,
        RefusalState: sdk.refusal_state,
        RiskContext: sdk.risk_context,
        SecurityContext: sdk.security_context,
        SemanticChainContext: sdk.semantic_context,
        AegisController: controller,
        IssuerTrustStore: sdk.issuer_trust_store,
    }

    return sdk, capability, wired


class TestTheSemanticBudgetDenies:
    """The first escape: a ceiling crossed by the bundled class."""

    def build(self, ceiling):
        sdk, capability, _ = estate()
        sdk.set_semantic_context(
            SemanticChainContext(
                agent="probe-agent",
                max_total_amount=float(ceiling),
            )
        )
        return sdk, capability, sdk.risk_context

    def test_crossing_the_ceiling_returns_a_denial(self) -> None:
        """It used to raise ``SemanticBudgetExceeded`` out of authorize()."""

        sdk, capability, _ = self.build(2)

        verdicts = [
            sdk.authorize(capability, ACTION, REQUEST) for _ in range(4)
        ]
        sdk.close()

        assert [outcome.allowed for outcome in verdicts] == [
            True,
            True,
            False,
            False,
        ]
        for outcome in verdicts[2:]:
            assert outcome.reason.startswith("semantic_budget_exceeded")

    def test_the_denial_is_recorded_like_any_other(self) -> None:
        """The half that made the escape a security defect, not a bug.

        A raise skipped ``_apply_denial`` entirely, so the risk context saw
        nothing. Asserting the verdict alone would pass over the thing that
        made this worth fixing.
        """

        sdk, capability, risk = self.build(1)

        for _ in range(3):
            sdk.authorize(capability, ACTION, REQUEST)

        snapshot = risk.snapshot("probe-agent")
        sdk.close()

        assert snapshot.denial_count == 2, (
            "the semantic budget denial did not reach the risk context; a "
            "caller could be refused indefinitely without ever "
            "accumulating the state those refusals are supposed to produce"
        )

    def test_a_rejected_request_does_not_consume_the_ceiling(self) -> None:
        """The reservation is rolled back, so the budget is not leaked."""

        sdk, capability, _ = self.build(2)

        for _ in range(5):
            sdk.authorize(capability, ACTION, REQUEST)

        total = sdk.semantic_context.total_amount()
        sdk.close()

        assert total == 2.0


class TestUnreadableBudgetStateDenies:
    """The second escape, and the one reachable with nothing subclassed."""

    def build(self, tmp_path):
        state_path = os.path.join(str(tmp_path), "budget.json")
        sdk, capability, _ = estate(state_path=state_path)
        return sdk, capability, sdk.risk_context, state_path

    def test_a_failed_integrity_hash_is_a_denial(self, tmp_path) -> None:
        """Tamper with the persisted budget; the boundary must still answer.

        ``authorize_and_record`` reloads from disk inside the terminal gate
        so a sibling process's spend is not lost. That load raises
        ``SecurityContextError`` on a hash mismatch, and nothing caught it:
        an attacker with write access to ``state_path`` -- not the key, not
        the capability -- made every authorization raise.
        """

        sdk, capability, risk, state_path = self.build(tmp_path)

        assert sdk.authorize(capability, ACTION, REQUEST).allowed

        with open(state_path, "r", encoding="utf-8") as handle:
            document = json.load(handle)
        document["payload"]["action_count"] = 0
        with open(state_path, "w", encoding="utf-8") as handle:
            json.dump(document, handle)

        outcome = sdk.authorize(capability, ACTION, REQUEST)
        snapshot = risk.snapshot("probe-agent")
        sdk.close()

        assert outcome.allowed is False
        assert outcome.reason == (
            "security_state_unavailable:SecurityContextError"
        )
        assert snapshot.denial_count == 1

    def test_a_truncated_state_file_is_a_denial(self, tmp_path) -> None:
        """The same, by a route that needs no knowledge of the format."""

        sdk, capability, _, state_path = self.build(tmp_path)

        assert sdk.authorize(capability, ACTION, REQUEST).allowed

        with open(state_path, "w", encoding="utf-8") as handle:
            handle.write("{")

        outcome = sdk.authorize(capability, ACTION, REQUEST)
        sdk.close()

        assert outcome.allowed is False
        assert outcome.reason.startswith("security_state_unavailable")

    def test_unreadable_state_never_becomes_permission(
        self, tmp_path
    ) -> None:
        """The direction that must never invert.

        Corrupting the file that records how much budget has been spent is
        an obvious thing to try if the hoped-for result is a reset ceiling.
        The store already refuses to guess -- it raises rather than
        defaulting to zero -- and the boundary must turn that refusal into
        a denial rather than an exception *or* an allow.
        """

        sdk, capability, _, state_path = self.build(tmp_path)
        sdk.security_context.max_actions = 1

        assert sdk.authorize(capability, ACTION, REQUEST).allowed

        with open(state_path, "w", encoding="utf-8") as handle:
            handle.write('{"payload": {"action_count": 0}, "x": 1}')

        outcome = sdk.authorize(capability, ACTION, REQUEST)
        sdk.close()

        assert outcome.allowed is False


class _FailingRollback:
    """The bundled transaction, wrapped in a rollback that raises.

    ``abort`` is delegated to the real one *before* raising, so the
    context lock is released and the estate stays usable. The leaked lock
    is not what is under test; the escape is.
    """

    def __init__(self, inner) -> None:
        self._inner = inner

    def commit(self) -> None:
        self._inner.commit()

    def abort(self) -> None:
        self._inner.abort()
        raise Boom("the reservation could not be rolled back")


class _HostileRollbackContext(SemanticChainContext):
    """A semantic context whose transactions cannot be rolled back.

    Injected rather than sabotaged in place, because a transaction is not
    a store the SDK holds. It is constructed inside the gate and handed
    straight back, so :func:`sabotage` cannot reach it and the sweep
    below never sees it -- which is why this one had to be found by
    reading the gate rather than by running the sweep.
    """

    def begin_authorization(self, **kwargs):
        return _FailingRollback(
            super().begin_authorization(**kwargs)
        )


def rollback_estate(*, agent: str = "probe-agent"):
    """The wired estate, with rollback made impossible.

    ``agent`` names the *security* context's agent. Passing anything
    other than ``probe-agent`` reaches the agent-mismatch denial, which
    is the shipped denial nearest the transaction: it needs no sabotage
    at all, so the only hostile component in that test is the rollback.
    """

    sdk, capability, wired = estate()
    sdk.set_semantic_context(
        _HostileRollbackContext(agent="probe-agent")
    )
    sdk.set_security_context(SecurityContext(agent=agent))
    wired[SecurityContext] = sdk.security_context
    wired[SemanticChainContext] = sdk.semantic_context

    return sdk, capability, wired


class TestARollbackThatRaisesLosesNoDenial:
    """The last unguarded mutation in the terminal gate.

    ``_gate_transaction`` opens a semantic transaction before it finishes
    deciding, so every denial after that point must roll it back first.
    That rollback used to be an unguarded call, and its callers are the
    ``except`` handlers whose entire purpose is to stop an exception
    replacing a verdict -- an ``abort`` that raised defeated them exactly
    where they were supposed to work. The gate caught the injected
    failure, converted it into a denial, and then lost the denial on the
    way out.

    A failed rollback is not re-decided. The request is already refused
    and there is no narrower answer available. What it must not be is
    silent: a reservation that did not roll back is state the *next*
    request will be judged against, so the exception's name is attached
    to the denial under ``rollback_error``.
    """

    def test_the_denial_survives_a_rollback_that_raises(self) -> None:
        sdk, capability, _ = rollback_estate(agent="a-stranger")

        try:
            outcome = sdk.authorize(capability, ACTION, REQUEST)
        except Exception as exc:  # noqa: BLE001 - that is the finding
            pytest.fail(
                f"a failed rollback raised {type(exc).__name__} out of "
                "authorize(). The caller has no verdict, and none of the "
                "writes _apply_denial performs happened."
            )
        finally:
            sdk.close()

        assert outcome.allowed is False
        assert outcome.reason == "security_context_agent_mismatch"

    def test_the_failed_rollback_is_named_on_the_denial(self) -> None:
        sdk, capability, _ = rollback_estate(agent="a-stranger")
        outcome = sdk.authorize(capability, ACTION, REQUEST)
        sdk.close()

        assert outcome.trace["rollback_error"] == "Boom"
        # Its own key. A lost audit record and a reservation that would
        # not roll back call for different responses, and reporting both
        # as ``evidence_error`` would tell an operator to go looking in
        # the wrong place.
        assert "evidence_error" not in outcome.trace

    def test_an_injected_gate_failure_and_a_failed_rollback_both_land(
        self,
    ) -> None:
        """The sharp case: the guard and the rollback fail together.

        ``SecurityContext.authorize_and_record`` raising is one of the two
        escapes this file was written for. Its handler denies with
        ``security_state_unavailable`` -- and then called the rollback. So
        the fix had to hold with *both* halves hostile, or the handler
        that closed the first escape would have been reopened by the
        second.
        """

        sdk, capability, wired = rollback_estate()
        sabotage(wired[SecurityContext], "authorize_and_record")

        outcome = sdk.authorize(capability, ACTION, REQUEST)
        sdk.close()

        assert outcome.allowed is False
        assert "security_state_unavailable" in outcome.reason
        assert outcome.trace["rollback_error"] == "Boom"

    def test_a_rollback_that_is_never_needed_changes_nothing(self) -> None:
        """Calibration.

        The two tests above would pass against an estate that refuses
        everything, and an unrollbackable transaction is a plausible way
        to build one. On the allow path ``commit`` runs and ``abort`` is
        never called, so the hostile rollback is invisible -- which is
        also the honest statement of scope: this guards the denial path,
        it does not make a failed rollback harmless.
        """

        sdk, capability, _ = rollback_estate()

        outcome = sdk.authorize(capability, ACTION, REQUEST)
        sdk.close()

        assert outcome.allowed is True
        assert "rollback_error" not in (outcome.trace or {})


class TestNoStoreFailureEscapesTheBoundary:
    """The sweep, so the next escape fails here rather than in production."""

    @pytest.mark.parametrize(
        "qualified",
        [
            f"{cls.__name__}.{method}"
            for cls in SWEPT
            for method in public_methods(cls)
        ],
    )
    def test_a_raising_store_method_still_yields_a_verdict(
        self, qualified
    ) -> None:
        """One method sabotaged, one authorization, one required outcome.

        Not every method is reached -- a single authorization touches a
        handful, and the rest produce the ordinary allow. The assertion is
        only about what must *not* happen: no exception may take the place
        of a verdict. A method that is never called passes trivially, and
        that is correct; the test exists to fail when a method that *is*
        called stops being guarded.
        """

        name, method = qualified.split(".", 1)
        cls = next(entry for entry in SWEPT if entry.__name__ == name)

        sdk, capability, wired = estate()
        sabotage(wired[cls], method)

        try:
            outcome = sdk.authorize(capability, ACTION, REQUEST)
        except Exception as exc:  # noqa: BLE001 - that is the finding
            pytest.fail(
                f"{qualified} raised {type(exc).__name__} out of "
                "authorize(). The boundary returns a verdict or it is not "
                "a boundary: an exception in place of a denial leaves the "
                "caller with no decision and skips every write "
                "_apply_denial performs -- the audit trace, the denial "
                "counters, and the DENIED lifecycle event."
            )
        finally:
            try:
                sdk.close()
            except Exception:  # noqa: BLE001 - teardown, not the finding
                pass

        assert isinstance(outcome.allowed, bool)
        assert outcome.reason

    def test_the_sweep_reaches_the_gates(self) -> None:
        """The sweep must not be vacuous.

        Every method above could pass by never being called. This asserts
        that the reads the gates are known to make do produce a denial, so
        a wiring change that quietly stops attaching a store fails here
        instead of turning the whole sweep green.
        """

        expected = {
            (RestrictionStore, "excludes"): "aegis_state_unavailable",
            (RefusalState, "check_action"): "refusal_state_unavailable",
            (RiskContext, "can_authorize"): "risk_state_unavailable",
            (
                SecurityContext,
                "authorize_and_record",
            ): "security_state_unavailable",
            (
                SemanticChainContext,
                "begin_authorization",
            ): "semantic_state_unavailable",
            (AegisController, "tracked"): "aegis_state_unavailable",
            (IssuerTrustStore, "is_trusted"): "issuer_trust_unavailable",
        }

        for (cls, method), prefix in sorted(
            expected.items(), key=lambda item: item[0][0].__name__
        ):
            sdk, capability, wired = estate()
            sabotage(wired[cls], method)
            outcome = sdk.authorize(capability, ACTION, REQUEST)
            sdk.close()

            assert outcome.allowed is False, (
                f"sabotaging {cls.__name__}.{method} did not even deny; "
                "the gate that reads it is not running"
            )
            assert prefix in outcome.reason, (
                f"{cls.__name__}.{method} denied with {outcome.reason!r}, "
                f"expected a reason naming {prefix}"
            )

    def test_the_swept_list_covers_the_epoch_bound_stores(self) -> None:
        """The sweep and the mutator census must walk the same stores.

        If one grows a store the other does not have, the pair stops being
        a check on each other.
        """

        from tests.test_v2_6_mutator_census import STORES

        missing = sorted(
            cls.__name__ for cls in set(STORES) - set(SWEPT)
        )

        assert not missing, (
            f"epoch-bound but not swept for boundary escapes: {missing}"
        )
