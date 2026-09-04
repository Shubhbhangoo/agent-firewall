"""v2.6: every mutator on an epoch-bound store is classified.

The AUTHORITY_EPOCH_COVERAGE invariant checks two directions over the
source: a declared widening write opens an epoch interval, and every
epoch interval belongs to a declared widening write. Both directions are
about the writes someone already thought about.

This file covers the direction neither of them can: a *new* method. Add
``RestrictionStore.relax`` tomorrow, bracket nothing, and the invariant
stays green -- it has no entry to check and no bracket to object to. The
census in :data:`~firewall.authority_epoch.WIDENING_WRITES` is only as
complete as the last person to think about it.

So the classification here is total. Every public method on every store
the SDK binds to its authority epoch must appear in exactly one of:

* :data:`WIDENING` -- can return authority a previous state removed. Must
  be in ``WIDENING_WRITES``.
* :data:`NARROWING` -- can only remove authority or add an obligation.
  Must **not** be bracketed: bracketing a narrowing write would deny
  requests that the write itself makes stricter, which is a cost with no
  security return.
* :data:`NEUTRAL` -- reads, or writes that no canonical gate consults.
* :data:`WAIVED` -- classified with a reason that is not one of the above.

An unclassified method fails :meth:`TestEveryMutatorIsClassified.
test_no_store_method_is_unclassified` with its name. That is the whole
mechanism: the failure is a prompt to decide, and the decision is
recorded here where a reviewer reads it.

This is a maintenance gate, not a proof. It cannot tell whether a method
was classified *correctly* -- ``NEUTRAL`` on something that widens would
pass. What it removes is the silent case: nobody having looked.
"""

from __future__ import annotations

import inspect

import pytest

from firewall.aegis.restriction import RestrictionStore
from firewall.authority_epoch import WIDENING_WRITES
from firewall.key_management import IssuerTrustStore
from firewall.refusal_state import RefusalState
from firewall.risk_context import RiskContext
from firewall.security_context import SecurityContext
from firewall.semantic_chain import SemanticChainContext

#: Every class the SDK binds to its authority epoch.
#:
#: Checked against ``FirewallSDK._authority_epoch_stores()`` at runtime by
#: :meth:`TestEveryMutatorIsClassified.test_the_store_list_matches_the_sdk`,
#: so binding a new kind of store to the epoch without classifying its
#: methods fails here rather than passing unnoticed.
STORES = (
    IssuerTrustStore,
    RestrictionStore,
    RefusalState,
    RiskContext,
    SecurityContext,
    SemanticChainContext,
)

#: Writes that can return authority a previous state removed.
WIDENING = frozenset(
    {
        "IssuerTrustStore.trust",
        "RestrictionStore.clear",
        "RestrictionStore.lift",
        "RefusalState.clear",
        "RefusalState.clear_all",
        "RiskContext.reset",
        "SecurityContext.reset",
        "SemanticChainContext.reset",
    }
)

#: Writes that can only remove authority or add an obligation.
#:
#: Deliberately *not* epoch-bracketed. A narrowing write landing inside an
#: authorization is not a soundness problem: the request's reads were taken
#: against a state at least as permissive as the one that now holds, so the
#: allow is still one a serial history produces -- with a linearization
#: point before the write. Bracketing them would turn every suspension into
#: a burst of spurious denials for requests already in flight.
NARROWING = frozenset(
    {
        "IssuerTrustStore.revoke",
        "RestrictionStore.apply",
        "RefusalState.record",
        "RiskContext.record_critical",
        "RiskContext.record_denial",
        "RiskContext.record_escalation",
        "SecurityContext.record",
        "SecurityContext.record_denial",
    }
)

#: Reads, and writes no canonical gate consults.
NEUTRAL = frozenset(
    {
        "IssuerTrustStore.is_revoked",
        "IssuerTrustStore.is_trusted",
        "IssuerTrustStore.trusted_issuers",
        "RestrictionStore.any_suspended",
        "RestrictionStore.describe",
        "RestrictionStore.excludes",
        "RestrictionStore.fingerprints",
        "RestrictionStore.journal",
        "RestrictionStore.restrictions_for",
        "RestrictionStore.suspended",
        "RefusalState.check",
        "RefusalState.check_action",
        "RefusalState.is_refused",
        "RefusalState.reason",
        "RefusalState.size",
        "RefusalState.snapshot",
        "RiskContext.can_authorize",
        "RiskContext.level",
        "RiskContext.snapshot",
        "SecurityContext.check",
        "SecurityContext.has_used_capability",
        "SecurityContext.snapshot",
        "SemanticChainContext.snapshot",
        "SemanticChainContext.total_amount",
    }
)

#: Classified, with a reason that is none of the three above.
#:
#: Each entry names why. A waiver with no reason is indistinguishable from
#: an oversight, which is what this file exists to prevent.
WAIVED = {
    "SecurityContext.authorize_and_record": (
        "check-and-consume, called from inside the terminal gate. It "
        "narrows on success (budget spent) and is the last read the gate "
        "takes, so there is no later read for a widening to be compared "
        "against. Bracketing it would open an interval inside the very "
        "authorization the interval is meant to protect."
    ),
    "SemanticChainContext.authorize_and_record": (
        "same shape: check-and-record inside the terminal gate, narrowing "
        "on success."
    ),
    "SemanticChainContext.begin_authorization": (
        "opens a transaction and hands back a handle that either commits "
        "or aborts. Narrowing while open -- the reserved amount is "
        "unavailable to anyone else -- and its lock is the one the epoch "
        "comparison is nested inside, so bracketing it would invert the "
        "lock order the boundary depends on."
    ),
    "SecurityContext.close": (
        "releases the file lock and stops persistence. Affects durability "
        "of accumulated state, not the authority any gate reads from it."
    ),
}


def public_methods(cls) -> tuple[str, ...]:
    """Qualified names of ``cls``'s own public methods and properties.

    Only ``vars(cls)`` -- inherited members belong to the class that
    defines them, and attributing them here would classify the same method
    once per subclass.
    """

    return tuple(
        sorted(
            f"{cls.__name__}.{name}"
            for name, value in vars(cls).items()
            if not name.startswith("_")
            and (
                inspect.isfunction(value)
                or isinstance(value, property)
            )
        )
    )


ALL_METHODS = tuple(
    name for cls in STORES for name in public_methods(cls)
)


class TestEveryMutatorIsClassified:
    """The gate itself."""

    @pytest.mark.parametrize("method", ALL_METHODS)
    def test_no_store_method_is_unclassified(self, method):
        """Every public method on a bound store has a classification.

        The failure message is the point: it names the method, and the
        person reading it has to decide whether the new write can return
        authority a previous state removed. If it can, it goes in
        ``WIDENING`` *and* in ``WIDENING_WRITES``, and the invariant then
        requires a bracket.
        """

        buckets = [
            name
            for name, bucket in (
                ("WIDENING", WIDENING),
                ("NARROWING", NARROWING),
                ("NEUTRAL", NEUTRAL),
                ("WAIVED", WAIVED),
            )
            if method in bucket
        ]

        assert buckets, (
            f"{method} is a new member of an epoch-bound store and is not "
            "classified. Decide whether it can return authority a "
            "previous state removed; add it to WIDENING (and to "
            "firewall.authority_epoch.WIDENING_WRITES, which requires a "
            "record_widening bracket), NARROWING, NEUTRAL, or WAIVED with "
            "a reason."
        )
        assert len(buckets) == 1, (
            f"{method} is classified {buckets}; the buckets are meant to "
            "be exclusive"
        )

    def test_no_classification_names_a_method_that_is_gone(self):
        """A stale entry states a claim about nothing."""

        classified = set(WIDENING | NARROWING | NEUTRAL) | set(WAIVED)
        stale = sorted(classified - set(ALL_METHODS))

        assert not stale, (
            f"classified but no longer defined on a bound store: {stale}"
        )

    def test_the_store_list_matches_the_sdk(self):
        """``STORES`` must be what the SDK actually binds.

        Binding a new kind of store to the epoch without adding it here
        would leave its methods unclassified *and* unnoticed, because the
        parametrization above only walks ``STORES``.
        """

        from firewall.aegis import AegisController
        from firewall.continuous_auth.monitor import MonitoringConfig
        from firewall.sdk import FirewallSDK

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
            SecurityContext(agent="probe-agent")
        )

        bound = {
            type(component)
            for component in sdk._authority_epoch_stores().values()
            if component is not None
        }

        sdk.close()

        unlisted = sorted(
            cls.__name__ for cls in bound - set(STORES)
        )

        assert not unlisted, (
            f"the SDK binds {unlisted} to its authority epoch, but this "
            "file does not classify their methods"
        )

    def test_every_widening_classification_is_in_the_census(self):
        """The two lists must not drift apart.

        ``WIDENING`` here is the classification; ``WIDENING_WRITES`` in the
        package is what the invariant enforces a bracket for. A method in
        the first and not the second is classified as dangerous and
        checked as though it were not.
        """

        declared = {name for _, name in WIDENING_WRITES}
        missing = sorted(WIDENING - declared)

        assert not missing, (
            "classified WIDENING but absent from "
            f"firewall.authority_epoch.WIDENING_WRITES: {missing}"
        )

    def test_no_narrowing_or_neutral_method_is_bracketed(self):
        """The reverse drift: a bracket where the classification says none.

        This is not a security failure -- an extra bracket only causes
        false denials -- but it is a contradiction between two documents,
        and the one that would be believed is the code.
        """

        declared = {name for _, name in WIDENING_WRITES}
        contradictions = sorted(
            declared & (NARROWING | NEUTRAL)
        )

        assert not contradictions, (
            "declared a widening write but classified NARROWING or "
            f"NEUTRAL: {contradictions}"
        )

    def test_every_waiver_gives_a_reason(self):
        for method, reason in sorted(WAIVED.items()):
            assert reason and len(reason) > 40, (
                f"{method} is waived without a usable reason"
            )
