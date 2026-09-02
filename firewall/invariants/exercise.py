"""A canonically exercised estate, so all eleven invariants can be run.

Five of the eleven invariants are claims about live state: a signed
delegation edge, an attenuation, a propagated revocation, an applied
policy transformation, a simulation that ran. A fresh :class:`FirewallSDK`
has none of them, so ``python -m firewall.invariants`` reports those five
``UNVERIFIABLE`` and ``--strict`` fails on every run -- which makes the
strict gate useless in CI, because a gate that always fails is turned
off.

This module supplies the missing state. :func:`canonical_estate` builds
an SDK that has issued, delegated, attenuated and revoked, plus a policy
history containing one real narrowing, entirely through the SDK's public
API. Nothing here reaches into a control-plane container, and nothing
here can grant authority: the estate is built by asking the firewall to
do things, and the invariant checks then read what happened.

**What a green exercised run means, and what it does not.** It means the
eleven invariants hold over *this* estate: the algebra of narrowing, the
propagation of revocation, the isolation of simulation and the structural
claims about the source tree all survive being exercised. It does not
certify a deployment. A production estate has capabilities, policies and
lineages this module never constructs, and an invariant that holds here
can be violated there -- which is why
:func:`firewall.invariants.check_all` still accepts a caller's own SDK
and policy history, and why an operator gating a real system should pass
that instead.

The estate is deliberately small and deliberately awkward in the places
that matter. The revoked capability is in the *middle* of a chain, so
REVOCATION_MONOTONICITY has a descendant to propagate to rather than
being satisfied by a revoked leaf. The attenuation hangs off the root and
carries no signed parent fingerprint, so it is invisible to
DELEGATION_MONOTONICITY and visible to CAPABILITY_MONOTONICITY -- one
edge would otherwise leave the second invariant with nothing to examine.
Every constraint set repeats its parent's keys, because a child that
drops a key is widening and ``delegate`` refuses it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional, Sequence

from firewall.capability2 import Capability2
from firewall.sdk import FirewallSDK

#: Key id used for the canonical estate's signing key.
EXERCISE_KEY_ID = "invariant-exercise-key"

#: Stated on every report produced from a canonical estate. A caller that
#: prints the report without this line is overclaiming.
CANONICAL_ESTATE_CAVEAT = (
    "these results describe a canonically exercised estate built by "
    "firewall.invariants.exercise, not a production deployment"
)


class ExerciseError(RuntimeError):
    """The canonical estate could not be built.

    Raised rather than returning a half-built estate: an invariant suite
    run against an estate that is missing the state it is about would
    report ``UNVERIFIABLE`` and look like a wiring problem, when the real
    finding is that the SDK refused a step the firewall is supposed to
    allow.
    """


@dataclass(frozen=True)
class Estate:
    """An exercised SDK and the policy history that goes with it.

    Both halves are needed for a full run: four of the five state-
    dependent invariants read the SDK, and POLICY_NON_WIDENING reads the
    history. Bundling them means a caller cannot supply one and silently
    leave the other unverifiable.
    """

    sdk: FirewallSDK
    policy_history: tuple[tuple[Capability2, Capability2], ...]
    #: Agents whose authority the estate deliberately destroyed, so a
    #: caller can assert the revocation actually propagated.
    revoked_agents: tuple[str, ...] = ()

    def close(self) -> None:
        """Release the SDK's resources.

        Safe to call more than once, and never raises: a throwaway estate
        failing to close must not mask the finding the caller came for.
        """

        try:
            self.sdk.close()
        except Exception:  # noqa: BLE001 - teardown of a throwaway
            pass

    def __enter__(self) -> "Estate":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


def narrowing_policy_history() -> tuple[tuple[Capability2, Capability2], ...]:
    """One real narrowing transformation, as POLICY_NON_WIDENING needs.

    The narrowing is in two independent dimensions -- the action list
    loses a member and the delegation ceiling drops -- so a checker that
    only compared one of them would still see a narrowing here and could
    not pass by ignoring the other.
    """

    return (
        (
            Capability2(
                capability="payments.send",
                constraints={
                    "action": ["send", "refund"],
                    "lineage": {"delegation_depth": {"lte": 3}},
                },
            ),
            Capability2(
                capability="payments.send",
                constraints={
                    "action": ["send"],
                    "lineage": {"delegation_depth": {"lte": 1}},
                },
            ),
        ),
    )


def canonical_estate(
    sdk: Optional[FirewallSDK] = None,
) -> Estate:
    """Build the canonical exercised estate.

    Pass an ``sdk`` to exercise an SDK the caller already configured;
    otherwise a fresh in-memory one is created. Either way the estate is
    built only through ``issue``, ``delegate``, ``attenuate`` and
    ``revoke``.

    Raises :class:`ExerciseError` if the firewall refuses a step or if
    revocation did not reach the grandchild -- the second is not an
    exercise failure but a REVOCATION_MONOTONICITY violation caught one
    layer early, and reporting it as a broken exerciser would be exactly
    backwards.
    """

    owned = sdk is None
    instance = sdk if sdk is not None else FirewallSDK()

    try:
        private_key = instance.generate_key(EXERCISE_KEY_ID).private_key

        root = instance.issue(
            agent="agent-root",
            capability="payments.send",
            constraints={
                "amount_max": 100,
                "allowed_actions": ["payments.send"],
            },
        )

        child = instance.delegate(
            root,
            private_key,
            delegatee="agent-child",
            constraints={
                "amount_max": 50,
                "allowed_actions": ["payments.send"],
            },
        ).child

        # No signed parent fingerprint: this edge exists for
        # CAPABILITY_MONOTONICITY, which is the only invariant that can
        # see it.
        instance.attenuate(
            root,
            private_key,
            constraints={
                "amount_max": 25,
                "allowed_actions": ["payments.send"],
            },
        )

        grandchild = instance.delegate(
            child,
            private_key,
            delegatee="agent-grandchild",
            constraints={
                "amount_max": 10,
                "allowed_actions": ["payments.send"],
            },
        ).child

        # Mid-chain, so the revocation has somewhere to propagate.
        instance.revoke(child, reason="invariant exercise")

        if not instance.is_effectively_revoked(grandchild):
            raise ExerciseError(
                "revoking agent-child left agent-grandchild usable, so "
                "REVOCATION_MONOTONICITY does not hold; the estate is "
                "correct and the firewall is not"
            )
    except ExerciseError:
        if owned:
            _quiet_close(instance)
        raise
    except Exception as error:  # noqa: BLE001 - reported, not swallowed
        if owned:
            _quiet_close(instance)
        raise ExerciseError(
            f"the canonical estate could not be built: "
            f"{type(error).__name__}: {error}"
        ) from error

    return Estate(
        sdk=instance,
        policy_history=narrowing_policy_history(),
        revoked_agents=("agent-child", "agent-grandchild"),
    )


def check_exercised(
    sdk: Optional[FirewallSDK] = None,
) -> Any:
    """Run the full suite against a canonical estate and return the report.

    The estate is closed before returning, so the report cannot be used
    to reach back into the SDK it described. It is an
    :class:`~firewall.invariants.model.InvariantReport` -- data, with no
    authority attached.
    """

    from firewall.invariants.registry import check_all

    with canonical_estate(sdk) as estate:
        return check_all(
            estate.sdk,
            policy_history=list(estate.policy_history),
        )


def _quiet_close(sdk: FirewallSDK) -> None:
    try:
        sdk.close()
    except Exception:  # noqa: BLE001 - teardown of a throwaway
        pass


def unexercised_names(
    results: Sequence[Any],
) -> tuple[str, ...]:
    """Names of invariants still unverifiable after exercising.

    A non-empty result from a canonical run is a finding about this
    module: a state-dependent invariant exists that the estate does not
    reach, and the strict gate is quietly narrower than eleven.
    """

    from firewall.invariants.model import InvariantStatus

    return tuple(
        item.name
        for item in results
        if item.status is InvariantStatus.UNVERIFIABLE
    )
