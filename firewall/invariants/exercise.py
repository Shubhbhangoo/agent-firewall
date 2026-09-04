"""A canonically exercised estate, so all seventeen invariants can be run.

Eight of the seventeen invariants are claims about live state: a signed
delegation edge, an attenuation, a propagated revocation, an applied
policy transformation, a simulation that ran, an authority envelope
projected either side of a lineage edge, and a recorded Aegis history. A
fresh :class:`FirewallSDK` has none of them, so
``python -m firewall.invariants`` reports those seven ``UNVERIFIABLE``
and ``--strict`` fails on every run -- which makes the strict gate
useless in CI, because a gate that always fails is turned off.

This module supplies the missing state. :func:`canonical_estate` builds
an SDK that has issued, delegated, attenuated and revoked, plus a policy
history containing one real narrowing, entirely through the SDK's public
API. Nothing here reaches into a control-plane container, and nothing
here can grant authority: the estate is built by asking the firewall to
do things, and the invariant checks then read what happened.

**What a green exercised run means, and what it does not.** It means the
seventeen invariants hold over *this* estate: the algebra of narrowing, the
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

A second delegation hangs off the root and is never revoked. It exists
for ENVELOPE_MONOTONICITY: a revoked capability projects the *bottom*
envelope, bottom is contained in everything, and every other edge here
has a revoked endpoint -- so without this branch the containment claim
would be satisfied by an estate in which nothing was left to contain.

The Aegis half runs on that same branch, and runs the long way round on
purpose: register, narrow, lift, then ask the boundary. Only the last
step can return the grant to ``ACTIVE``, because ``REVALIDATING ->
ACTIVE`` is the one edge in the state machine that raises residual
authority and the only one that demands a canonical
``FirewallSDK.authorize()`` allow as evidence. Traversing it here is what
gives AEGIS_STATE_TRANSITIONS a real history to audit instead of an
algebra with nothing recorded under it. It is skipped -- not forced --
when the caller supplies an SDK with Aegis switched off, which is both
the default configuration and a legitimate one;
:attr:`Estate.aegis_exercised` says which happened.
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

    Both halves are needed for a full run: six of the seven state-
    dependent invariants read the SDK, and POLICY_NON_WIDENING reads the
    history. Bundling them means a caller cannot supply one and silently
    leave the other unverifiable.
    """

    sdk: FirewallSDK
    policy_history: tuple[tuple[Capability2, Capability2], ...]
    #: Agents whose authority the estate deliberately destroyed, so a
    #: caller can assert the revocation actually propagated.
    revoked_agents: tuple[str, ...] = ()
    #: Whether the Aegis lifecycle was exercised. ``False`` means the
    #: supplied SDK had Aegis switched off, so AEGIS_STATE_TRANSITIONS
    #: will report ``UNVERIFIABLE`` -- a true statement about that SDK
    #: rather than a defect in this module.
    aegis_exercised: bool = False

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
    otherwise a fresh in-memory one is created with Aegis switched on,
    because AEGIS_STATE_TRANSITIONS has nothing to audit without it.
    Either way the estate is built only through ``issue``, ``delegate``,
    ``attenuate``, ``revoke``, ``authorize`` and the Aegis controller's
    own API.

    Raises :class:`ExerciseError` if the firewall refuses a step or if
    revocation did not reach the grandchild -- the second is not an
    exercise failure but a REVOCATION_MONOTONICITY violation caught one
    layer early, and reporting it as a broken exerciser would be exactly
    backwards.
    """

    owned = sdk is None
    instance = (
        sdk if sdk is not None else FirewallSDK(aegis_enabled=True)
    )
    aegis_exercised = False

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

        # Deliberately not revoked, and deliberately a delegation rather
        # than an attenuation: ENVELOPE_MONOTONICITY needs one edge whose
        # two endpoints both project a non-bottom envelope, and a revoked
        # endpoint projects bottom.
        peer = instance.delegate(
            root,
            private_key,
            delegatee="agent-peer",
            constraints={
                "amount_max": 40,
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

        aegis_exercised = _exercise_aegis(instance, peer)
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
        aegis_exercised=aegis_exercised,
    )


#: Restriction key the exercised narrowing is written under, and lifted
#: under. One key, so the lift is unambiguous.
AEGIS_EXERCISE_KEY = "aegis:invariant-exercise"


def _exercise_aegis(
    sdk: FirewallSDK,
    capability: Any,
) -> bool:
    """Walk one grant through ``ISSUED -> NARROWED -> REVALIDATING -> ACTIVE``.

    Returns ``False`` without touching anything when the SDK has Aegis
    switched off. Aegis is opt-in and off by default, so a caller passing
    their own SDK is not doing anything wrong by not having it; forcing a
    controller onto their SDK would change the configuration under test,
    and reaching past ``sdk.aegis`` to install one would be exactly the
    control-plane access CONTROL_PLANE_INTEGRITY forbids.

    Raises :class:`ExerciseError` if the boundary denies the final
    authorization or if the grant does not end in ``ACTIVE``. Both mean
    the estate did not traverse the evidenced edge, and returning an
    estate that merely looks exercised would leave
    AEGIS_STATE_TRANSITIONS auditing a history with no widening in it --
    the one thing its evidence rule exists to constrain.
    """

    controller = sdk.aegis

    if controller is None:
        return False

    fingerprint = sdk.fingerprint(capability)

    controller.register(
        fingerprint,
        agent_id=capability.agent_id,
        capability=capability.capability,
    )

    # A real narrowing, then a real lift. The narrowing is what puts the
    # grant below ACTIVE in the residual order; the lift only removes the
    # obstacle and cannot restore standing, which is why the authorize
    # below is not optional.
    controller.narrow(
        fingerprint,
        key=AEGIS_EXERCISE_KEY,
        reason="invariant exercise: narrowed to establish a real edge",
        constraints={"amount_max": 5},
        trigger="invariant_exercise",
    )
    controller.lift(
        fingerprint,
        AEGIS_EXERCISE_KEY,
        reason="invariant exercise: obstacle removed, standing not restored",
    )

    decision = sdk.authorize(
        capability,
        "payments.send",
        # Both constraint keys, because ``_check_constraints`` denies on a
        # key the request omits: ``amount_max`` reads ``amount``, and a
        # list constraint requires the request's value to be a member.
        {"amount": 10, "allowed_actions": "payments.send"},
    )

    if not decision.allowed:
        raise ExerciseError(
            f"the exercised grant could not be re-authorized after its "
            f"restriction was lifted ({decision.reason}), so the "
            f"REVALIDATING -> ACTIVE edge was never traversed"
        )

    grant = controller.grant(fingerprint)

    if grant is None or grant.state.value != "active":
        state = "missing" if grant is None else grant.state.value
        raise ExerciseError(
            f"the boundary allowed but the grant is {state} rather than "
            f"active, so a canonical allow did not restore standing"
        )

    return True


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
    reach, and the strict gate is quietly narrower than seventeen.
    """

    from firewall.invariants.model import InvariantStatus

    return tuple(
        item.name
        for item in results
        if item.status is InvariantStatus.UNVERIFIABLE
    )
