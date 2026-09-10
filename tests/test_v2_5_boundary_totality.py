"""v2.5: the canonical boundary decides, or it denies. It never raises.

``FirewallSDK.authorize`` is documented as total -- "the authorization
path never raises in place of deciding" -- and v2.4 shipped that claim in
the threat model, the invariant registry and the Aegis design notes. It
was false in nine reachable places, and the FAIL_CLOSED invariant stayed
green throughout because all eight of its probes were malformed *input*
against a *healthy* SDK. Nothing exercised a firewall that could not read
its own state.

Two directions of failure are pinned here, and they are not the same bug.

*An unreadable read must not become permissive.* Five dependencies the
boundary consults could raise, and the caller who wrapped ``authorize`` in
``except Exception`` and carried on was handed an unauthorized request
with no verdict attached. Each is now a denial that names the dependency.

*A denial must survive the loss of its own evidence.* The audit writes on
the denial paths could raise *after* the verdict existed, which destroyed
the denial. A denial now keeps its verdict and reports the loss in
``trace["evidence_error"]``; an allow that cannot be recorded becomes
``evidence_unavailable:...``, because an unrecorded allow is the one
verdict that must not be handed out quietly.

The headline finding has its own class. ``_gate_time`` skipped the expiry
check entirely -- silently, by abstaining -- whenever it could not read a
clock, and containment depended on the bundled verifier privately
consulting the same clock. Replace the verifier with a *correct* one that
leaves time to the firewall and an expired capability was authorized. See
:class:`TestExpiryCannotBeSkippedByAnUnreadableClock`.

Every attack here is reproduced through the public API. Nothing reaches
into a gate directly, because a gate called out of order proves nothing
about what ``authorize`` does.
"""

from __future__ import annotations

import dataclasses
import time
from typing import Any, Optional

import pytest

from firewall.sdk import FirewallSDK

ACTION = "payments.send"
CONSTRAINTS = {"amount_max": 100}
WITHIN = {"amount": 10}
BEYOND = {"amount": 10_000}


class Unreadable:
    """One dependency whose named reads raise instead of answering.

    Everything else forwards to the real object. Replacing a subsystem
    with a stub would prove much less: the stub's whole behaviour differs,
    so a denial afterwards could have any cause. Here exactly one question
    becomes unanswerable and the rest of the dependency still works.

    Attribute *writes* forward too. The SDK refreshes verifier trust in
    place, and a wrapper that swallowed those writes would drift from the
    object it wraps and make the probe measure the drift instead.
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


def scratch(**kwargs: Any) -> tuple[FirewallSDK, Any]:
    """A fresh SDK and a capability that its own boundary will allow."""

    sdk = FirewallSDK(**kwargs)
    sdk.generate_key("v25-probe")

    capability = sdk.issue(
        agent="probe-agent",
        capability=ACTION,
        constraints=dict(CONSTRAINTS),
    )

    return sdk, capability


def sdk_verdict(
    sdk: FirewallSDK,
    capability: Any,
    request: dict,
    refusal_scope: str = "action",
) -> tuple[bool, str]:
    """``(allowed, reason)`` for one call, so verdicts compare as values.

    Comparing whole results would compare traces and timings too; comparing
    ``allowed`` alone would let a denial for one reason stand in for a
    denial for another, which is exactly the substitution the refusal tests
    below exist to detect.
    """

    result = sdk.authorize(
        capability,
        action=ACTION,
        request=dict(request),
        refusal_scope=refusal_scope,
    )

    return result.allowed, result.reason


#: ``(attribute, read, refusal_scope, expected_reason_prefix)`` for every
#: security-relevant read ``authorize`` performs. Established by spying on
#: a real authorization rather than by reading the source: ``replay``,
#: ``keys``, ``north_star`` and the delegation budgets are absent because
#: the boundary never consults them, and a probe against a dependency that
#: is never read would pass while proving nothing.
UNREADABLE_READS = (
    ("verifier", "verify", "action", "verification_error"),
    ("verifier", "clock", "action", "clock_unavailable:"),
    (
        "refusal_state",
        "check_action",
        "action",
        "refusal_state_unavailable:",
    ),
    (
        "refusal_state",
        "check",
        "request",
        "refusal_state_unavailable:",
    ),
    (
        "revocation",
        "is_revoked",
        "action",
        "revocation_state_unavailable:",
    ),
    (
        "issuer_trust_store",
        "is_trusted",
        "action",
        "issuer_trust_unavailable:",
    ),
    (
        "delegation_lineage",
        "chain",
        "action",
        "revocation_state_unavailable:",
    ),
    ("lifecycle", "record", "action", "evidence_unavailable:"),
)


class TestAnUnreadableDependencyIsADenial:
    """Every read the boundary makes can fail. None of them may escape."""

    @pytest.mark.parametrize(
        "attribute,read,scope,expected",
        UNREADABLE_READS,
        ids=[f"{a}.{r}" for a, r, _, _ in UNREADABLE_READS],
    )
    def test_an_unreadable_read_denies_and_names_the_dependency(
        self,
        attribute: str,
        read: str,
        scope: str,
        expected: str,
    ):
        sdk, capability = scratch()

        # The control runs on the instance about to be sabotaged. Without
        # it a denial afterwards would prove nothing: an SDK that denied
        # for an unrelated reason satisfies the assertion below while the
        # dependency failure goes unexercised.
        control = sdk.authorize(
            capability,
            action=ACTION,
            request=dict(WITHIN),
            refusal_scope=scope,
        )
        assert control.allowed is True, control.reason

        setattr(
            sdk,
            attribute,
            Unreadable(getattr(sdk, attribute), read),
        )

        result = sdk.authorize(
            capability,
            action=ACTION,
            request=dict(WITHIN),
            refusal_scope=scope,
        )

        assert result.allowed is False
        assert result.reason.startswith(expected), result.reason

    def test_no_unreadable_read_anywhere_produces_an_allow(self):
        """The sweep-wide property, asserted as one statement.

        The per-read tests above pin *which* denial each failure produces,
        and a future change could satisfy every one of them individually
        while introducing a tenth read that fails open. This asserts the
        property the others only imply: across the whole sweep, zero
        allows and zero escapes.
        """

        allows: list[str] = []
        escapes: list[str] = []

        for attribute, read, scope, _ in UNREADABLE_READS:
            sdk, capability = scratch()
            setattr(
                sdk,
                attribute,
                Unreadable(getattr(sdk, attribute), read),
            )

            try:
                result = sdk.authorize(
                    capability,
                    action=ACTION,
                    request=dict(WITHIN),
                    refusal_scope=scope,
                )
            except Exception as error:
                escapes.append(
                    f"{attribute}.{read}: {type(error).__name__}"
                )
                continue

            if result.allowed:
                allows.append(f"{attribute}.{read}: {result.reason}")

        assert escapes == []
        assert allows == []


class TestADenialSurvivesTheLossOfItsOwnEvidence:
    """The worse direction: the verdict existed and the write destroyed it.

    An allow that cannot be recorded is withheld -- an unrecorded allow is
    the one verdict that must not be handed out quietly. A *denial* that
    cannot be recorded keeps its verdict, because the alternative is that
    an audit-log failure converts a refusal into an exception, and a
    caller that treats an exception as "try something else" has been given
    strictly more room than the refusal allowed.
    """

    def test_a_denial_keeps_its_verdict_when_the_log_is_unwritable(self):
        sdk, capability = scratch()
        sdk.lifecycle = Unreadable(sdk.lifecycle, "record")

        result = sdk.authorize(
            capability,
            action=ACTION,
            request=dict(BEYOND),
        )

        assert result.allowed is False
        assert result.reason == "constraint_denied"

    def test_the_evidence_loss_is_reported_rather_than_swallowed(self):
        sdk, capability = scratch()
        sdk.lifecycle = Unreadable(sdk.lifecycle, "record")

        result = sdk.authorize(
            capability,
            action=ACTION,
            request=dict(BEYOND),
        )

        # Contained is not the same as silent. The verdict is unchanged and
        # the fact that it was not written down travels with it.
        assert isinstance(result.trace, dict)
        assert result.trace["evidence_error"] == "RuntimeError"

    def test_an_unrecordable_allow_is_withheld(self):
        sdk, capability = scratch()
        sdk.lifecycle = Unreadable(sdk.lifecycle, "record")

        result = sdk.authorize(
            capability,
            action=ACTION,
            request=dict(WITHIN),
        )

        assert result.allowed is False
        assert result.reason == "evidence_unavailable:RuntimeError"


class TestTheBundledStoresReachTheSamePaths:
    """No mock required. Two shipped components fail exactly like this.

    Every test above installs a wrapper, which invites the reading that
    the whole defect class needed a hostile injected dependency to reach.
    It did not. A ``FirewallSDK`` built with a persistent store and then
    closed -- a process shutting down, a store handed out and reused after
    ``close()`` -- reaches the same code with nothing injected at all.
    """

    def test_a_closed_lifecycle_store_withholds_an_allow(self, tmp_path):
        sdk, capability = scratch(
            lifecycle_store_path=str(tmp_path / "lifecycle.db"),
        )

        control = sdk.authorize(
            capability, action=ACTION, request=dict(WITHIN)
        )
        assert control.allowed is True, control.reason

        sdk.lifecycle.close()

        result = sdk.authorize(
            capability, action=ACTION, request=dict(WITHIN)
        )

        assert result.allowed is False
        assert result.reason == (
            "evidence_unavailable:LifecycleStoreClosedError"
        )

    def test_a_closed_lifecycle_store_still_denies_an_over_ceiling_request(
        self, tmp_path
    ):
        sdk, capability = scratch(
            lifecycle_store_path=str(tmp_path / "lifecycle.db"),
        )
        sdk.lifecycle.close()

        result = sdk.authorize(
            capability, action=ACTION, request=dict(BEYOND)
        )

        assert result.allowed is False
        assert result.reason == "constraint_denied"
        assert result.trace["evidence_error"] == (
            "LifecycleStoreClosedError"
        )

    def test_a_closed_revocation_store_denies_rather_than_raising(
        self, tmp_path
    ):
        sdk, capability = scratch(
            revocation_store_path=str(tmp_path / "revocation.db"),
        )

        control = sdk.authorize(
            capability, action=ACTION, request=dict(WITHIN)
        )
        assert control.allowed is True, control.reason

        sdk._revocation_store.close()

        # An ``AttributeError`` from deep inside a closed sqlite3
        # connection is exactly the kind of failure that must not reach a
        # caller as an exception: it looks like a bug in the caller's code
        # rather than a refusal by the firewall.
        result = sdk.authorize(
            capability, action=ACTION, request=dict(WITHIN)
        )

        assert result.allowed is False
        assert result.reason == (
            "revocation_state_unavailable:AttributeError"
        )

    def test_a_closed_revocation_store_denies_a_hostile_request_too(
        self, tmp_path
    ):
        sdk, capability = scratch(
            revocation_store_path=str(tmp_path / "revocation.db"),
        )
        sdk._revocation_store.close()

        result = sdk.authorize(
            capability, action=ACTION, request=dict(BEYOND)
        )

        # Revocation is consulted before constraints, so the unreadable
        # store decides. Either denial is correct; an allow or a raise is
        # not, and that is what this pins.
        assert result.allowed is False


class SignatureOnlyVerifier:
    """Real Ed25519 verification, no opinion about time.

    Deliberately *not* a permissive stub. It rejects forgeries and it
    rejects capabilities edited after signing -- the assertions below prove
    that on the same object -- so it is a legitimate cryptographic trust
    root, not a handover of trust. The only thing it declines to do is
    enforce the validity window, which is the firewall's own gate.

    It forwards everything it does not override, including ``clock``, so
    that :meth:`TestExpiryCannotBeSkippedByAnUnreadableClock.test_the_replacement_verifier_is_a_real_trust_root`
    can establish it is a real trust root before the clock is taken away.
    """

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def verify(self, capability: Any, *args: Any, **kwargs: Any) -> bool:
        saved = self._inner.clock
        self._inner.clock = lambda: (
            capability.issued_at + capability.expires_at
        ) / 2.0
        try:
            return self._inner.verify(capability, *args, **kwargs)
        finally:
            self._inner.clock = saved


class TestExpiryCannotBeSkippedByAnUnreadableClock:
    """``_gate_time`` abstained when it could not read the time.

    That abstention was invisible under the bundled verifier, which
    consults the same clock and refuses on its own. So the expiry
    guarantee was being upheld by a component that never promised to
    uphold it, and the moment that component was replaced by a correct one
    with a different division of labour, expiry vanished: an expired
    capability came back ``allowed=True reason=authorized``.
    """

    @staticmethod
    def _expired_and_live(sdk: FirewallSDK) -> tuple[Any, Any]:
        now = time.time()
        expired = sdk.issue(
            agent="probe-agent",
            capability=ACTION,
            constraints=dict(CONSTRAINTS),
            issued_at=now - 100.0,
            expires_at=now - 50.0,
        )
        live = sdk.issue(
            agent="probe-agent",
            capability=ACTION,
            constraints=dict(CONSTRAINTS),
        )
        return expired, live

    def test_the_replacement_verifier_is_a_real_trust_root(self):
        """Without this, every assertion below is about a broken stub."""

        sdk, _ = scratch()
        expired, live = self._expired_and_live(sdk)
        foreign_sdk, _ = scratch()
        forged = foreign_sdk.issue(
            agent="probe-agent",
            capability=ACTION,
            constraints=dict(CONSTRAINTS),
        )
        tampered = dataclasses.replace(
            live,
            constraints={"amount_max": 10_000},
        )

        sdk.verifier = SignatureOnlyVerifier(sdk.verifier)

        assert (
            sdk.authorize(
                forged, action=ACTION, request=dict(WITHIN)
            ).allowed
            is False
        )
        assert (
            sdk.authorize(
                tampered, action=ACTION, request={"amount": 5_000}
            ).allowed
            is False
        )
        # And it still allows what it should, so the denials below are not
        # a verifier that refuses everything.
        assert (
            sdk.authorize(
                live, action=ACTION, request=dict(WITHIN)
            ).allowed
            is True
        )

    def test_a_clockless_verifier_does_not_authorize_an_expired_capability(
        self,
    ):
        sdk, _ = scratch()
        expired, _ = self._expired_and_live(sdk)

        inner = sdk.verifier
        signature_only = SignatureOnlyVerifier(inner)

        class Clockless:
            """A verifier object with no ``clock`` attribute at all."""

            def verify(
                self, capability: Any, *args: Any, **kwargs: Any
            ) -> bool:
                return signature_only.verify(
                    capability, *args, **kwargs
                )

        sdk.verifier = Clockless()
        assert getattr(sdk.verifier, "clock", None) is None

        result = sdk.authorize(
            expired, action=ACTION, request=dict(WITHIN)
        )

        assert result.allowed is False
        assert result.reason == "clock_unavailable:no_clock"

    @pytest.mark.parametrize(
        "label,clock,expected",
        (
            ("raises", None, "clock_unavailable:RuntimeError"),
            (
                "returns a string",
                lambda: "not-a-time",
                "clock_unavailable:ValueError",
            ),
            (
                "returns nan",
                lambda: float("nan"),
                "clock_unavailable:non_finite",
            ),
            (
                "returns -inf",
                lambda: float("-inf"),
                "clock_unavailable:non_finite",
            ),
        ),
    )
    def test_an_unusable_clock_reading_is_a_denial(
        self,
        label: str,
        clock: Any,
        expected: str,
    ):
        """``nan`` is the quiet one.

        A raising clock at least announces itself. ``nan`` compares false
        against every bound, so ``now >= expires_at`` and
        ``now < issued_at`` were both false and the gate fell through to
        the allow path having checked nothing.
        """

        sdk, _ = scratch()
        expired, _ = self._expired_and_live(sdk)

        if clock is None:

            def clock():  # type: ignore[misc]
                raise RuntimeError("clock is unreachable")

        sdk.verifier.clock = clock

        result = sdk.authorize(
            expired, action=ACTION, request=dict(WITHIN)
        )

        assert result.allowed is False
        assert result.reason == expected, label

    def test_a_healthy_clock_still_reports_expiry_the_same_way(self):
        """The fix must not have replaced the real reasons with its own."""

        sdk, _ = scratch()
        expired, live = self._expired_and_live(sdk)

        assert (
            sdk.authorize(
                expired, action=ACTION, request=dict(WITHIN)
            ).reason
            == "expired"
        )
        assert (
            sdk.authorize(
                live, action=ACTION, request=dict(WITHIN)
            ).reason
            == "authorized"
        )


class TestMalformedArgumentsAreVerdicts:
    """``authorize`` touches the caller's objects before any gate runs.

    Both operations it performs on them can fail on a hostile one:
    ``deepcopy`` calls into ``__deepcopy__``, and fingerprinting
    canonicalises the capability as JSON. Both used to propagate out of
    ``authorize`` before a single gate had run, so a request that could not
    even be read produced no verdict.

    A third read happens inside ``_gate_time``: ``expires_at`` and
    ``issued_at`` are ordinary attributes of a caller-supplied object, and
    comparing a malformed one against the clock raises. That one is a
    verdict too.
    """

    def test_a_request_that_cannot_be_copied_is_denied(self):
        class Uncopyable(dict):
            def __deepcopy__(self, memo):
                raise RuntimeError("no copies of this")

        sdk, capability = scratch()

        result = sdk.authorize(
            capability,
            action=ACTION,
            request=Uncopyable(amount=10),
        )

        assert result.allowed is False
        assert result.reason == "invalid_request:RuntimeError"

    def test_a_capability_that_cannot_be_fingerprinted_is_denied(self):
        class Unserializable:
            pass

        sdk, capability = scratch()
        unnameable = dataclasses.replace(
            capability,
            constraints={"amount_max": Unserializable()},
        )

        result = sdk.authorize(
            unnameable,
            action=ACTION,
            request=dict(WITHIN),
        )

        assert result.allowed is False
        assert result.reason == "invalid_capability:TypeError"

    @pytest.mark.parametrize(
        "action,expected",
        (
            ("", "invalid_action"),
            ("   ", "invalid_action"),
            (None, "invalid_action"),
            (42, "invalid_action"),
        ),
    )
    def test_an_unusable_action_is_denied(
        self, action: Any, expected: str
    ):
        sdk, capability = scratch()

        result = sdk.authorize(
            capability, action=action, request=dict(WITHIN)
        )

        assert result.allowed is False
        assert result.reason == expected

    @pytest.mark.parametrize("bound", ("expires_at", "issued_at"))
    @pytest.mark.parametrize(
        "value", ("soon", None, True, 0, object())
    )
    def test_a_malformed_validity_bound_is_denied(
        self, bound: str, value: Any
    ):
        """Every unusable timestamp produces a verdict, by one of three routes.

        ``_gate_time`` reads both bounds off the caller's object and
        compares them against ``now``. The three routes were measured, not
        assumed, and they are all denials:

        * ``"soon"`` and ``None`` have no ordering against a float, so the
          comparison raises inside the gate and becomes
          ``capability_time_invalid:TypeError``.
        * ``True`` and ``0`` *are* orderable -- ``bool`` is an ``int`` --
          so they are ordinary verdicts: an ``expires_at`` in the past is
          ``expired``, and an ``issued_at`` in the past is not a time
          violation at all, so the tampered capability is caught by the
          cryptographic gate instead.
        * ``object()`` is not JSON-canonicalisable, so fingerprinting
          refuses it before any gate runs.

        The assertion is the union of those, which is the property that
        matters: a defined security result rather than an escape. The exact
        reason for the unorderable case is pinned separately below.
        """

        sdk, capability = scratch()
        malformed = dataclasses.replace(capability, **{bound: value})

        result = sdk.authorize(
            malformed,
            action=ACTION,
            request=dict(WITHIN),
        )

        assert result.allowed is False
        assert result.reason in (
            "capability_time_invalid:TypeError",
            "invalid_capability:TypeError",
            "expired",
            "invalid_signature",
        ), result.reason

    @pytest.mark.parametrize("bound", ("expires_at", "issued_at"))
    def test_the_unorderable_bound_names_the_unreadable_state(
        self, bound: str
    ):
        """The reason for the raising case specifically, pinned once.

        The sweep above tolerates four reasons so that a value which merely
        compares badly is not mistaken for one that cannot compare at all.
        This one asserts the exact reason, because
        ``capability_time_invalid`` is the fail-closed conversion and a
        silent abstention that let a later gate answer instead would
        satisfy the looser assertion -- which is precisely how the expiry
        skip in :class:`TestExpiryCannotBeSkippedByAnUnreadableClock`
        stayed invisible.
        """

        sdk, capability = scratch()
        malformed = dataclasses.replace(capability, **{bound: "soon"})

        result = sdk.authorize(
            malformed,
            action=ACTION,
            request=dict(WITHIN),
        )

        assert result.reason == "capability_time_invalid:TypeError"


class TestRefusalStateNarrowsAndNothingElse:
    """The one gate input no invariant represents in a snapshot.

    ``_gate_refusal`` is first in the chain and reads state the SDK
    accumulates as it denies things. The invariant review records that as a
    coverage gap: ``python -m firewall.invariants`` reads capabilities,
    envelopes, Aegis history and revocation, and nothing in it can see a
    latched refusal. So the properties are pinned here instead, and the gap
    is stated rather than closed with a seventeenth green check.

    Two of the three security-relevant halves are already established
    elsewhere and are not re-litigated here: an unreadable refusal store
    denies (two of ``FAIL_CLOSED``'s nine dependency probes), and no gate
    can originate an allow at all (``AUTHORIZATION_UNIQUENESS``). What is
    left is behavioural and belongs in a test: the scope argument is
    total, and latching is one-directional.
    """

    @pytest.mark.parametrize(
        "scope",
        ("Action", "", None, 0, True, ["action"], object()),
    )
    def test_an_unrecognised_scope_is_a_denial_not_a_default(
        self, scope: Any
    ):
        """No spelling of the scope argument selects a permissive path.

        The gate dispatches on two exact strings and every other value
        falls to an ``else``. That ``else`` returning a denial rather than
        picking a default is the whole point: a caller who passes
        ``"Action"`` -- or a boolean, or nothing that is a string at all --
        has expressed no scope, and guessing one on their behalf would
        decide how durable a refusal is on the strength of a typo.
        """

        sdk, capability = scratch()

        result = sdk.authorize(
            capability,
            action=ACTION,
            request=dict(WITHIN),
            refusal_scope=scope,
        )

        assert result.allowed is False
        assert result.reason == "invalid_refusal_scope"

    def test_a_latched_refusal_narrows_a_request_that_was_allowed(self):
        """The control for the test below, and a fact worth pinning alone.

        ``WITHIN`` is allowed on a pristine boundary. One over-ceiling call
        latches, and the same ``WITHIN`` is then refused -- so the state
        does change the verdict, which is what makes its directionality
        worth establishing.
        """

        sdk, capability = scratch()

        assert sdk.authorize(
            capability, action=ACTION, request=dict(WITHIN)
        ).allowed is True

        assert sdk.authorize(
            capability, action=ACTION, request=dict(BEYOND)
        ).reason == "constraint_denied"

        latched = sdk.authorize(
            capability, action=ACTION, request=dict(WITHIN)
        )

        assert latched.allowed is False
        assert latched.reason == "refusal_state"

    def test_clearing_a_refusal_restores_the_pristine_verdicts_and_no_more(
        self,
    ):
        """Clearing may return what refusal took. It must not return more.

        The failure this excludes is a boundary where recovering from a
        refusal is *cheaper* than never having been refused -- where the
        clear leaves behind an allow the pristine boundary would not give.
        So both verdicts are compared against a boundary that never
        refused anything: the in-range request comes back, and the
        out-of-range one is still ``constraint_denied`` rather than
        anything softer.
        """

        pristine, pristine_capability = scratch()
        reference = {
            "within": sdk_verdict(
                pristine, pristine_capability, WITHIN
            ),
            "beyond": sdk_verdict(
                pristine, pristine_capability, BEYOND
            ),
        }

        assert reference["within"] == (True, "authorized")
        assert reference["beyond"] == (False, "constraint_denied")

        sdk, capability = scratch()

        assert sdk_verdict(sdk, capability, BEYOND) == (
            False,
            "constraint_denied",
        )
        assert sdk_verdict(sdk, capability, WITHIN) == (
            False,
            "refusal_state",
        )

        sdk.refusal_state.clear_all()

        assert sdk_verdict(sdk, capability, WITHIN) == reference["within"]
        assert sdk_verdict(sdk, capability, BEYOND) == reference["beyond"]

    def test_a_refusal_recorded_against_another_action_does_not_deny(self):
        """Narrowing is fail-closed, but it is not indiscriminate.

        Asserted because the opposite would be easy to ship and easy to
        mistake for caution: a coarser ``check_action`` that matched on
        agent and fingerprint alone would deny every action once any one of
        them was refused. That direction is safe and still wrong -- it
        would make one bad request disable an agent's whole capability, and
        nothing else in the suite would notice.
        """

        sdk, capability = scratch()

        sdk.refusal_state.record(
            agent=capability.agent_id,
            capability_fingerprint=sdk.fingerprint(capability),
            action="payments.other",
            request={"amount": 1},
            reason="probe",
        )

        assert sdk_verdict(sdk, capability, WITHIN) == (True, "authorized")

    def test_the_two_scopes_differ_in_granularity_not_in_direction(self):
        """Action scope ignores the request; request scope keys on it.

        A refusal recorded for the same action and a *different* request
        denies at action scope and does not at request scope. Both readings
        are refusals-or-nothing, which is why HTTP can choose the narrower
        one without choosing a weaker one --- see
        ``TestTheNonceOrderingDivergenceIsDeliberate`` in
        ``test_v2_5_integration_divergence`` for why it does.
        """

        sdk, capability = scratch()

        sdk.refusal_state.record(
            agent=capability.agent_id,
            capability_fingerprint=sdk.fingerprint(capability),
            action=ACTION,
            request={"amount": 999_999},
            reason="probe",
        )

        assert sdk_verdict(sdk, capability, WITHIN, "action") == (
            False,
            "refusal_state",
        )
        assert sdk_verdict(sdk, capability, WITHIN, "request") == (
            True,
            "authorized",
        )



class TestEveryAuthorizingEntryPointInheritsTotality:
    """Totality has to hold where callers actually enter.

    ``authorize`` is the boundary, but it is not the only method a
    deployment calls. Each of these reaches the same gate chain, and each
    is checked separately rather than assumed: a wrapper that caught the
    old exception and substituted its own answer would have hidden the
    defect on its own surface while the boundary stayed broken, and a
    wrapper that adds a read of its own could still escape.
    """

    ENTRY_POINTS = (
        "authorize",
        "authorize_north_star",
        "authorize_continuous",
        "authorize_with_delegation_budget",
    )

    @pytest.mark.parametrize("entry", ENTRY_POINTS)
    def test_an_unreadable_revocation_store_denies_on_every_entry_point(
        self, entry: str
    ):
        sdk, capability = scratch()

        if entry == "authorize_with_delegation_budget":
            # Without a configured lineage budget this surface denies
            # ``delegation_budget_not_configured`` and the control below
            # would fail for a reason that has nothing to do with the
            # unreadable store.
            sdk.configure_delegation_budget(
                capability,
                max_total_amount=1_000.0,
            )

        method = getattr(sdk, entry)

        control = method(
            capability, action=ACTION, request=dict(WITHIN)
        )
        assert control.allowed is True, (entry, control.reason)

        sdk.revocation = Unreadable(sdk.revocation, "is_revoked")

        result = method(
            capability, action=ACTION, request=dict(WITHIN)
        )

        assert result.allowed is False
        assert result.reason == (
            "revocation_state_unavailable:RuntimeError"
        )


class TestTheContainedConsequenceIsStatedHonestly:
    """The evidence denial is conservative, not neutral. Say so.

    ``_gate_transaction`` commits, then records. When the record fails the
    allow is withdrawn -- but the commit is not rolled back, so the
    request's budget is spent on a request that was refused. The direction
    is safe: authority is *destroyed*, never granted, and a caller cannot
    convert this into more room than it had. It is still a limitation, and
    ``docs/v2.5-boundary.md`` states it as one. This test exists so that
    claim is backed by a measurement rather than by a sentence.
    """

    def test_an_unrecordable_allow_spends_budget_it_did_not_grant(self):
        from firewall.security_context import SecurityContext

        context = SecurityContext(
            "probe-agent",
            max_actions=2,
            max_total_amount=100,
        )
        sdk = FirewallSDK(security_context=context)
        sdk.generate_key("v25-probe")
        capability = sdk.issue(
            agent="probe-agent",
            capability=ACTION,
            constraints=dict(CONSTRAINTS),
        )

        assert context.action_count == 0
        assert context.total_amount == 0.0

        sdk.lifecycle = Unreadable(sdk.lifecycle, "record")

        first = sdk.authorize(
            capability, action=ACTION, request={"amount": 40}
        )

        assert first.allowed is False
        assert first.reason == "evidence_unavailable:RuntimeError"

        # The refused request consumed the budget anyway.
        assert context.action_count == 1
        assert context.total_amount == 40.0

    def test_the_consequence_narrows_rather_than_widens(self):
        """Spending budget on a refusal can only ever deny more."""

        from firewall.security_context import SecurityContext

        context = SecurityContext(
            "probe-agent",
            max_actions=2,
            max_total_amount=100,
        )
        sdk = FirewallSDK(security_context=context)
        sdk.generate_key("v25-probe")
        capability = sdk.issue(
            agent="probe-agent",
            capability=ACTION,
            constraints=dict(CONSTRAINTS),
        )
        sdk.lifecycle = Unreadable(sdk.lifecycle, "record")

        for _ in range(2):
            assert (
                sdk.authorize(
                    capability, action=ACTION, request={"amount": 40}
                ).allowed
                is False
            )

        # Budget exhausted by two refusals. Restore the evidence sink and
        # confirm the exhaustion is real: the loss cost this agent
        # authority, which is the safe direction to fail in.
        sdk.lifecycle = object.__getattribute__(sdk.lifecycle, "_wrapped")

        result = sdk.authorize(
            capability, action=ACTION, request={"amount": 40}
        )

        assert result.allowed is False
        assert result.reason != "authorized"


class TestFailClosedActuallyExercisesTheDependencyPath:
    """A green invariant that never runs the path is not evidence.

    FAIL_CLOSED reported HOLDS across all of v2.4 while five dependencies
    could turn any decision into an exception, because its eight probes
    were malformed *input* against a healthy SDK. v2.5 added nine
    dependency-failure probes. These two tests are the negative controls
    for that addition: revert either guard and the invariant must go red.
    Without them the new probes could be quietly weakened into passing
    unconditionally and nothing would notice.
    """

    @staticmethod
    def _status_with(monkeypatch, name: str, replacement: Any) -> Any:
        from firewall.invariants import runtime

        monkeypatch.setattr(
            FirewallSDK,
            name,
            staticmethod(replacement),
            raising=True,
        )

        return runtime.check_fail_closed()

    def test_it_goes_red_when_unreadable_state_is_swallowed(
        self, monkeypatch
    ):
        from firewall.invariants.model import InvariantStatus

        result = self._status_with(
            monkeypatch,
            "_read_security_state",
            lambda read: (read(), None),
        )

        assert result.status is InvariantStatus.VIOLATED
        assert result.findings

    def test_it_goes_red_when_evidence_writes_are_unguarded(
        self, monkeypatch
    ):
        from firewall.invariants.model import InvariantStatus

        def unguarded(write):
            write()
            return None

        result = self._status_with(
            monkeypatch,
            "_write_evidence",
            unguarded,
        )

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "evidence log" in finding for finding in result.findings
        )

    def test_it_holds_on_the_shipped_implementation(self):
        from firewall.invariants import runtime
        from firewall.invariants.model import InvariantStatus

        result = runtime.check_fail_closed()

        assert result.status is InvariantStatus.HOLDS
        assert result.details["dependency_probes"] == 9
