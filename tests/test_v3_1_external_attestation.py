"""v3.1: external state attestation -- attack the twenty-second invariant.

v2.8 recorded what happened. v2.9 established whether the *recorded claim*
could be trusted. Both stop at the same place: everything in the journals
was pushed into them by the process the firewall runs in. v3.1 draws the
last line in the chain:

    AUTHORIZED =/= EXECUTED =/= OBSERVED =/= VERIFIED
               =/= ATTESTED =/= COMPLETED

``EXTERNAL_STATE_ATTESTATION_SOUNDNESS`` (the twenty-second registered
invariant) machine-checks the new layer: every recorded attestation claim
binds to the exact effect, attempt, execution and correlation handle it
speaks about, re-derives to its own id, is reachable only through a
signature that verified under a registered, unrevoked external issuer key
over a supported algorithm and a current validity window, is claimed
exactly once in the replay ledger, is never started outside the declared
protocol paths, is never referenced from the ALLOW path at all, can
neither grant authority nor resurrect a revoked or expired execution, and
is required -- current, attested, uncontradicted -- before a lease over an
adopted side effect may be recorded COMPLETED when the deployment asks for
it.

This file attacks every one of those, the way
``tests/test_v2_9_effect_verification.py`` attacked the verification
layer: forged envelopes, stale ones, replayed ones, envelopes lifted onto
another effect, contradictions, missing evidence, tampered rows, and the
fail-closed handling of an unreadable trust store, clock or journal.

The SDK boundary is tested alongside the invariant, because a check that
only fires after the fact is worth less than a gate that refuses before
it: every attack below is asserted both as a refused
``AttestationResult``/``ExecutionLeaseOutcome`` at the boundary *and*, in
:class:`TestInvariantTeeth`, as a ``VIOLATED`` finding if the records are
edited into the shape the invariant exists to catch.
"""

from __future__ import annotations

import time
import uuid

from dataclasses import replace

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from firewall.effect import (
    EffectOutcome,
    EffectState,
    ReceiptKind,
)
from firewall.effect_verification import (
    VerificationOutcome,
    VerifierVerdict,
)
from firewall.execution_lease import ExecutionState
from firewall.external_attestation import (
    DEFAULT_MAX_AGE_SECONDS,
    AttestationEnvelope,
    AttestationJournalError,
    AttestationOutcome,
    ExternalIssuerError,
    build_attestation,
    canonical_external_state_digest,
    verify_envelope_signature,
)
from firewall.invariants import (
    check_external_state_attestation_soundness,
)
from firewall.invariants import runtime as runtime_module
from firewall.invariants.model import InvariantStatus
from firewall.invariants.runtime import _attestation_source_findings
from firewall.sdk import FirewallSDK

ACTION = "payments.send"
REQUEST = {"amount": 5}
EFFECT = {"to": "acct-9", "amount": 5}
EFFECT_TYPE = "transfer"
KEY = "key-attestation"

#: The external issuer the tests register, and the provider the receipt
#: claims. Equal on purpose: a real deployment's assertion bridge names the
#: system whose state it observed.
ISSUER = "acme-payments"
KEY_ID = "acme-key-1"
PROVIDER = "acme-payments"
EXT_ID = "acme-request-1"

#: Sentinel meaning "use what the side-effect row recorded".
MATCH = object()


class Clock:
    """A clock the test can move, for the freshness attacks."""

    def __init__(self, start: float | None = None):
        self.value = float(start if start is not None else time.time())

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> float:
        self.value += float(seconds)
        return self.value


class Issuer:
    """One test-controlled external issuer with a registered key."""

    def __init__(self, sdk: FirewallSDK, *, key_id: str = KEY_ID):
        self.private = Ed25519PrivateKey.generate()
        self.key_id = key_id
        sdk.trust_external_issuer(
            ISSUER,
            key_id,
            self.private.public_key(),
        )

    def rotate(self, sdk: FirewallSDK, key_id: str) -> "Issuer":
        return Issuer(sdk, key_id=key_id)


def make_sdk(*, clock=None, issuer: bool = True, **kwargs):
    """A fresh SDK with one throwaway signing key and one external issuer."""

    sdk = FirewallSDK(clock=clock, **kwargs)
    sdk.generate_key(f"v31-{uuid.uuid4().hex[:10]}")
    return (sdk, Issuer(sdk) if issuer else None)


def make_capability(sdk, *, ttl: float = 3600.0):
    now = sdk.verifier.clock()
    return sdk.issue(
        agent="agent-a",
        capability=ACTION,
        constraints={"amount_max": 100},
        expires_at=now + ttl,
    )


def walk_to_attempt(sdk, cap, *, execution_id=None, key=KEY):
    """authorize -> reserve -> start -> prepare -> attempt."""

    issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
    assert issued.allowed, issued.reason
    reserved = sdk.reserve_execution(
        issued.lease,
        cap,
        ACTION,
        dict(REQUEST),
        execution_id=execution_id or f"exec-{uuid.uuid4().hex[:8]}",
    )
    assert reserved.allowed, reserved.reason
    started = sdk.start_execution(reserved.lease, cap, ACTION, dict(REQUEST))
    assert started.allowed, started.reason
    prepared = sdk.prepare_effect(
        started.lease,
        cap,
        ACTION,
        dict(REQUEST),
        effect=dict(EFFECT),
        effect_type=EFFECT_TYPE,
        idempotency_key=key,
    )
    assert prepared.allowed, prepared.reason
    attempted = sdk.attempt_effect(
        started.lease,
        cap,
        ACTION,
        dict(REQUEST),
        effect=dict(EFFECT),
        effect_type=EFFECT_TYPE,
        idempotency_key=key,
    )
    assert attempted.allowed, attempted.reason
    return issued, started, attempted


def record_success(
    sdk,
    cap,
    lease,
    *,
    key=KEY,
    outcome=EffectOutcome.SUCCEEDED,
    kind=ReceiptKind.PROVIDER_EVIDENCE,
    ext_id=EXT_ID,
    provider=PROVIDER,
):
    return sdk.record_effect_receipt(
        lease,
        cap,
        ACTION,
        dict(REQUEST),
        effect=dict(EFFECT),
        effect_type=EFFECT_TYPE,
        idempotency_key=key,
        observed_outcome=outcome,
        evidence_kind=kind,
        external_request_id=ext_id,
        provider=provider,
    )


def build_env(
    sdk,
    lease,
    *,
    issuer: Issuer,
    observed_outcome=EffectOutcome.SUCCEEDED,
    private_key=None,
    issuer_id: str = ISSUER,
    key_id: str | None = None,
    nonce=None,
    issued_at=None,
    ttl: float = DEFAULT_MAX_AGE_SECONDS,
    not_before=None,
    clock=None,
    state_digest=None,
    effect_id=MATCH,
    attempt_id=MATCH,
    lease_id=MATCH,
    effect_digest=MATCH,
    capability_fingerprint=MATCH,
    agent_id=MATCH,
    action=MATCH,
    idempotency_key=MATCH,
    execution_id=MATCH,
    external_request_id=MATCH,
    provider=MATCH,
) -> AttestationEnvelope:
    """Mint a genuine envelope over the row a lease currently holds.

    Everything defaults to what the *journal row* recorded, so the envelope
    is scoped to the real effect; each attack overrides exactly one field,
    which is what makes the refusal it provokes attributable to that field.

    ``issued_at`` is stamped from the firewall's own clock unless the caller
    says otherwise. That is not a convenience: an attestation window is only
    meaningful in the time base the firewall compares it against, and a test
    that stamped wall time while the SDK read an injected clock would be
    measuring clock skew rather than the property under test.
    """

    row = sdk.effects.by_lease(lease.lease_id)
    assert row is not None, "no side-effect row to attest"

    def pick(value, actual):
        return actual if value is MATCH else value

    return build_attestation(
        issuer_id=issuer_id,
        key_id=key_id or issuer.key_id,
        private_key=private_key or issuer.private,
        effect_id=pick(effect_id, row.effect_id),
        lease_id=pick(lease_id, row.lease_id),
        attempt_id=pick(attempt_id, row.attempt_id),
        effect_digest=pick(effect_digest, row.effect_digest),
        capability_fingerprint=pick(
            capability_fingerprint, row.capability_fingerprint
        ),
        agent_id=pick(agent_id, row.agent_id),
        action=pick(action, row.action),
        idempotency_key=pick(idempotency_key, row.idempotency_key),
        state_digest=(
            state_digest
            if state_digest is not None
            else canonical_external_state_digest(
                {"nonce": uuid.uuid4().hex, "outcome": str(observed_outcome)}
            )
        ),
        external_request_id=pick(
            external_request_id, row.external_request_id or ""
        ),
        observed_outcome=observed_outcome,
        provider=pick(provider, row.provider),
        execution_id=pick(execution_id, row.execution_id),
        issued_at=issued_at,
        ttl=ttl,
        not_before=not_before,
        nonce=nonce,
        clock=clock if clock is not None else sdk.verifier.clock,
    )


def attest(sdk, lease, cap, envelope, *, key=KEY):
    """Present one envelope to the SDK's attestation protocol step."""

    return sdk.record_attestation(
        lease,
        cap,
        ACTION,
        dict(REQUEST),
        effect=dict(EFFECT),
        effect_type=EFFECT_TYPE,
        idempotency_key=key,
        attestation=envelope,
    )


def authenticator(evidence):
    return VerifierVerdict(
        outcome=VerificationOutcome.VERIFIED,
        method="acme-authenticator",
        note="acme status api confirmed the recorded request",
    )


def commit(sdk, lease, cap, **kwargs):
    kwargs.setdefault("verifier", authenticator)
    kwargs.setdefault("method", "acme-authenticator")
    return sdk.commit_effect(
        lease,
        cap,
        ACTION,
        dict(REQUEST),
        effect=dict(EFFECT),
        effect_type=EFFECT_TYPE,
        idempotency_key=KEY,
        **kwargs,
    )


def audit(sdk):
    return check_external_state_attestation_soundness(sdk)


def walk_attested(sdk, cap, *, issuer, execution_id=None):
    """The whole protocol to a COMPLETED, attested execution."""

    issued, started, _ = walk_to_attempt(
        sdk, cap, execution_id=execution_id
    )
    receipt = record_success(sdk, cap, started.lease)
    assert receipt.allowed, receipt.reason

    envelope = build_env(sdk, started.lease, issuer=issuer)
    result = attest(sdk, started.lease, cap, envelope)
    assert result.allowed, result.reason

    outcome = commit(
        sdk,
        started.lease,
        cap,
        attestation=envelope,
        attestation_required=True,
    )
    assert outcome.allowed, outcome.reason

    return issued, started, receipt, envelope, outcome


# ======================================================================
# Calibration: what the invariant accepts, and what it must not
# ======================================================================


class TestCalibrationAndToothlessness:
    def test_the_calibration_records_hold(self):
        """The whole chain through the real protocol is not a violation."""

        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        issued, started, _, _, outcome = walk_attested(
            sdk, cap, issuer=issuer
        )
        result = audit(sdk)
        record = sdk.execution_leases.get(issued.lease.lease_id)
        claims = sdk.attestation_records()
        sdk.close()

        assert result.status is InvariantStatus.HOLDS, result.reason
        assert record.state is ExecutionState.COMPLETED
        assert [claim.outcome for claim in claims] == [
            AttestationOutcome.ATTESTED
        ]
        assert outcome.allowed

    def test_a_fresh_sdk_is_unverifiable_not_violated(self):
        sdk, _ = make_sdk()
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.UNVERIFIABLE

    def test_a_deployment_that_requires_attestation_is_checkable(self):
        """Requiring it is itself the state the invariant audits."""

        sdk, _ = make_sdk(require_external_attestation=True)
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.HOLDS

    def test_the_source_census_is_closed(self):
        """Everything the layer touches is declared, and nothing else."""

        findings, notes = _attestation_source_findings()

        assert findings == ()
        assert any("ALLOW path" in note for note in notes)

    def test_the_census_notices_an_undeclared_journal_caller(self, monkeypatch):
        """The census has teeth: undeclare the one path and it fails."""

        monkeypatch.setattr(
            runtime_module,
            "ATTESTATION_STORE_MUTATOR_OWNERS",
            frozenset(),
        )
        findings, _ = _attestation_source_findings()

        assert any(
            "drives the attestation journal" in finding
            for finding in findings
        )

    def test_the_census_notices_an_undeclared_trust_anchor(self, monkeypatch):
        monkeypatch.setattr(
            runtime_module,
            "EXTERNAL_ISSUER_MUTATOR_OWNERS",
            frozenset(),
        )
        findings, _ = _attestation_source_findings()

        assert any(
            "external issuer key" in finding for finding in findings
        )

    def test_the_census_notices_an_allow_path_reference(self, monkeypatch):
        """The negative rule inspects references, not just mutators."""

        monkeypatch.setattr(
            runtime_module,
            "ATTESTATION_ALLOW_PATH_OWNERS",
            frozenset({"FirewallSDK._journal_attestation"}),
        )
        findings, _ = _attestation_source_findings()

        assert any("ALLOW path" in finding for finding in findings)

    def test_the_declarations_name_real_functions(self):
        for module, function in (
            runtime_module.ATTESTATION_STORE_MUTATOR_OWNERS
            | runtime_module.EXTERNAL_ISSUER_MUTATOR_OWNERS
            | runtime_module.ATTESTATION_HELPER_CALLERS
        ):
            assert module.endswith(".py")
            assert getattr(FirewallSDK, function.split(".")[-1], None)

    def test_attestation_creates_no_authorization_verdict(self):
        """Nothing in the layer constructs an ``AuthorizationResult``.

        The type test is structural on purpose: a verdict-shaped object
        from this layer would be a second authority, and
        AUTHORIZATION_UNIQUENESS is what forbids one.
        """

        import ast

        import firewall.external_attestation as module

        tree = ast.parse(open(module.__file__, encoding="utf-8").read())

        # Parsed, not grepped: the module's own prose names ``authorize()``
        # and ``AuthorizationResult`` to explain what it does *not* do, and
        # a text search would read that explanation as a call site.
        forbidden = {"AuthorizationResult", "_result", "authorize"}

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = (
                func.id
                if isinstance(func, ast.Name)
                else func.attr
                if isinstance(func, ast.Attribute)
                else None
            )
            assert name not in forbidden, name


# ======================================================================
# Forgery: who signed it, and did the signature verify
# ======================================================================


class TestForgery:
    def test_an_unregistered_issuer_is_refused(self):
        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        envelope = build_env(
            sdk, started.lease, issuer=issuer, issuer_id="not-registered"
        )
        result = attest(sdk, started.lease, cap, envelope)
        record = sdk.attestation_records()[0]
        sdk.close()

        assert not result.allowed
        assert result.reason == "attestation_issuer_unknown"
        assert record.outcome is AttestationOutcome.NOT_ATTESTED
        assert record.signature_verified is False

    def test_a_signature_by_an_unknown_key_is_refused(self):
        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        envelope = build_env(
            sdk,
            started.lease,
            issuer=issuer,
            private_key=Ed25519PrivateKey.generate(),
        )
        result = attest(sdk, started.lease, cap, envelope)
        sdk.close()

        assert not result.allowed
        assert result.reason == "attestation_signature_invalid"

    def test_a_registered_key_of_another_issuer_is_not_this_issuer(self):
        """Registration is per issuer *and* per key, not per key material.

        The envelope names a registered issuer and a registered key -- of a
        different issuer -- and carries a signature from a third key. The
        lookup succeeds and the signature does not, which is exactly the
        attack a name-based trust model would wave through.
        """

        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        sdk.trust_external_issuer(
            "other-system", "other-key", Ed25519PrivateKey.generate().public_key()
        )

        envelope = build_env(
            sdk,
            started.lease,
            issuer=issuer,
            issuer_id="other-system",
            key_id="other-key",
            private_key=issuer.private,
        )
        result = attest(sdk, started.lease, cap, envelope)
        record = sdk.attestation_records()[0]
        sdk.close()

        assert not result.allowed
        assert result.reason == "attestation_signature_invalid"
        assert record.issuer_id == "other-system"
        assert record.signature_verified is False

    def test_an_unregistered_key_of_a_known_issuer_is_refused(self):
        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        envelope = build_env(
            sdk,
            started.lease,
            issuer=issuer,
            key_id="never-registered",
        )
        result = attest(sdk, started.lease, cap, envelope)
        sdk.close()

        assert not result.allowed
        assert result.reason == "attestation_issuer_unknown"

    def test_a_revoked_issuer_key_stops_being_accepted(self):
        """Revocation bites even on a statement already on the journal.

        The envelope is verified again on every presentation rather than
        answered from the record, so withdrawing a key withdraws its
        statements immediately -- and the earlier accepted claim is
        preserved beside the refusal instead of being rewritten.
        """

        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        envelope = build_env(sdk, started.lease, issuer=issuer)
        first = attest(sdk, started.lease, cap, envelope)
        assert first.allowed

        sdk.revoke_external_issuer_key(
            ISSUER, issuer.key_id, reason="key compromised"
        )

        again = attest(sdk, started.lease, cap, envelope, key=KEY)
        claims = sdk.attestation_records()
        sdk.close()

        assert not again.allowed
        assert again.reason == "attestation_issuer_revoked"
        assert [claim.outcome for claim in claims] == [
            AttestationOutcome.ATTESTED,
            AttestationOutcome.NOT_ATTESTED,
        ]

    def test_a_revoked_issuer_refuses_a_fresh_signature(self):
        """Revocation is not retroactive-eraser: new statements are refused."""

        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        envelope = build_env(sdk, started.lease, issuer=issuer)
        sdk.revoke_external_issuer(ISSUER, reason="external system compromised")

        result = attest(sdk, started.lease, cap, envelope)
        record = sdk.attestation_records()[0]
        sdk.close()

        assert not result.allowed
        assert result.reason == "attestation_issuer_revoked"
        assert record.signature_verified is False
        assert record.envelope_id == envelope.envelope_id
        assert record.reason == "attestation_issuer_revoked"

    def test_a_revoked_key_cannot_be_re_registered(self):
        sdk, issuer = make_sdk()
        sdk.revoke_external_issuer_key(ISSUER, issuer.key_id)

        with pytest.raises(ExternalIssuerError):
            sdk.trust_external_issuer(
                ISSUER, issuer.key_id, issuer.private.public_key()
            )

        sdk.close()

    def test_a_live_key_cannot_be_silently_replaced(self):
        sdk, issuer = make_sdk()

        with pytest.raises(ExternalIssuerError):
            sdk.trust_external_issuer(
                ISSUER,
                issuer.key_id,
                Ed25519PrivateKey.generate().public_key(),
            )

        sdk.close()

    def test_an_unsupported_algorithm_is_refused(self):
        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        envelope = build_env(sdk, started.lease, issuer=issuer)
        result = attest(
            sdk,
            started.lease,
            cap,
            replace(envelope, algorithm="RSA-PSS"),
        )
        sdk.close()

        assert not result.allowed
        assert result.reason == "attestation_unsupported_algorithm"

    def test_an_unsupported_version_is_refused(self):
        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        envelope = build_env(sdk, started.lease, issuer=issuer)
        result = attest(
            sdk,
            started.lease,
            cap,
            replace(envelope, attestation_version=99),
        )
        sdk.close()

        assert not result.allowed
        assert result.reason == "attestation_unsupported_version"

    def test_a_statement_of_another_type_is_refused(self):
        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        envelope = build_env(sdk, started.lease, issuer=issuer)
        result = attest(
            sdk,
            started.lease,
            cap,
            replace(envelope, statement_type="agent_identity"),
        )
        sdk.close()

        assert not result.allowed
        assert result.reason == "attestation_statement_unsupported"

    def test_a_missing_signature_is_refused(self):
        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        envelope = build_env(sdk, started.lease, issuer=issuer)
        result = attest(
            sdk, started.lease, cap, replace(envelope, signature="")
        )
        sdk.close()

        assert not result.allowed
        assert result.reason == "attestation_signature_invalid"

    def test_a_malformed_envelope_is_refused(self):
        sdk, _issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        result = attest(
            sdk,
            started.lease,
            cap,
            {"issuer_id": "acme-payments", "signature": "!!!"},
        )
        record = sdk.attestation_records()[0]
        sdk.close()

        assert not result.allowed
        assert result.reason == "attestation_malformed"
        assert record.envelope_id == ""
        assert record.reason == "attestation_malformed"

    def test_a_tampered_block_invalidates_the_signature(self):
        """Editing the signed block is editing the thing that was signed."""

        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        envelope = build_env(sdk, started.lease, issuer=issuer)
        tampered = replace(
            envelope,
            state_digest=canonical_external_state_digest({"forged": True}),
        )

        assert tampered.envelope_id != envelope.envelope_id
        assert (
            verify_envelope_signature(tampered, issuer.private.public_key())
            is False
        )

        result = attest(sdk, started.lease, cap, tampered)
        sdk.close()

        assert not result.allowed
        assert result.reason == "attestation_signature_invalid"

    def test_a_genuine_signature_for_another_effect_is_a_scope_mismatch(self):
        """The 'valid signature, wrong effect' attack in its real form."""

        sdk, issuer = make_sdk()
        cap = make_capability(sdk)

        _a_issued, a_started, _ = walk_to_attempt(
            sdk, cap, execution_id="exec-a", key="key-a"
        )
        record_success(sdk, cap, a_started.lease, key="key-a")

        _b_issued, b_started, _ = walk_to_attempt(
            sdk, cap, execution_id="exec-b", key="key-b"
        )
        record_success(sdk, cap, b_started.lease, key="key-b")

        envelope_a = build_env(sdk, a_started.lease, issuer=issuer)

        result = attest(sdk, b_started.lease, cap, envelope_a, key="key-b")
        record = sdk.attestation_records()[0]
        sdk.close()

        assert not result.allowed
        assert result.reason == "attestation_scope_mismatch"
        # The scope fields were all genuine -- only the effect differs -- so
        # the signature really did verify. The record says so.
        assert record.signature_verified is True
        assert "effect_id" in (record.note or "")

    def test_an_envelope_for_another_capability_or_agent_is_refused(self):
        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        envelope = build_env(
            sdk, started.lease, issuer=issuer, capability_fingerprint="0" * 32
        )
        result = attest(sdk, started.lease, cap, envelope)
        sdk.close()

        assert not result.allowed
        assert result.reason == "attestation_scope_mismatch"
        assert "capability_fingerprint" in (
            sdk.attestation_records()[0].note or ""
        )

    def test_an_envelope_for_another_attempt_is_refused(self):
        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        envelope = build_env(
            sdk, started.lease, issuer=issuer, attempt_id="attempt-elsewhere"
        )
        result = attest(sdk, started.lease, cap, envelope)
        sdk.close()

        assert not result.allowed
        assert result.reason == "attestation_scope_mismatch"
        assert "attempt_id" in (sdk.attestation_records()[0].note or "")

    def test_attestation_never_grants_authority(self):
        """An attested effect changes no authorization verdict."""

        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        before = sdk.authorize(cap, action=ACTION, request=dict(REQUEST))
        assert before.allowed is True

        envelope = build_env(sdk, started.lease, issuer=issuer)
        assert attest(sdk, started.lease, cap, envelope).allowed

        after = sdk.authorize(cap, action=ACTION, request=dict(REQUEST))
        over = sdk.authorize(
            cap, action=ACTION, request={"amount": 10_000}
        )
        sdk.close()

        assert after.allowed == before.allowed
        assert after.reason == before.reason
        assert over.allowed is False

    def test_attestation_cannot_resurrect_a_revoked_execution(self):
        """A signature arriving after revocation is evidence, not authority."""

        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        # The envelope is minted while the execution is live, and presented
        # after the authority behind it was withdrawn.
        envelope = build_env(sdk, started.lease, issuer=issuer)
        sdk.revoke(cap)

        result = attest(sdk, started.lease, cap, envelope)
        record = sdk.attestation_records()[0]
        lease = sdk.execution_leases.get(issued.lease.lease_id)
        sdk.close()

        assert not result.allowed
        assert result.outcome is AttestationOutcome.NOT_ATTESTED
        assert "capability_revoked" in result.reason
        assert record.signature_verified is True
        assert lease.state in (
            ExecutionState.REVOKED,
            ExecutionState.DENIED,
        )

    def test_attestation_never_resurrects_an_expired_execution(self):
        """The envelope is current; the *execution* is not."""

        clock = Clock()
        sdk, issuer = make_sdk(clock=clock)
        cap = make_capability(sdk)
        issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        clock.advance(10_000.0)  # the lease deadline passes

        # Minted now, so its window is open: nothing about the statement is
        # stale, and the refusal can only be about the authority behind it.
        envelope = build_env(sdk, started.lease, issuer=issuer)

        result = attest(sdk, started.lease, cap, envelope)
        record = sdk.attestation_records()[0]
        lease = sdk.execution_leases.get(issued.lease.lease_id)
        sdk.close()

        assert not result.allowed
        assert result.outcome is AttestationOutcome.NOT_ATTESTED
        assert "lease_expired" in result.reason
        # The signature really did verify, and the record says so: what is
        # missing is authority, not evidence.
        assert record.signature_verified is True
        assert lease.state is ExecutionState.EXPIRED


# ======================================================================
# Freshness: is the statement about the state current
# ======================================================================


class TestFreshness:
    def test_an_expired_envelope_is_refused(self):
        clock = Clock()
        sdk, issuer = make_sdk(clock=clock)
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        envelope = build_env(sdk, started.lease, issuer=issuer, ttl=5.0)
        clock.advance(60.0)

        result = attest(sdk, started.lease, cap, envelope)
        record = sdk.attestation_records()[0]
        sdk.close()

        assert not result.allowed
        assert result.reason == "attestation_expired"
        assert record.signature_verified is True
        assert record.issued_at <= record.expires_at

    def test_a_not_yet_valid_envelope_is_refused(self):
        clock = Clock()
        sdk, issuer = make_sdk(clock=clock)
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        now = clock()
        envelope = build_env(
            sdk,
            started.lease,
            issuer=issuer,
            issued_at=now,
            not_before=now + 600.0,
            ttl=1200.0,
        )
        result = attest(sdk, started.lease, cap, envelope)
        sdk.close()

        assert not result.allowed
        assert result.reason == "attestation_not_yet_valid"

    def test_an_envelope_older_than_the_max_age_is_refused(self):
        """The deployment's ceiling, independent of the issuer's window."""

        clock = Clock()
        sdk, issuer = make_sdk(clock=clock)
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        now = clock()
        envelope = build_env(
            sdk,
            started.lease,
            issuer=issuer,
            issued_at=now,
            ttl=1e6,
        )
        clock.advance(DEFAULT_MAX_AGE_SECONDS + 1.0)

        result = attest(sdk, started.lease, cap, envelope)
        sdk.close()

        assert not result.allowed
        assert result.reason == "attestation_stale"

    def test_a_clock_skew_cannot_make_an_old_envelope_new(self):
        """Skew widens the window; max_age is measured unadjusted."""

        clock = Clock()
        sdk, issuer = make_sdk(
            clock=clock, attestation_clock_skew_seconds=600.0
        )
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        now = clock()
        envelope = build_env(
            sdk,
            started.lease,
            issuer=issuer,
            issued_at=now - 1000.0,
            ttl=1e6,
            not_before=now - 1000.0,
        )

        result = attest(sdk, started.lease, cap, envelope)
        sdk.close()

        assert not result.allowed
        assert result.reason == "attestation_stale"

    def test_a_claim_that_goes_stale_does_not_complete_later(self):
        """Freshness is re-checked at the completion, not trusted from the
        moment the claim was recorded."""

        clock = Clock()
        sdk, issuer = make_sdk(clock=clock)
        cap = make_capability(sdk)
        issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        # The envelope's window is short and the execution lease's is
        # longer, so the claim can go stale while the execution it is about
        # is still live -- which is the case that has to be refused.
        envelope = build_env(sdk, started.lease, issuer=issuer, ttl=5.0)
        assert attest(sdk, started.lease, cap, envelope).allowed

        clock.advance(30.0)  # the envelope's window closes; the lease lives

        # Committing now, without re-presenting the envelope, is refused:
        # the recorded claim was current when it was accepted and is stale
        # now, so the gate re-checks freshness instead of trusting the
        # journal to remember a window that has since closed.
        outcome = commit(sdk, started.lease, cap, attestation_required=True)
        lease = sdk.execution_leases.get(issued.lease.lease_id)
        reasons = [claim.reason for claim in sdk.attestation_records()]
        result = audit(sdk)
        sdk.close()

        assert not outcome.allowed
        assert outcome.reason == (
            "effect_unattested:attestation_expired_at_completion"
        )
        assert lease.state is ExecutionState.STARTED
        assert reasons[0] == "attestation_verified"
        assert "attestation_expired_at_completion" in reasons
        # Every refusal is on the record, and none of them completed
        # anything: a stale claim is a refusal, not a violation.
        assert result.status is InvariantStatus.HOLDS

    def test_a_stale_envelope_presented_at_completion_is_refused(self):
        """The same property from the other side: the envelope itself."""

        clock = Clock()
        sdk, issuer = make_sdk(clock=clock)
        cap = make_capability(sdk)
        issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        envelope = build_env(sdk, started.lease, issuer=issuer, ttl=5.0)
        assert attest(sdk, started.lease, cap, envelope).allowed
        clock.advance(30.0)

        presented = commit(
            sdk,
            started.lease,
            cap,
            attestation=envelope,
            attestation_required=True,
        )
        lease = sdk.execution_leases.get(issued.lease.lease_id)
        sdk.close()

        assert not presented.allowed
        assert presented.reason == "effect_unattested:attestation_expired"
        assert lease.state is ExecutionState.STARTED

    def test_a_fresh_claim_completes(self):
        clock = Clock()
        sdk, issuer = make_sdk(clock=clock)
        cap = make_capability(sdk)
        issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        envelope = build_env(sdk, started.lease, issuer=issuer, ttl=300.0)
        assert attest(sdk, started.lease, cap, envelope).allowed
        clock.advance(10.0)

        outcome = commit(
            sdk,
            started.lease,
            cap,
            attestation=envelope,
            attestation_required=True,
        )
        lease = sdk.execution_leases.get(issued.lease.lease_id)
        sdk.close()

        assert outcome.allowed, outcome.reason
        assert lease.state is ExecutionState.COMPLETED


# ======================================================================
# Replay: one signed statement is evidence once
# ======================================================================


class TestReplay:
    def test_the_identical_envelope_twice_is_idempotent(self):
        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        envelope = build_env(sdk, started.lease, issuer=issuer)

        first = attest(sdk, started.lease, cap, envelope)
        second = attest(sdk, started.lease, cap, envelope)
        claims = sdk.attestation_records()
        nonces = sdk.nonce_claims()
        sdk.close()

        assert first.allowed and second.allowed
        assert len(claims) == 1
        assert len(nonces) == 1
        assert first.record.attestation_id == second.record.attestation_id

    def test_an_envelope_cannot_be_replayed_onto_another_effect(self):
        sdk, issuer = make_sdk()
        cap = make_capability(sdk)

        _a_issued, a_started, _ = walk_to_attempt(
            sdk, cap, execution_id="exec-a", key="key-a"
        )
        record_success(sdk, cap, a_started.lease, key="key-a")
        envelope_a = build_env(sdk, a_started.lease, issuer=issuer)
        assert attest(sdk, a_started.lease, cap, envelope_a, key="key-a").allowed

        _b_issued, b_started, _ = walk_to_attempt(
            sdk, cap, execution_id="exec-b", key="key-b"
        )
        record_success(sdk, cap, b_started.lease, key="key-b")

        result = attest(sdk, b_started.lease, cap, envelope_a, key="key-b")
        sdk.close()

        assert not result.allowed
        assert result.reason == "attestation_scope_mismatch"

    def test_a_reused_nonce_under_a_second_envelope_is_refused(self):
        """The second half of replay protection: the nonce ledger."""

        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        nonce = uuid.uuid4().hex
        first_envelope = build_env(
            sdk, started.lease, issuer=issuer, nonce=nonce
        )
        second_envelope = build_env(
            sdk, started.lease, issuer=issuer, nonce=nonce
        )

        assert first_envelope.envelope_id != second_envelope.envelope_id

        first = attest(sdk, started.lease, cap, first_envelope)
        second = attest(sdk, started.lease, cap, second_envelope)

        claims = sdk.attestation_records()
        result = audit(sdk)
        sdk.close()

        assert first.allowed
        assert not second.allowed
        assert second.reason == "attestation_replayed"
        assert second.outcome is AttestationOutcome.NOT_ATTESTED
        # The refusal is recorded truthfully and the accepted claim is
        # preserved beside it rather than overwritten.
        assert [claim.outcome for claim in claims] == [
            AttestationOutcome.ATTESTED,
            AttestationOutcome.NOT_ATTESTED,
        ]
        assert result.status is InvariantStatus.HOLDS

    def test_the_nonce_ledger_binds_one_envelope_to_one_effect(self):
        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        row = sdk.effects.by_lease(started.lease.lease_id)
        record_success(sdk, cap, started.lease)

        envelope = build_env(sdk, started.lease, issuer=issuer)
        assert attest(sdk, started.lease, cap, envelope).allowed

        claims = sdk.nonce_claims()
        sdk.close()

        assert len(claims) == 1
        assert claims[0].envelope_id == envelope.envelope_id
        assert claims[0].effect_id == row.effect_id
        assert claims[0].attempt_id == row.attempt_id
        assert claims[0].issuer_id == ISSUER

    def test_a_crash_between_the_claim_and_the_record_is_recoverable(self):
        """The nonce claim is idempotent for the identical presentation."""

        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        envelope = build_env(sdk, started.lease, issuer=issuer)
        row = sdk.effects.by_lease(started.lease.lease_id)

        # Stand in for the crash: the ledger holds the claim, the journal
        # does not hold the row.
        claimed, _existing = sdk.attestations.claim_nonce(
            issuer_id=ISSUER,
            nonce=envelope.nonce,
            envelope_id=envelope.envelope_id,
            effect_id=row.effect_id,
            attempt_id=row.attempt_id,
        )
        assert claimed

        result = attest(sdk, started.lease, cap, envelope)
        claims = sdk.attestation_records()
        sdk.close()

        assert result.allowed, result.reason
        assert [claim.outcome for claim in claims] == [
            AttestationOutcome.ATTESTED
        ]

    def test_replay_protection_survives_a_restart(self, tmp_path):
        """A ledger that dies with the process is not replay protection.

        The second generation re-registers the same external issuer key --
        configuration comes back, it is not inherited -- and reuses the
        nonce the first generation accepted, for a *different* statement
        about a *different* effect. The ledger read back from disk is what
        refuses it.
        """

        path = tmp_path / "attestation.sqlite3"

        sdk, issuer = make_sdk(attestation_store_path=path)
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        nonce = uuid.uuid4().hex
        envelope = build_env(sdk, started.lease, issuer=issuer, nonce=nonce)
        assert attest(sdk, started.lease, cap, envelope).allowed
        sdk.close()

        sdk2 = FirewallSDK(attestation_store_path=path)
        sdk2.generate_key("v31-restart")
        sdk2.trust_external_issuer(
            ISSUER, issuer.key_id, issuer.private.public_key()
        )
        cap2 = make_capability(sdk2)
        _issued2, started2, _ = walk_to_attempt(sdk2, cap2)
        record_success(sdk2, cap2, started2.lease)

        asserted = sdk2.nonce_claims()
        reissued = build_env(
            sdk2, started2.lease, issuer=issuer, nonce=nonce
        )
        result = attest(sdk2, started2.lease, cap2, reissued)
        sdk2.close()

        assert [claim.nonce for claim in asserted] == [nonce]
        assert not result.allowed
        assert result.reason == "attestation_replayed"
        assert result.outcome is AttestationOutcome.NOT_ATTESTED

    def test_records_and_nonces_are_durable_together(self, tmp_path):
        """The row and the claim on its nonce come back from one file."""

        path = tmp_path / "attestation2.sqlite3"

        sdk, issuer = make_sdk(attestation_store_path=path)
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)
        envelope = build_env(sdk, started.lease, issuer=issuer)
        accepted = attest(sdk, started.lease, cap, envelope)
        assert accepted.allowed
        sdk.close()

        sdk2 = FirewallSDK(attestation_store_path=path)

        claims = sdk2.attestation_records()
        nonces = sdk2.nonce_claims()
        sdk2.close()

        assert len(claims) == 1
        assert claims[0].outcome is AttestationOutcome.ATTESTED
        assert claims[0].attestation_id == accepted.record.attestation_id
        assert claims[0].attestation_id == claims[0].rederived_id()
        assert len(nonces) == 1
        assert nonces[0].envelope_id == envelope.envelope_id
        assert nonces[0].nonce == envelope.nonce

    def test_an_unregistered_issuer_after_a_restart_is_refused(self, tmp_path):
        """Trust is configuration, not durable state: it fails closed."""

        path = tmp_path / "attestation3.sqlite3"

        sdk, issuer = make_sdk(attestation_store_path=path)
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)
        envelope = build_env(sdk, started.lease, issuer=issuer)
        sdk.close()

        sdk2 = FirewallSDK(attestation_store_path=path)
        sdk2.generate_key("v31-restart-3")
        cap2 = make_capability(sdk2)
        _issued2, started2, _ = walk_to_attempt(sdk2, cap2)
        record_success(sdk2, cap2, started2.lease)

        # The same issuer, the same key, the same shape of statement -- and
        # no registered trust anchor, because trust is configuration and
        # configuration is re-declared, never inherited.
        result = attest(sdk2, started2.lease, cap2, envelope, key=KEY)
        sdk2.close()

        assert not result.allowed
        assert result.reason == "attestation_issuer_unknown"


# ======================================================================
# Correlation: is the statement about *this* external request
# ======================================================================


class TestCorrelation:
    def test_a_correlation_mismatch_is_refused(self):
        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease, ext_id="acme-request-1")

        envelope = build_env(
            sdk,
            started.lease,
            issuer=issuer,
            external_request_id="acme-request-999",
        )
        result = attest(sdk, started.lease, cap, envelope)
        record = sdk.attestation_records()[0]
        sdk.close()

        assert not result.allowed
        assert result.reason == "attestation_correlation_mismatch"
        assert record.correlated is False
        assert record.correlation_source == "none"

    def test_an_absent_correlation_is_refused(self):
        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease, ext_id=None)

        envelope = build_env(
            sdk, started.lease, issuer=issuer, external_request_id=""
        )
        result = attest(sdk, started.lease, cap, envelope)
        sdk.close()

        assert not result.allowed
        assert result.reason == "attestation_correlation_absent"

    def test_the_envelope_may_supply_the_correlation_the_receipt_lacked(self):
        """The signed handle is the only one there is; the record says so."""

        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease, ext_id=None)

        envelope = build_env(
            sdk,
            started.lease,
            issuer=issuer,
            external_request_id="acme-recovered-1",
        )
        result = attest(sdk, started.lease, cap, envelope)
        record = result.record
        outcome = commit(
            sdk,
            started.lease,
            cap,
            attestation=envelope,
            attestation_required=True,
        )
        sdk.close()

        assert result.allowed
        assert record.correlation_source == "attestation"
        assert record.correlated is True
        assert record.external_request_id == "acme-recovered-1"
        assert outcome.allowed

    def test_a_provider_mismatch_is_refused(self):
        """The state was not attested by the claimed external system."""

        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease, provider=PROVIDER)

        envelope = build_env(
            sdk, started.lease, issuer=issuer, provider="some-other-system"
        )
        result = attest(sdk, started.lease, cap, envelope)
        sdk.close()

        assert not result.allowed
        assert result.reason == "attestation_provider_mismatch"

    def test_a_missing_state_digest_is_refused(self):
        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        envelope = build_env(sdk, started.lease, issuer=issuer)

        # ``build_attestation`` refuses to mint one, which is the point:
        # an attestation that names no state has nothing to correlate. The
        # only way to present one is to forge the field, and the signature
        # then fails -- so a *signed* envelope always names its state.
        with pytest.raises(Exception):
            build_attestation(
                issuer_id=ISSUER,
                key_id=KEY_ID,
                private_key=issuer.private,
                effect_id="e",
                lease_id="l",
                attempt_id="a",
                effect_digest="d",
                capability_fingerprint="c",
                agent_id="g",
                action=ACTION,
                idempotency_key="k",
                state_digest="",
            )

        result = attest(
            sdk,
            started.lease,
            cap,
            replace(envelope, state_digest=""),
        )
        sdk.close()

        assert not result.allowed
        # Tampering with the signed block fails the signature before the
        # digest check is even reached, and either refusal is correct.
        assert result.reason in (
            "attestation_signature_invalid",
            "attestation_state_digest_missing",
        )

    def test_an_effect_that_was_never_attempted_has_nothing_to_attest(self):
        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))
        reserved = sdk.reserve_execution(
            issued.lease, cap, ACTION, dict(REQUEST), execution_id="x"
        )
        started = sdk.start_execution(
            reserved.lease, cap, ACTION, dict(REQUEST)
        )
        sdk.prepare_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )

        result = attest(sdk, started.lease, cap, None)
        sdk.close()

        assert not result.allowed
        assert result.reason in (
            "effect_not_attempted",
            "attestation_missing",
        )


# ======================================================================
# Contradiction: what the external system says versus what was recorded
# ======================================================================


class TestContradiction:
    def test_an_attested_failure_over_a_recorded_success_contradicts(self):
        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        envelope = build_env(
            sdk,
            started.lease,
            issuer=issuer,
            observed_outcome=EffectOutcome.FAILED,
        )
        result = attest(sdk, started.lease, cap, envelope)
        record = sdk.attestation_records()[0]
        lease = sdk.execution_leases.get(issued.lease.lease_id)
        sdk.close()

        assert not result.allowed
        assert result.reason == "attestation_contradicted"
        assert result.outcome is AttestationOutcome.CONTRADICTED
        assert record.asserted_outcome is EffectOutcome.FAILED
        assert record.signature_verified is True
        assert record.attestation_id == record.rederived_id()
        assert lease.state is ExecutionState.STARTED

    def test_a_contradiction_is_preserved_beside_the_earlier_claim(self):
        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        good = build_env(sdk, started.lease, issuer=issuer)
        assert attest(sdk, started.lease, cap, good).allowed

        bad = build_env(
            sdk,
            started.lease,
            issuer=issuer,
            observed_outcome=EffectOutcome.FAILED,
        )
        assert not attest(sdk, started.lease, cap, bad).allowed

        claims = sdk.attestation_records()
        sdk.close()

        assert [claim.outcome for claim in claims] == [
            AttestationOutcome.ATTESTED,
            AttestationOutcome.CONTRADICTED,
        ]

    def test_two_conclusive_attestations_that_disagree_contradict(self):
        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        sdk.record_effect_receipt(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            observed_outcome=EffectOutcome.UNKNOWN,
            evidence_kind=ReceiptKind.PROVIDER_EVIDENCE,
            external_request_id=EXT_ID,
            provider=PROVIDER,
        )

        # The external system resolves the firewall's UNKNOWN: a
        # resolution, not a contradiction.
        resolved = build_env(
            sdk,
            started.lease,
            issuer=issuer,
            observed_outcome=EffectOutcome.SUCCEEDED,
        )
        first = attest(sdk, started.lease, cap, resolved)
        assert first.allowed
        assert first.outcome is AttestationOutcome.ATTESTED

        # A second, genuinely signed statement saying the opposite.
        contradicted = build_env(
            sdk,
            started.lease,
            issuer=issuer,
            observed_outcome=EffectOutcome.FAILED,
        )
        second = attest(sdk, started.lease, cap, contradicted)
        claims = sdk.attestation_records()
        sdk.close()

        assert not second.allowed
        assert second.reason == "attestation_contradicted"
        assert [claim.outcome for claim in claims] == [
            AttestationOutcome.ATTESTED,
            AttestationOutcome.CONTRADICTED,
        ]

    def test_unknown_contradicts_nothing_and_resolves_nothing(self):
        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        sdk.record_effect_receipt(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            observed_outcome=EffectOutcome.UNKNOWN,
            evidence_kind=ReceiptKind.PROVIDER_EVIDENCE,
            external_request_id=EXT_ID,
            provider=PROVIDER,
        )

        envelope = build_env(
            sdk,
            started.lease,
            issuer=issuer,
            observed_outcome=EffectOutcome.SUCCEEDED,
        )
        result = attest(sdk, started.lease, cap, envelope)
        sdk.close()

        assert result.allowed
        assert result.outcome is AttestationOutcome.ATTESTED

    def test_an_inconclusive_attestation_is_not_evidence(self):
        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        envelope = build_env(
            sdk,
            started.lease,
            issuer=issuer,
            observed_outcome=EffectOutcome.UNKNOWN,
        )
        result = attest(sdk, started.lease, cap, envelope)
        sdk.close()

        assert not result.allowed
        assert result.reason == "attestation_inconclusive"
        assert result.outcome is AttestationOutcome.NOT_ATTESTED

    def test_an_unrecognized_outcome_is_not_a_verdict(self):
        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        envelope = build_env(sdk, started.lease, issuer=issuer)
        result = attest(
            sdk,
            started.lease,
            cap,
            replace(envelope, observed_outcome="probably_fine"),
        )
        sdk.close()

        assert not result.allowed
        assert result.reason in (
            "attestation_signature_invalid",
            "attestation_outcome_unknown",
        )

    def test_a_contradiction_is_never_resolved_away(self):
        """A later fresh attestation does not lift a standing contradiction."""

        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        good = build_env(sdk, started.lease, issuer=issuer)
        assert attest(sdk, started.lease, cap, good).allowed

        bad = build_env(
            sdk,
            started.lease,
            issuer=issuer,
            observed_outcome=EffectOutcome.FAILED,
        )
        assert not attest(sdk, started.lease, cap, bad).allowed

        # A third, honest statement agreeing with the row. It cannot lift
        # the contradiction either -- the contradicting claim asserted
        # FAILED, so *every* further conclusive statement disagrees with one
        # of the two already recorded. A contradiction is therefore not
        # resolvable by presenting more statements; it stands until an
        # operator reconciles what happened.
        third = build_env(sdk, started.lease, issuer=issuer)
        third_result = attest(sdk, started.lease, cap, third)
        outcome = commit(
            sdk,
            started.lease,
            cap,
            attestation=third,
            attestation_required=True,
        )
        lease = sdk.execution_leases.get(issued.lease.lease_id)
        claims = sdk.attestation_records()
        result = audit(sdk)
        sdk.close()

        assert not third_result.allowed
        assert third_result.reason == "attestation_contradicted"
        assert not outcome.allowed
        assert "attestation_contradicted" in outcome.reason
        assert lease.state is ExecutionState.STARTED
        assert [claim.outcome for claim in claims] == [
            AttestationOutcome.ATTESTED,
            AttestationOutcome.CONTRADICTED,
            AttestationOutcome.CONTRADICTED,
        ]
        # Nothing was completed on a contradicted effect, and every refusal
        # is a truthful record rather than a violation.
        assert result.status is InvariantStatus.HOLDS


# ======================================================================
# Missing evidence, and failing closed when it cannot be obtained
# ======================================================================


class TestMissingEvidenceAndFailClosed:
    def test_a_required_attestation_that_is_absent_refuses_the_commit(self):
        sdk, _issuer = make_sdk()
        cap = make_capability(sdk)
        issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        outcome = commit(sdk, started.lease, cap, attestation_required=True)
        claims = sdk.attestation_records()
        lease = sdk.execution_leases.get(issued.lease.lease_id)
        sdk.close()

        assert not outcome.allowed
        assert outcome.reason == "effect_unattested:attestation_required"
        assert [claim.reason for claim in claims] == ["attestation_required"]
        assert lease.state is ExecutionState.STARTED

    def test_the_sdk_level_requirement_applies_without_the_flag(self):
        sdk, _issuer = make_sdk(require_external_attestation=True)
        cap = make_capability(sdk)
        issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        outcome = commit(sdk, started.lease, cap)
        lease = sdk.execution_leases.get(issued.lease.lease_id)
        sdk.close()

        assert not outcome.allowed
        assert "attestation_required" in outcome.reason
        assert lease.state is ExecutionState.STARTED

    def test_the_requirement_is_not_a_mutable_widening_switch(self):
        sdk, _issuer = make_sdk(require_external_attestation=True)

        with pytest.raises(AttributeError):
            sdk.require_external_attestation = False

        assert sdk.require_external_attestation is True
        sdk.close()

    def test_a_refused_attestation_does_not_block_a_later_genuine_one(self):
        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        forged = build_env(
            sdk,
            started.lease,
            issuer=issuer,
            private_key=Ed25519PrivateKey.generate(),
        )
        assert not attest(sdk, started.lease, cap, forged).allowed

        genuine = build_env(sdk, started.lease, issuer=issuer)
        assert attest(sdk, started.lease, cap, genuine).allowed

        outcome = commit(
            sdk,
            started.lease,
            cap,
            attestation=genuine,
            attestation_required=True,
        )
        lease = sdk.execution_leases.get(issued.lease.lease_id)
        sdk.close()

        assert outcome.allowed, outcome.reason
        assert lease.state is ExecutionState.COMPLETED

    def test_run_effect_without_an_attestor_refuses_when_required(self):
        sdk, _issuer = make_sdk()
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))

        outcome = sdk.run_effect(
            issued.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key="run-key",
            execution_id="exec-run",
            handler=lambda: {"external_request_id": EXT_ID},
            receipt_kind=ReceiptKind.HANDLER_OBSERVATION,
            attestation_required=True,
        )
        lease = sdk.execution_leases.get(issued.lease.lease_id)
        sdk.close()

        assert not outcome.allowed
        assert "attestation_required" in outcome.reason
        assert lease.state is ExecutionState.STARTED

    def test_an_attestor_that_raises_refuses_instead_of_raising(self):
        """Evidence that could not be obtained is a refusal, not a crash.

        The handler already ran, so the effect is recorded; the completion
        is what must fail closed, and a caller's ``except`` must never be
        what decides that.
        """

        sdk, _issuer = make_sdk()
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))

        def attestor(observation):
            raise RuntimeError("the external status API is unreachable")

        outcome = sdk.run_effect(
            issued.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key="run-key",
            execution_id="exec-run",
            handler=lambda: {"external_request_id": EXT_ID},
            receipt_kind=ReceiptKind.HANDLER_OBSERVATION,
            attestor=attestor,
        )
        claims = sdk.attestation_records()
        lease = sdk.execution_leases.get(issued.lease.lease_id)
        sdk.close()

        assert not outcome.allowed
        assert "attestation" in outcome.reason
        assert any("attestor raised" in (claim.note or "") for claim in claims)
        assert lease.state is ExecutionState.STARTED

    def test_run_effect_with_a_live_attestor_completes(self):
        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        issued = sdk.authorize_execution(cap, ACTION, dict(REQUEST))

        def attestor(observation):
            row = sdk.effects.by_lease(issued.lease.lease_id)
            return build_attestation(
                issuer_id=ISSUER,
                key_id=KEY_ID,
                private_key=issuer.private,
                effect_id=row.effect_id,
                lease_id=row.lease_id,
                attempt_id=row.attempt_id,
                effect_digest=row.effect_digest,
                capability_fingerprint=row.capability_fingerprint,
                agent_id=row.agent_id,
                action=row.action,
                idempotency_key=row.idempotency_key,
                state_digest=canonical_external_state_digest({"run": True}),
                external_request_id=observation["external_request_id"],
                observed_outcome="succeeded",
                provider=row.provider,
                execution_id=row.execution_id,
            )

        outcome = sdk.run_effect(
            issued.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key="run-key",
            execution_id="exec-run",
            handler=lambda: {
                "external_request_id": EXT_ID,
                "provider": PROVIDER,
            },
            receipt_kind=ReceiptKind.HANDLER_OBSERVATION,
            attestor=attestor,
        )
        lease = sdk.execution_leases.get(issued.lease.lease_id)
        result = audit(sdk)
        sdk.close()

        assert outcome.allowed, outcome.reason
        assert lease.state is ExecutionState.COMPLETED
        assert result.status is InvariantStatus.HOLDS

    def test_an_unreadable_trust_store_is_a_refusal(self):
        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)
        envelope = build_env(sdk, started.lease, issuer=issuer)

        class Unreadable:
            def get(self, *args, **kwargs):
                raise RuntimeError("the trust store is unreachable")

        sdk.external_issuers = Unreadable()

        result = attest(sdk, started.lease, cap, envelope)
        sdk.close()

        assert not result.allowed
        assert result.reason == "attestation_trust_unavailable"

    def test_an_unreadable_clock_is_a_refusal(self):
        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)
        envelope = build_env(sdk, started.lease, issuer=issuer)

        def broken_clock():
            raise RuntimeError("the clock is unreachable")

        sdk.attestations._clock = broken_clock

        result = attest(sdk, started.lease, cap, envelope)
        sdk.close()

        assert not result.allowed
        # Named precisely: an unreadable clock cannot answer the freshness
        # question *or* stamp a row, and the refusal says which question
        # went unanswered rather than blaming the journal.
        assert result.reason == "attestation_clock_unavailable"

    def test_an_unwritable_journal_is_a_refusal(self):
        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)
        envelope = build_env(sdk, started.lease, issuer=issuer)

        class BrokenBackend:
            def insert(self, record):
                raise AttestationJournalError("the journal is unwritable")

            def claim_nonce(self, claim):
                raise AttestationJournalError("the journal is unwritable")

        sdk.attestations._backend = BrokenBackend()

        # The nonce claim fails first -- a statement must not be accepted
        # when the ledger that makes it one-shot cannot be written.
        result = attest(sdk, started.lease, cap, envelope)
        sdk.close()

        assert not result.allowed
        assert result.reason == "attestation_store_error"

    def test_a_present_but_unverifiable_envelope_is_never_ignored(self):
        """Supplying an envelope that fails is not the same as not
        supplying one: the refusal names the evidence."""

        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        forged = build_env(
            sdk,
            started.lease,
            issuer=issuer,
            private_key=Ed25519PrivateKey.generate(),
        )
        result = attest(sdk, started.lease, cap, forged)
        outcome = commit(
            sdk,
            started.lease,
            cap,
            attestation=forged,
            attestation_required=True,
        )
        sdk.close()

        assert not result.allowed
        assert not outcome.allowed
        assert outcome.reason == (
            "effect_unattested:attestation_signature_invalid"
        )


# ======================================================================
# Invariant teeth: edit the records and the check must say so
# ======================================================================


class TestInvariantTeeth:
    def _attested(self, **kwargs):
        sdk, issuer = make_sdk(**kwargs)
        cap = make_capability(sdk)
        issued, started, receipt, envelope, outcome = walk_attested(
            sdk, cap, issuer=issuer
        )
        return sdk, cap, issued, started, receipt, envelope, outcome

    def _tamper(self, sdk, **changes):
        stored = sdk.attestation_records()[0]
        corrupted = replace(stored, **changes)
        sdk.attestations._records[stored.attestation_id] = corrupted
        return corrupted

    def test_an_attested_row_without_a_verified_signature_is_a_violation(self):
        sdk, *_rest = self._attested()
        self._tamper(sdk, signature_verified=False)
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "without a verified signature" in finding
            for finding in result.findings
        )

    def test_a_forged_issuer_is_a_violation(self):
        sdk, *_rest = self._attested()
        self._tamper(sdk, issuer_id="attacker")
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "does not re-derive" in finding for finding in result.findings
        )

    def test_a_swapped_envelope_is_a_violation(self):
        sdk, *_rest = self._attested()
        self._tamper(sdk, envelope_id="0" * 64)
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "does not re-derive" in finding for finding in result.findings
        )

    def test_an_attested_row_under_an_unsupported_algorithm_is_a_violation(self):
        sdk, *_rest = self._attested()
        self._tamper(sdk, algorithm="RSA-PSS")
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "cannot verify" in finding for finding in result.findings
        )

    def test_an_attested_row_without_a_conclusive_outcome_is_a_violation(self):
        sdk, *_rest = self._attested()
        self._tamper(sdk, asserted_outcome=EffectOutcome.UNKNOWN)
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "only a conclusive outcome" in finding
            for finding in result.findings
        )

    def test_an_attested_row_without_correlation_is_a_violation(self):
        sdk, *_rest = self._attested()
        self._tamper(sdk, correlated=False, correlation_source="none")
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "without a correlation handle" in finding
            for finding in result.findings
        )

    def test_an_attested_row_without_a_state_digest_is_a_violation(self):
        sdk, *_rest = self._attested()
        self._tamper(sdk, state_digest="")
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "ATTESTED without" in finding for finding in result.findings
        )

    def test_a_contradiction_against_nothing_is_a_violation(self):
        sdk, cap, issued, started, _receipt, envelope, _outcome = (
            self._attested()
        )
        row = sdk.effects.by_lease(started.lease.lease_id)

        # A CONTRADICTED claim that contradicts no conclusive statement:
        # UNKNOWN contradicts nothing, so this row cannot be a
        # contradiction whatever produced it.
        sdk.attestations.record(
            effect_id=row.effect_id,
            lease_id=row.lease_id,
            execution_id=row.execution_id,
            attempt_id=row.attempt_id,
            outcome=AttestationOutcome.CONTRADICTED,
            reason="forged contradiction",
            issued_at=envelope.issued_at,
            not_before=envelope.not_before,
            expires_at=envelope.expires_at,
            envelope_id="c" * 64,
            issuer_id=ISSUER,
            key_id=KEY_ID,
            algorithm="Ed25519",
            nonce="forged-nonce",
            effect_digest=row.effect_digest,
            capability_fingerprint=row.capability_fingerprint,
            agent_id=row.agent_id,
            action=row.action,
            idempotency_key=row.idempotency_key,
            asserted_outcome=EffectOutcome.UNKNOWN,
            state_digest="s",
            external_request_id=EXT_ID,
            correlated=True,
            correlation_source="receipt",
        )
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "only conclusive statements contradict" in finding
            for finding in result.findings
        )

    def test_a_completed_lease_without_a_current_claim_is_a_violation(self):
        sdk, *_rest = self._attested(require_external_attestation=True)
        sdk.attestations._records.clear()
        sdk.attestations._by_effect.clear()
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "requires an external attestation" in finding
            for finding in result.findings
        )

    def test_a_completed_lease_with_a_contradiction_standing_is_a_violation(self):
        sdk, cap, issued, started, _receipt, envelope, _outcome = (
            self._attested()
        )
        row = sdk.effects.by_lease(started.lease.lease_id)

        sdk.attestations.record(
            effect_id=row.effect_id,
            lease_id=row.lease_id,
            execution_id=row.execution_id,
            attempt_id=row.attempt_id,
            outcome=AttestationOutcome.CONTRADICTED,
            reason="attestation_contradicted",
            issued_at=envelope.issued_at,
            not_before=envelope.not_before,
            expires_at=envelope.expires_at,
            envelope_id="d" * 64,
            issuer_id=ISSUER,
            key_id=KEY_ID,
            algorithm="Ed25519",
            nonce="contradicting-nonce",
            effect_digest=row.effect_digest,
            capability_fingerprint=row.capability_fingerprint,
            agent_id=row.agent_id,
            action=row.action,
            idempotency_key=row.idempotency_key,
            asserted_outcome=EffectOutcome.FAILED,
            state_digest="s",
            external_request_id=EXT_ID,
            correlated=True,
            correlation_source="receipt",
        )
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "CONTRADICTED attestation stands" in finding
            for finding in result.findings
        )

    def test_a_not_attested_claim_superseding_a_completion_is_a_violation(self):
        sdk, *_rest = self._attested()
        stored = sdk.attestation_records()[0]

        sdk.attestations.record(
            effect_id=stored.effect_id,
            lease_id=stored.lease_id,
            execution_id=stored.execution_id,
            attempt_id=stored.attempt_id,
            outcome=AttestationOutcome.NOT_ATTESTED,
            reason="attestation_expired",
            issued_at=stored.issued_at,
            not_before=stored.not_before,
            expires_at=stored.expires_at,
            envelope_id="e" * 64,
            issuer_id=ISSUER,
            key_id=KEY_ID,
            algorithm="Ed25519",
            nonce="later-nonce",
            effect_digest=stored.effect_digest,
            capability_fingerprint=stored.capability_fingerprint,
            agent_id=stored.agent_id,
            action=stored.action,
            idempotency_key=stored.idempotency_key,
            asserted_outcome=EffectOutcome.SUCCEEDED,
            state_digest="s",
            external_request_id=EXT_ID,
            correlated=True,
            correlation_source="receipt",
        )
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "not attested" in finding for finding in result.findings
        )

    def test_a_missing_ledger_entry_is_a_violation(self):
        sdk, *_rest = self._attested()
        sdk.attestations._nonces.clear()
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "replay ledger" in finding for finding in result.findings
        )

    def test_a_ledger_entry_for_another_effect_is_a_violation(self):
        sdk, *_rest = self._attested()
        (key, claim), = list(sdk.attestations._nonces.items())
        sdk.attestations._nonces[key] = replace(
            claim, effect_id="0" * 32
        )
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "nonce ledger holds envelope" in finding
            for finding in result.findings
        )

    def test_one_envelope_attested_for_two_effects_is_a_violation(self):
        """A lifted claim, built consistently so only the ledger catches it."""

        sdk, issuer = make_sdk()
        cap = make_capability(sdk)

        _a_issued, a_started, _ = walk_to_attempt(
            sdk, cap, execution_id="exec-a", key="key-a"
        )
        record_success(sdk, cap, a_started.lease, key="key-a")
        envelope_a = build_env(sdk, a_started.lease, issuer=issuer)
        assert attest(sdk, a_started.lease, cap, envelope_a, key="key-a").allowed

        _b_issued, b_started, _ = walk_to_attempt(
            sdk, cap, execution_id="exec-b", key="key-b"
        )
        record_success(sdk, cap, b_started.lease, key="key-b")
        row_b = sdk.effects.by_lease(b_started.lease.lease_id)

        # The same signed envelope, re-recorded as an attested claim about
        # a different effect. The id re-derives -- this is not a forged row
        # -- and the ledger is what remembers the statement was already
        # evidence for effect A.
        sdk.attestations.record(
            effect_id=row_b.effect_id,
            lease_id=row_b.lease_id,
            execution_id=row_b.execution_id,
            attempt_id=row_b.attempt_id,
            outcome=AttestationOutcome.ATTESTED,
            reason="attestation_verified",
            issued_at=envelope_a.issued_at,
            not_before=envelope_a.not_before,
            expires_at=envelope_a.expires_at,
            envelope_id=envelope_a.envelope_id,
            issuer_id=ISSUER,
            key_id=KEY_ID,
            algorithm="Ed25519",
            nonce=envelope_a.nonce,
            effect_digest=row_b.effect_digest,
            capability_fingerprint=row_b.capability_fingerprint,
            agent_id=row_b.agent_id,
            action=row_b.action,
            idempotency_key=row_b.idempotency_key,
            asserted_outcome=EffectOutcome.SUCCEEDED,
            state_digest=canonical_external_state_digest({"stolen": True}),
            external_request_id=row_b.external_request_id,
            provider=row_b.provider,
            correlated=True,
            correlation_source="receipt",
            signature_verified=True,
        )
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "one signed statement is one" in finding
            or "nonce ledger holds envelope" in finding
            for finding in result.findings
        )

    def test_a_claim_lifted_onto_another_attempt_is_a_violation(self):
        sdk, cap, issued, started, _receipt, envelope, _outcome = (
            self._attested()
        )
        stored = sdk.attestation_records()[0]
        self._tamper(sdk, attempt_id="0" * 32)
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "does not re-derive" in finding
            or "another attempt" in finding
            for finding in result.findings
        )

    def test_the_allow_path_rule_is_not_vacuous(self, monkeypatch):
        """Both halves: a clean tree passes, and a gate reference fails."""

        assert _attestation_source_findings()[0] == ()

        monkeypatch.setattr(
            runtime_module,
            "ATTESTATION_ALLOW_PATH_OWNERS",
            frozenset({"FirewallSDK._attest_row_claim"}),
        )
        findings, _ = _attestation_source_findings()

        assert any("ALLOW path" in finding for finding in findings)


# ======================================================================
# Boundaries: what the layer touches, and what it must never touch
# ======================================================================


class TestBoundaries:
    def test_attestation_does_not_write_the_effect_journal(self):
        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        before = sdk.effects.by_lease(started.lease.lease_id).to_dict()
        envelope = build_env(sdk, started.lease, issuer=issuer)
        assert attest(sdk, started.lease, cap, envelope).allowed
        after = sdk.effects.by_lease(started.lease.lease_id).to_dict()
        sdk.close()

        assert before == after

    def test_attestation_does_not_touch_the_control_plane(self):
        from firewall.invariants import control_plane_snapshot

        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        before = control_plane_snapshot(sdk)
        envelope = build_env(sdk, started.lease, issuer=issuer)
        assert attest(sdk, started.lease, cap, envelope).allowed
        commit(
            sdk,
            started.lease,
            cap,
            attestation=envelope,
            attestation_required=True,
        )
        after = control_plane_snapshot(sdk)
        sdk.close()

        assert before == after

    def test_the_attestation_journal_is_not_the_verification_journal(self):
        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        issued, started, _, envelope, _outcome = walk_attested(
            sdk, cap, issuer=issuer
        )
        attestation_claims = sdk.attestation_records()
        verification_claims = sdk.verification_records()
        sdk.close()

        assert len(attestation_claims) == 1
        assert len(verification_claims) == 1
        assert attestation_claims[0].attestation_id != (
            verification_claims[0].verification_id
        )
        assert (
            attestation_claims[0].effect_id
            == verification_claims[0].effect_id
        )

    def test_a_refusal_is_data_never_an_exception(self):
        """The boundary rule holds on the attestation path too."""

        sdk, _issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        for junk in (
            None,
            42,
            "not-an-envelope",
            [],
            {"effect_id": "e"},
        ):
            result = attest(sdk, started.lease, cap, junk)
            assert result.allowed is False
            assert isinstance(result.reason, str) and result.reason

        sdk.close()

    def test_an_attested_effect_is_distinguishable_from_a_recorded_one(self):
        """The release's whole point, asserted as data.

        ``record_effect_receipt`` alone leaves a row the firewall wrote.
        ``record_attestation`` adds a row signed outside it. The two are
        different rows in different journals with different provenance,
        which is what makes them different claims.
        """

        sdk, issuer = make_sdk()
        cap = make_capability(sdk)
        _issued, started, _ = walk_to_attempt(sdk, cap)
        record_success(sdk, cap, started.lease)

        row = sdk.effects.by_lease(started.lease.lease_id)
        assert row.state is EffectState.SUCCEEDED
        assert row.evidence_kind is ReceiptKind.PROVIDER_EVIDENCE
        assert sdk.attestation_records() == ()

        envelope = build_env(sdk, started.lease, issuer=issuer)
        result = attest(sdk, started.lease, cap, envelope)
        claim = result.record
        sdk.close()

        # The row says the firewall recorded a provider-evidence
        # observation; the attestation says a named external issuer signed
        # a statement, with that issuer's key, nonce and state digest.
        assert claim.outcome is AttestationOutcome.ATTESTED
        assert claim.issuer_id == ISSUER
        assert claim.envelope_id == envelope.envelope_id
        assert claim.state_digest == envelope.state_digest
        assert claim.signature_verified is True
        assert row.effect_id == claim.effect_id
