"""v2.9: effect verification soundness -- attack the twentieth invariant.

v2.8 recorded what happened. v2.9 establishes whether the recorded claim
can be trusted:

    AUTHORIZED =/= EXECUTED =/= OBSERVED =/= VERIFIED =/= COMPLETED

``EFFECT_VERIFICATION_SOUNDNESS`` (the twentieth registered invariant)
machine-checks the new layer: every recorded verification claim binds to
the exact effect, attempt and evidence snapshot it speaks about,
re-derives to its own id, never confirms provider-labelled evidence
through the structural method, can neither grant authority nor resurrect
a revoked or expired execution, and is required -- current, VERIFIED, and
uncontradicted -- before a lease over an adopted side effect may be
recorded COMPLETED.

This file tests the invariant's teeth and its calibrations the same way
test_v2_8_commit_integrity.py did for SIDE_EFFECT_COMMIT_INTEGRITY:
positive controls through the real protocol report HOLDS, and every
forged, replayed, stale or cross-execution claim the invariant exists to
catch is a VIOLATION. The strict-chain semantics are also tested at the
SDK boundary, where the completion gate must refuse before any record
could be forged.
"""

from __future__ import annotations

import uuid

from dataclasses import replace

from firewall.effect import (
    EffectOutcome,
    ReceiptKind,
)
from firewall.effect_verification import (
    STRUCTURAL_METHOD,
    VerificationOutcome,
    VerifierVerdict,
    canonical_snapshot_digest,
    verification_binding_digest,
)
from firewall.execution_lease import ExecutionState
from firewall.invariants import (
    check_effect_verification_soundness,
)
from firewall.invariants.model import InvariantStatus
from firewall.sdk import FirewallSDK

ACTION = "payments.send"
REQUEST = {"amount": 5}
EFFECT = {"to": "acct-9", "amount": 5}
EFFECT_TYPE = "transfer"
KEY = "key-verification"


def make_capability(sdk):
    key = sdk.generate_key(f"v29c-{uuid.uuid4().hex[:10]}").private_key
    return sdk.issue(
        agent="agent-a",
        capability=ACTION,
        private_key=key,
        constraints={"amount_max": 100},
    )


def walk_to_attempt(sdk, cap, execution_id=None):
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
        idempotency_key=KEY,
    )
    assert prepared.allowed, prepared.reason
    attempted = sdk.attempt_effect(
        started.lease,
        cap,
        ACTION,
        dict(REQUEST),
        effect=dict(EFFECT),
        effect_type=EFFECT_TYPE,
        idempotency_key=KEY,
    )
    assert attempted.allowed, attempted.reason
    return issued, started, attempted


def walk_clean_verified(sdk, cap, *, kind=None, execution_id=None):
    """The full protocol to a VERIFIED SUCCEEDED row on a COMPLETED lease.

    ``kind`` selects the receipt's evidence kind. Default is a handler
    observation, which the structural verifier confirms; when the caller
    passes ``ReceiptKind.PROVIDER_EVIDENCE`` a named authenticator is
    used instead, mirroring what a real deployment must wire.
    """

    kind = kind if kind is not None else ReceiptKind.HANDLER_OBSERVATION
    issued, started, _attempted = walk_to_attempt(
        sdk, cap, execution_id=execution_id
    )

    receipt = sdk.record_effect_receipt(
        started.lease,
        cap,
        ACTION,
        dict(REQUEST),
        effect=dict(EFFECT),
        effect_type=EFFECT_TYPE,
        idempotency_key=KEY,
        observed_outcome=EffectOutcome.SUCCEEDED,
        evidence_kind=kind,
        external_request_id="ext-verified",
    )
    assert receipt.allowed, receipt.reason

    if kind is ReceiptKind.PROVIDER_EVIDENCE:
        def authenticator(evidence):
            return VerifierVerdict(
                outcome=VerificationOutcome.VERIFIED,
                method="acme-authenticator",
                note="acme status API confirmed the recorded request",
            )

        commit = sdk.commit_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            verifier=authenticator,
            method="acme-authenticator",
        )
    else:
        commit = sdk.commit_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )

    assert commit.allowed, commit.reason
    return issued, receipt, commit


def audit(sdk):
    return check_effect_verification_soundness(sdk)


class TestCalibrationAndToothlessness:
    def test_the_calibration_records_hold(self):
        """A verified handler observation through the real protocol is not
        a violation."""

        sdk = FirewallSDK()
        cap = make_capability(sdk)
        _, _, commit = walk_clean_verified(sdk, cap)
        result = audit(sdk)
        record = sdk.execution_leases.get(commit.lease.lease_id)
        sdk.close()

        assert result.status is InvariantStatus.HOLDS
        assert record.state is ExecutionState.COMPLETED

    def test_a_fresh_sdk_is_unverifiable_not_violated(self):
        sdk = FirewallSDK()
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.UNVERIFIABLE

    def test_provider_evidence_verified_by_a_named_authenticator_holds(self):
        """Provider evidence may be confirmed only by an authenticating
        verifier the deployment wired; the invariant accepts that path."""

        sdk = FirewallSDK()
        cap = make_capability(sdk)
        walk_clean_verified(
            sdk, cap, kind=ReceiptKind.PROVIDER_EVIDENCE
        )
        result = audit(sdk)
        claims = sdk.verification_records()
        sdk.close()

        assert result.status is InvariantStatus.HOLDS
        assert any(
            claim.method == "acme-authenticator"
            and claim.outcome is VerificationOutcome.VERIFIED
            for claim in claims
        )


class TestStrictChainAtTheBoundary:
    def test_observed_does_not_complete(self):
        """OBSERVED =/= COMPLETED: a succeeded receipt alone cannot close
        the lease; the completion gate refuses until a VERIFIED claim
        exists."""

        sdk = FirewallSDK()
        cap = make_capability(sdk)
        issued, started, _ = walk_to_attempt(sdk, cap)

        receipt = sdk.record_effect_receipt(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            observed_outcome=EffectOutcome.SUCCEEDED,
            evidence_kind=ReceiptKind.HANDLER_OBSERVATION,
        )
        assert receipt.allowed, receipt.reason

        refused = sdk.complete_execution(
            started.lease, cap, ACTION, dict(REQUEST)
        )
        record = sdk.execution_leases.get(issued.lease.lease_id)
        sdk.close()

        assert not refused.allowed
        assert "effect_unverified" in refused.reason
        # Still started: the refusal leaves the record recoverable.
        assert record.state is ExecutionState.STARTED

    def test_commit_runs_the_verifier_and_then_completes(self):
        sdk = FirewallSDK()
        cap = make_capability(sdk)
        _, _, commit = walk_clean_verified(sdk, cap)
        claims = sdk.verification_records()
        sdk.close()

        assert commit.allowed
        assert len(claims) == 1
        assert claims[0].outcome is VerificationOutcome.VERIFIED
        assert claims[0].method == STRUCTURAL_METHOD

    def test_a_contradiction_poisons_a_later_verified_claim(self):
        """Contradictory evidence is preserved and must prevent completion:
        a CONTRADICTED claim on the same snapshot outranks anything
        recorded after it."""

        sdk = FirewallSDK()
        cap = make_capability(sdk)
        issued, started, _ = walk_to_attempt(sdk, cap)
        sdk.record_effect_receipt(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            observed_outcome=EffectOutcome.SUCCEEDED,
            evidence_kind=ReceiptKind.HANDLER_OBSERVATION,
        )

        # First a clean verification...
        v1 = sdk.verify_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        assert v1.allowed, v1.reason

        # ...then an auditor's contradiction of the same evidence.
        def contradictor(evidence):
            return VerifierVerdict(
                outcome=VerificationOutcome.CONTRADICTED,
                method="internal-auditor",
                note="the recorded correlation id does not match the "
                "provider ledger",
            )

        v2 = sdk.verify_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            verifier=contradictor,
            method="internal-auditor",
        )
        assert not v2.allowed
        assert v2.reason == "effect_contradicted"

        # The structural verifier would say VERIFIED again, but the gate
        # must not let a contradiction be papered over by re-verifying.
        refused = sdk.commit_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        record = sdk.execution_leases.get(issued.lease.lease_id)
        sdk.close()

        assert not refused.allowed
        assert "evidence_contradicted" in refused.reason
        assert record.state is ExecutionState.STARTED

    def test_verification_requires_a_named_method(self):
        """The journal must never guess whose check a claim came from."""

        sdk = FirewallSDK()
        cap = make_capability(sdk)
        issued, started, _ = walk_to_attempt(sdk, cap)
        sdk.record_effect_receipt(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            observed_outcome=EffectOutcome.SUCCEEDED,
            evidence_kind=ReceiptKind.PROVIDER_EVIDENCE,
        )

        def authenticator(evidence):
            return VerifierVerdict(
                outcome=VerificationOutcome.VERIFIED,
                method="acme-authenticator",
            )

        # A verifier without a method: refused.
        r1 = sdk.verify_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            verifier=authenticator,
        )
        # A verifier claiming the structural id: refused (impersonation).
        r2 = sdk.verify_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            verifier=authenticator,
            method=STRUCTURAL_METHOD,
        )
        # A verifier returning a bare bool, not a VerifierVerdict: refused.
        r3 = sdk.verify_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            verifier=lambda evidence: True,
            method="acme-authenticator",
        )
        sdk.close()

        assert not r1.allowed and r1.reason == "invalid_verification_method"
        assert not r2.allowed and r2.reason == "invalid_verification_method"
        assert not r3.allowed and r3.reason == "invalid_verifier_verdict"

    def test_verification_cannot_resurrect_revoked_authority(self):
        """VERIFIED never re-authorizes: after revocation the verifier's
        VERIFIED verdict is preserved as NOT_VERIFIED, the lease burns to
        REVOKED, and no claim can be recorded as verified."""

        sdk = FirewallSDK()
        cap = make_capability(sdk)
        issued, started, _ = walk_to_attempt(sdk, cap)
        sdk.record_effect_receipt(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            observed_outcome=EffectOutcome.SUCCEEDED,
            evidence_kind=ReceiptKind.HANDLER_OBSERVATION,
        )
        sdk.revoke(cap, reason="withdrawn")

        r = sdk.verify_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        claims = sdk.verification_records()
        record = sdk.execution_leases.get(issued.lease.lease_id)
        sdk.close()

        assert not r.allowed
        assert "capability_revoked" in r.reason
        assert record.state is ExecutionState.REVOKED
        assert claims  # truthfully recorded...
        assert all(
            claim.outcome is not VerificationOutcome.VERIFIED
            for claim in claims
        )

    def test_verification_grants_nothing(self):
        """A HOLDS report does not make a denied authorization allowed."""

        sdk = FirewallSDK()
        cap = make_capability(sdk)
        walk_clean_verified(sdk, cap)
        result = audit(sdk)

        denied = sdk.authorize(cap, ACTION, {"amount": 10_000})
        sdk.close()

        assert result.status is InvariantStatus.HOLDS
        assert denied.allowed is False

    def test_verification_for_another_effect_is_refused(self):
        """The claim binds the exact effect: presenting a different effect
        (same lease) cannot be verified."""

        sdk = FirewallSDK()
        cap = make_capability(sdk)
        issued, started, _ = walk_to_attempt(sdk, cap)
        sdk.record_effect_receipt(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            observed_outcome=EffectOutcome.SUCCEEDED,
            evidence_kind=ReceiptKind.HANDLER_OBSERVATION,
        )
        other = {"to": "acct-other", "amount": 999}
        r = sdk.verify_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=other,
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        sdk.close()

        assert not r.allowed
        assert r.reason == "effect_mismatch"


class TestInvariantRecordTeeth:
    def _sdk_with_verified_row(self):
        sdk = FirewallSDK()
        cap = make_capability(sdk)
        _, _, _commit = walk_clean_verified(sdk, cap)
        claims = sdk.verification_records()
        assert len(claims) == 1
        return sdk, claims[0]

    def test_a_forged_id_is_a_violation(self):
        """A record whose stored id does not re-derive from its binding is
        forged; the invariant names it."""

        sdk, claim = self._sdk_with_verified_row()

        # Keep the id, change the method: the id no longer re-derives.
        forged = replace(claim, method="intruder")
        sdk.verifications._records[forged.verification_id] = forged
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any("does not re-derive" in f for f in result.findings)

    def test_structural_verifying_provider_evidence_is_a_violation(self):
        """A label is not proof: a VERIFIED claim on provider evidence
        through the structural method is exactly the lie the invariant
        exists to catch."""

        sdk, claim = self._sdk_with_verified_row()

        snapshot = dict(claim.snapshot)
        snapshot["evidence_kind"] = ReceiptKind.PROVIDER_EVIDENCE.value
        forged = replace(claim, snapshot=snapshot)
        forged = replace(
            forged,
            snapshot_digest=canonical_snapshot_digest(snapshot),
        )
        sdk.verifications._records[forged.verification_id] = forged
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any("a label is not proof" in f for f in result.findings)

    def test_verified_over_lost_authority_is_a_violation(self):
        """VERIFIED must never resurrect a withdrawn execution: a claim
        whose snapshot says the receipt was recorded under lost authority
        is a violation."""

        sdk, claim = self._sdk_with_verified_row()

        snapshot = dict(claim.snapshot)
        snapshot["receipt_authority_valid"] = False
        forged = replace(claim, snapshot=snapshot)
        forged = replace(
            forged,
            snapshot_digest=canonical_snapshot_digest(snapshot),
        )
        sdk.verifications._records[forged.verification_id] = forged
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any("lost authority" in f for f in result.findings)

    def test_a_claim_for_an_unrecorded_effect_is_a_violation(self):
        """A verification claim must speak about a recorded effect."""

        sdk, claim = self._sdk_with_verified_row()

        orphan = replace(claim, effect_id="0" * 64, attempt_id="1" * 32)
        orphan = replace(
            orphan,
            verification_id=verification_binding_digest(
                effect_id=orphan.effect_id,
                attempt_id=orphan.attempt_id,
                snapshot_digest=orphan.snapshot_digest,
                outcome=orphan.outcome,
                method=orphan.method,
            ),
        )
        sdk.verifications._records[orphan.verification_id] = orphan
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any("which has no side-effect row" in f for f in result.findings)

    def test_a_completed_lease_with_stale_verification_is_a_violation(self):
        """A completed execution over an adopted side effect must carry a
        current VERIFIED claim: moving the effect's evidence after the
        fact (here by forging the row) leaves the verification stale."""

        sdk, claim = self._sdk_with_verified_row()

        row = sdk.effects.get(claim.effect_id)
        forged = replace(row, external_request_id="moved-after-verify")
        sdk.effects._records[forged.effect_id] = forged
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "no verification claim speaks about the row's current "
            "evidence" in f
            for f in result.findings
        )

    def test_a_claim_about_another_attempt_is_a_violation(self):
        """Verification binds the attempt: a claim whose attempt is not
        the row's current attempt is cross-execution evidence."""

        sdk, claim = self._sdk_with_verified_row()

        cross = replace(claim, attempt_id="9" * 32)
        cross = replace(
            cross,
            verification_id=verification_binding_digest(
                effect_id=cross.effect_id,
                attempt_id=cross.attempt_id,
                snapshot_digest=cross.snapshot_digest,
                outcome=cross.outcome,
                method=cross.method,
            ),
        )
        sdk.verifications._records[cross.verification_id] = cross
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any("current attempt" in f for f in result.findings)


class TestVerificationJournalBasics:
    def test_idempotent_re_verification_records_once(self):
        """The claim's natural id dedupes: re-running the identical
        verification returns the existing claim and writes nothing new."""

        sdk = FirewallSDK()
        cap = make_capability(sdk)
        issued, started, _ = walk_to_attempt(sdk, cap)
        sdk.record_effect_receipt(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            observed_outcome=EffectOutcome.SUCCEEDED,
            evidence_kind=ReceiptKind.HANDLER_OBSERVATION,
        )
        v1 = sdk.verify_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        v2 = sdk.verify_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        claims = sdk.verification_records()
        sdk.close()

        assert v1.allowed and v2.allowed
        assert len(claims) == 1

    def test_reconciliation_makes_a_claim_stale_until_reverified(self):
        """Verification speaks about one snapshot. If the effect is later
        reconciled to a different state the old claim no longer matches,
        and the execution cannot complete until the new evidence is
        verified."""

        sdk = FirewallSDK()
        cap = make_capability(sdk)
        issued, started, _ = walk_to_attempt(sdk, cap)

        # Record an UNKNOWN receipt, then reconcile it to a confirmed
        # success: the evidence snapshot changed after the attempt.
        sdk.record_effect_receipt(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            observed_outcome=EffectOutcome.UNKNOWN,
            evidence_kind=ReceiptKind.HANDLER_OBSERVATION,
        )
        reconciled = sdk.reconcile_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            resolution=EffectOutcome.SUCCEEDED,
            evidence_kind=ReceiptKind.HANDLER_OBSERVATION,
        )
        assert reconciled.allowed, reconciled.reason

        # Verify the *reconciled* claim; the attempt is unchanged but the
        # evidence (a second observation) is fresh.
        v = sdk.verify_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        assert v.allowed, v.reason

        commit = sdk.commit_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        record = sdk.execution_leases.get(issued.lease.lease_id)
        sdk.close()

        assert commit.allowed, commit.reason
        assert record.state is ExecutionState.COMPLETED

    def test_the_claim_id_binds_method_and_verdict(self):
        """A NOT_VERIFIED structural attempt and a later VERIFIED claim
        from a named authenticator are distinct rows; the later one is
        what the completion gate reads."""

        sdk = FirewallSDK()
        cap = make_capability(sdk)
        issued, started, _ = walk_to_attempt(sdk, cap)
        sdk.record_effect_receipt(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            observed_outcome=EffectOutcome.SUCCEEDED,
            evidence_kind=ReceiptKind.PROVIDER_EVIDENCE,
        )

        # Structural refuses provider evidence...
        first = sdk.verify_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        assert not first.allowed
        assert first.reason == "effect_not_verified"

        # ...and the named authenticator confirms it on the same evidence.
        def authenticator(evidence):
            return VerifierVerdict(
                outcome=VerificationOutcome.VERIFIED,
                method="acme-authenticator",
            )

        second = sdk.verify_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            verifier=authenticator,
            method="acme-authenticator",
        )
        commit = sdk.commit_effect(
            started.lease,
            cap,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        record = sdk.execution_leases.get(issued.lease.lease_id)
        sdk.close()

        assert not first.allowed
        assert second.allowed, second.reason
        assert commit.allowed, commit.reason
        assert record.state is ExecutionState.COMPLETED
