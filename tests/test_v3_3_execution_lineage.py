"""v3.3: execution lineage soundness -- attack the twenty-fourth invariant.

Every release before this one answered a question about one *stage* of an
execution: v2.7 recorded the continuation of an allow, v2.8 the side effect,
v2.9 the verification, v3.1 the external attestation, v3.2 the temporal
context each of those is valid in. None of them established that the stages
belong to **one execution**, that they happened in that order, or that
nothing was forked, grafted or re-ordered along the way.

``EXECUTION_LINEAGE_SOUNDNESS`` (the twenty-fourth registered invariant)
machine-checks that layer:

.. code-block:: text

    AUTHORIZED -> EXECUTED -> OBSERVED -> VERIFIED -> ATTESTED -> COMPLETED

* **Intact** -- every commitment re-derives its own id, chains to the one
  before it from a fixed genesis anchor, sits at a contiguous sequence and
  the ordinal its stage requires, and accumulates a binding that may gain a
  field and never change or drop one.
* **Unique** -- one lineage per lease and per execution identity, exactly one
  commitment per stage, at most one seal and it is last.
* **Correctly bound** -- the chain agrees with the lease record it claims and
  with the effect row each evidence commitment describes.
* **Tamper-evident** -- the whole chain is re-derived from the four journals
  by the invariant, so a stale or edited record cannot hide.

This file attacks each of those from both sides -- the SDK boundary and the
invariant -- and asserts that the *gate* fails closed, not merely that the
audit notices afterwards.
"""

from __future__ import annotations

import json
import os
import threading
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
from firewall.execution_lease import (
    ExecutionLease,
    ExecutionState,
)
from firewall.external_attestation import (
    AttestationOutcome,
    build_attestation,
    canonical_external_state_digest,
)
from firewall.invariants import check_execution_lineage_soundness
from firewall.invariants import runtime as runtime_module
from firewall.invariants.model import InvariantStatus
from firewall.invariants.runtime import (
    _lineage_grouped,
    _lineage_source_findings,
)
from firewall.lineage import (
    BINDING_FIELDS,
    LINEAGE_ANCHOR,
    STAGE_ORDINAL,
    STAGE_ORDER,
    ExecutionLineage,
    LineageBindingError,
    LineageBrokenError,
    LineageConflictError,
    LineageJournal,
    LineageKind,
    LineageOutcome,
    LineageSealedError,
    LineageStage,
    LineageStageOrderError,
    LineageSubjectMismatchError,
    binding_digest,
    canonical_binding,
    canonical_evidence_digest,
    completeness_problems,
    link_id,
    merge_binding,
)
from firewall.lineage_store import SQLiteLineageStore
from firewall.sdk import FirewallSDK

ACTION = "payments.send"
REQUEST = {"amount": 5}
EFFECT = {"to": "acct-9", "amount": 5}
EFFECT_TYPE = "transfer"
KEY = "key-lineage"
PROVIDER = "acme-payments"

ISSUER_PRIVATE = Ed25519PrivateKey.generate()

BINDING = {
    "lease_id": "lease-1",
    "capability_fingerprint": "fp-1",
    "agent_id": "agent-a",
    "capability": ACTION,
    "action": ACTION,
    "request_digest": "rd-1",
    "policy_version": "p-1",
    # Part of the binding rather than a free-floating argument: the genesis
    # commits it, and the accumulate-only rule then refuses any later stage
    # that drops it -- which is what makes "one lineage per execution
    # identity" a property the chain enforces rather than one the index
    # merely hopes for.
    "execution_id": "exec-1",
}

PRIOR = tuple(STAGE_ORDER[:-1])


# ======================================================================
# Helpers
# ======================================================================


def make_sdk(**kwargs):
    sdk = FirewallSDK(**kwargs)
    sdk.generate_key(f"v33-{uuid.uuid4().hex[:8]}")
    sdk.trust_external_issuer(PROVIDER, "acme-key-1", ISSUER_PRIVATE.public_key())
    return sdk


def make_capability(sdk):
    return sdk.issue(
        agent="agent-a",
        capability=ACTION,
        constraints={"amount_max": 100},
    )


def walk_to_attempt(sdk, capability, *, execution_id="exec-lineage", key=KEY):
    issued = sdk.authorize_execution(capability, ACTION, dict(REQUEST))
    assert issued.allowed, issued.reason
    reserved = sdk.reserve_execution(
        issued.lease,
        capability,
        ACTION,
        dict(REQUEST),
        execution_id=execution_id,
    )
    assert reserved.allowed, reserved.reason
    started = sdk.start_execution(
        reserved.lease, capability, ACTION, dict(REQUEST)
    )
    assert started.allowed, started.reason
    prepared = sdk.prepare_effect(
        started.lease,
        capability,
        ACTION,
        dict(REQUEST),
        effect=dict(EFFECT),
        effect_type=EFFECT_TYPE,
        idempotency_key=key,
    )
    assert prepared.allowed, prepared.reason
    attempted = sdk.attempt_effect(
        started.lease,
        capability,
        ACTION,
        dict(REQUEST),
        effect=dict(EFFECT),
        effect_type=EFFECT_TYPE,
        idempotency_key=key,
    )
    assert attempted.allowed, attempted.reason
    return issued, started


def record_success(sdk, capability, lease, *, key=KEY):
    receipt = sdk.record_effect_receipt(
        lease,
        capability,
        ACTION,
        dict(REQUEST),
        effect=dict(EFFECT),
        effect_type=EFFECT_TYPE,
        idempotency_key=key,
        observed_outcome=EffectOutcome.SUCCEEDED,
        evidence_kind=ReceiptKind.PROVIDER_EVIDENCE,
        external_request_id="ext-lineage",
        provider=PROVIDER,
    )
    assert receipt.allowed, receipt.reason
    return receipt


def authenticator(evidence):
    return VerifierVerdict(
        outcome=VerificationOutcome.VERIFIED,
        method="acme-authenticator",
        note="acme status api confirmed the recorded request",
    )


def envelope_for(sdk, lease, *, ttl=3_600.0):
    row = sdk.effects.by_lease(lease.lease_id)
    assert row is not None

    return build_attestation(
        issuer_id=PROVIDER,
        key_id="acme-key-1",
        private_key=ISSUER_PRIVATE,
        effect_id=row.effect_id,
        lease_id=row.lease_id,
        attempt_id=row.attempt_id,
        effect_digest=row.effect_digest,
        capability_fingerprint=row.capability_fingerprint,
        agent_id=row.agent_id,
        action=row.action,
        idempotency_key=row.idempotency_key,
        state_digest=canonical_external_state_digest(
            {"nonce": uuid.uuid4().hex}
        ),
        external_request_id=row.external_request_id or "",
        observed_outcome="succeeded",
        provider=row.provider,
        execution_id=row.execution_id,
        ttl=ttl,
    )


def attest(sdk, lease, capability, envelope, *, key=KEY):
    return sdk.record_attestation(
        lease,
        capability,
        ACTION,
        dict(REQUEST),
        effect=dict(EFFECT),
        effect_type=EFFECT_TYPE,
        idempotency_key=key,
        attestation=envelope,
    )


def audit(sdk):
    return check_execution_lineage_soundness(sdk)


def walk_completed(sdk, capability, *, with_attestation=False, execution_id=None):
    """The whole pipeline to a COMPLETED lease, optionally attested."""

    issued, started = walk_to_attempt(
        sdk, capability, execution_id=execution_id or "exec-complete"
    )
    record_success(sdk, capability, started.lease)

    kwargs = {
        "verifier": authenticator,
        "method": "acme-authenticator",
    }
    envelope = None

    if with_attestation:
        envelope = envelope_for(sdk, started.lease)
        attested = attest(sdk, started.lease, capability, envelope)
        assert attested.allowed, attested.reason
        kwargs["attestation"] = envelope
        kwargs["attestation_required"] = True

    outcome = sdk.commit_effect(
        started.lease,
        capability,
        ACTION,
        dict(REQUEST),
        effect=dict(EFFECT),
        effect_type=EFFECT_TYPE,
        idempotency_key=KEY,
        **kwargs,
    )
    assert outcome.allowed, outcome.reason

    return issued, started, outcome


def lineage_of(sdk, lease_id):
    lineage = sdk.lineage_for_lease(lease_id)
    assert lineage is not None, "no lineage for this lease"
    return lineage


# ======================================================================
# Calibration
# ======================================================================


class TestCalibration:
    def test_the_full_pipeline_completes_with_all_six_stages(self):
        sdk = make_sdk()
        capability = make_capability(sdk)
        issued, _started, outcome = walk_completed(
            sdk, capability, with_attestation=True
        )
        lineage = lineage_of(sdk, issued.lease.lease_id)
        result = audit(sdk)
        sdk.close()

        assert outcome.allowed
        assert [stage for stage in lineage.stages] == list(STAGE_ORDER)
        assert lineage.verify() == ()
        assert lineage.completed is True
        assert lineage.sealed is True
        assert result.status is InvariantStatus.HOLDS, result.reason
        assert result.details["completed"] == 1

    def test_an_execution_without_a_side_effect_records_not_adopted(self):
        sdk = make_sdk()
        capability = make_capability(sdk)
        issued = sdk.authorize_execution(capability, ACTION, dict(REQUEST))
        reserved = sdk.reserve_execution(
            issued.lease, capability, ACTION, dict(REQUEST), execution_id="x"
        )
        started = sdk.start_execution(
            reserved.lease, capability, ACTION, dict(REQUEST)
        )
        outcome = sdk.complete_execution(
            started.lease, capability, ACTION, dict(REQUEST)
        )
        lineage = lineage_of(sdk, issued.lease.lease_id)
        result = audit(sdk)
        sdk.close()

        assert outcome.allowed, outcome.reason
        assert lineage.stages == STAGE_ORDER
        assert lineage.outcome_of(LineageStage.OBSERVED) is (
            LineageOutcome.NOT_ADOPTED
        )
        assert lineage.outcome_of(LineageStage.VERIFIED) is (
            LineageOutcome.NOT_ADOPTED
        )
        assert lineage.outcome_of(LineageStage.ATTESTED) is (
            LineageOutcome.NOT_ADOPTED
        )
        assert result.status is InvariantStatus.HOLDS

    def test_a_fresh_sdk_is_unverifiable_not_violated(self):
        sdk = make_sdk()
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.UNVERIFIABLE
        assert "no execution lineage has been opened" in result.reason

    def test_no_sdk_is_unverifiable(self):
        result = audit(None)

        assert result.status is InvariantStatus.UNVERIFIABLE
        assert result.holds is False

    def test_a_lease_alone_holds_for_the_chain_it_has(self):
        """One stage committed, chain intact -- the audit says so."""

        sdk = make_sdk()
        capability = make_capability(sdk)
        issued = sdk.authorize_execution(capability, ACTION, dict(REQUEST))
        lineage = lineage_of(sdk, issued.lease.lease_id)
        result = audit(sdk)
        sdk.close()

        assert lineage.stages == (LineageStage.AUTHORIZED,)
        assert result.status is InvariantStatus.HOLDS

    def test_the_source_census_is_closed(self):
        findings, notes = _lineage_source_findings()

        assert findings == ()
        assert "ALLOW path" in notes[0]


# ======================================================================
# The chain's own rules: order, idempotence, binding, sealing
# ======================================================================


class TestChainDiscipline:
    def _journal(self):
        journal = LineageJournal()
        lineage = journal.open(
            lease_id="lease-1",
            execution_id="exec-1",
            binding=dict(BINDING),
            lease_digest="ld-1",
        )
        return journal, lineage

    def advance(self, journal, lineage, stage, **overrides):
        binding = dict(BINDING)
        binding.update(overrides)
        return journal.advance(
            lineage_id=lineage.lineage_id,
            stage=stage,
            outcome=LineageOutcome.ADOPTED,
            evidence={"stage": stage.value, "n": STAGE_ORDINAL[stage]},
            binding=binding,
            lease_digest="ld-1",
        )

    def test_the_genesis_is_anchored_and_ordinal_zero(self):
        _journal, lineage = self._journal()

        assert lineage.genesis.parent_digest == LINEAGE_ANCHOR
        assert lineage.genesis.sequence == 0
        assert lineage.genesis.stage is LineageStage.AUTHORIZED
        assert lineage.genesis.ordinal == 0
        assert lineage.verify() == ()

    def test_a_link_rederives_its_own_id(self):
        journal, lineage = self._journal()
        lineage = self.advance(journal, lineage, LineageStage.EXECUTED)

        for link in lineage.links:
            assert link.rederived_id() == link.commitment_id

    def test_a_skipped_stage_is_refused(self):
        journal, lineage = self._journal()

        with pytest.raises(LineageStageOrderError):
            self.advance(journal, lineage, LineageStage.VERIFIED)

    def test_a_repeated_stage_with_a_different_claim_is_a_fork(self):
        journal, lineage = self._journal()
        self.advance(journal, lineage, LineageStage.EXECUTED)

        with pytest.raises(Exception) as caught:
            journal.advance(
                lineage_id=lineage.lineage_id,
                stage=LineageStage.EXECUTED,
                outcome=LineageOutcome.ADOPTED,
                evidence={"stage": "executed", "n": 999},
                binding=dict(BINDING),
                lease_digest="ld-1",
            )

        assert "different claim" in str(caught.value)
        kinds = [finding.kind for finding in journal.findings()]
        assert "branch" in kinds

    def test_the_identical_claim_twice_is_idempotent(self):
        journal, lineage = self._journal()
        first = self.advance(journal, lineage, LineageStage.EXECUTED)
        second = self.advance(journal, first, LineageStage.EXECUTED)

        assert len(first.links) == len(second.links)

    def test_the_binding_may_gain_a_field_and_never_change_one(self):
        journal, lineage = self._journal()
        lineage = self.advance(
            journal, lineage, LineageStage.EXECUTED, execution_id="exec-1"
        )
        assert lineage.binding["execution_id"] == "exec-1"

        with pytest.raises(LineageSubjectMismatchError):
            self.advance(
                journal, lineage, LineageStage.OBSERVED, agent_id="agent-b"
            )

    def test_a_binding_may_not_lose_a_field_it_had(self):
        journal, lineage = self._journal()
        lineage = self.advance(
            journal, lineage, LineageStage.EXECUTED, effect_id="eff-1"
        )

        partial = dict(BINDING)
        partial["effect_id"] = None

        with pytest.raises(LineageSubjectMismatchError):
            journal.advance(
                lineage_id=lineage.lineage_id,
                stage=LineageStage.OBSERVED,
                outcome=LineageOutcome.ADOPTED,
                evidence={"stage": "observed"},
                binding=partial,
                lease_digest="ld-1",
            )

    def test_a_required_field_may_not_be_nulled(self):
        journal, lineage = self._journal()
        partial = dict(BINDING)
        partial["agent_id"] = None

        with pytest.raises(LineageBindingError):
            journal.advance(
                lineage_id=lineage.lineage_id,
                stage=LineageStage.EXECUTED,
                outcome=LineageOutcome.ADOPTED,
                evidence={"stage": "executed"},
                binding=partial,
                lease_digest="ld-1",
            )

    def test_an_identical_second_genesis_is_idempotent(self):
        """A retry after a crash between the write and the publish."""

        journal, lineage = self._journal()

        again = journal.open(
            lease_id="lease-1",
            execution_id="exec-1",
            binding=dict(BINDING),
            lease_digest="ld-1",
        )

        assert again.lineage_id == lineage.lineage_id
        assert journal.size() == 1
        assert len(journal.links()) == 1

    def test_a_second_genesis_with_another_binding_is_a_substitution(self):
        journal, _lineage = self._journal()
        other = dict(BINDING)
        other["agent_id"] = "agent-b"

        with pytest.raises(LineageSubjectMismatchError):
            journal.open(
                lease_id="lease-1",
                execution_id=None,
                binding=other,
                lease_digest="ld-1",
            )

    def test_a_second_lineage_for_one_execution_identity_is_a_fork(self):
        journal, _lineage = self._journal()
        second = dict(BINDING)
        second["lease_id"] = "lease-2"

        with pytest.raises(LineageConflictError):
            journal.open(
                lease_id="lease-2",
                execution_id="exec-1",
                binding=second,
                lease_digest="ld-2",
            )

    def test_a_seal_ends_the_lineage_and_a_commitment_after_it_is_refused(self):
        journal, lineage = self._journal()
        sealed = journal.seal(lineage_id=lineage.lineage_id, reason="aborted")

        assert sealed.sealed is True
        assert sealed.intact is True
        assert sealed.head.kind is LineageKind.SEAL

        with pytest.raises(LineageSealedError):
            self.advance(journal, sealed, LineageStage.EXECUTED)

    def test_a_second_seal_with_a_different_reason_is_a_fork(self):
        journal, lineage = self._journal()
        journal.seal(lineage_id=lineage.lineage_id, reason="aborted")

        with pytest.raises(Exception) as caught:
            journal.seal(lineage_id=lineage.lineage_id, reason="denied")

        assert "sealed" in str(caught.value)

    def test_the_identical_seal_is_idempotent(self):
        journal, lineage = self._journal()
        first = journal.seal(lineage_id=lineage.lineage_id, reason="aborted")
        second = journal.seal(lineage_id=lineage.lineage_id, reason="aborted")

        assert len(first.links) == len(second.links)

    def test_an_unknown_lineage_is_refused_by_name(self):
        journal = LineageJournal()

        with pytest.raises(Exception) as caught:
            journal.advance(
                lineage_id="nope",
                stage=LineageStage.EXECUTED,
                outcome=LineageOutcome.ADOPTED,
                evidence={},
                binding=dict(BINDING),
                lease_digest="ld",
            )

        assert "no lineage" in str(caught.value)

    def test_a_broken_chain_refuses_every_further_commitment(self):
        journal, lineage = self._journal()
        lineage = self.advance(journal, lineage, LineageStage.EXECUTED)

        # Edit a stored link in place: the digest no longer matches.
        chain = list(journal._links[lineage.lineage_id])
        chain[1] = replace(chain[1], evidence_digest="0" * 64)
        journal._links[lineage.lineage_id] = chain

        with pytest.raises(LineageBrokenError):
            self.advance(journal, lineage, LineageStage.OBSERVED)


# ======================================================================
# Fork detection and cross-execution substitution, at the SDK
# ======================================================================


class TestForkAndSubstitution:
    def test_two_executions_have_two_lineages(self):
        sdk = make_sdk()
        capability = make_capability(sdk)
        first, _ = walk_to_attempt(sdk, capability, execution_id="exec-a")
        second, _ = walk_to_attempt(sdk, capability, execution_id="exec-b")

        one = lineage_of(sdk, first.lease.lease_id)
        two = lineage_of(sdk, second.lease.lease_id)
        result = audit(sdk)
        sdk.close()

        assert one.lineage_id != two.lineage_id
        assert one.binding["execution_id"] == "exec-a"
        assert two.binding["execution_id"] == "exec-b"
        assert result.status is InvariantStatus.HOLDS

    def test_a_second_lineage_for_one_execution_identity_is_refused(self):
        """The fork the store enforces: one identity, one live execution."""

        sdk = make_sdk()
        capability = make_capability(sdk)
        issued = sdk.authorize_execution(capability, ACTION, dict(REQUEST))
        reserved = sdk.reserve_execution(
            issued.lease, capability, ACTION, dict(REQUEST), execution_id="same"
        )
        assert reserved.allowed

        second = sdk.authorize_execution(capability, ACTION, dict(REQUEST))
        refused = sdk.reserve_execution(
            second.lease, capability, ACTION, dict(REQUEST), execution_id="same"
        )
        sdk.close()

        assert not refused.allowed

    def test_cross_execution_substitution_is_refused(self):
        """Evidence from one execution cannot be committed to another's chain.

        The journal's rule catches a field the chain has already *fixed*
        changing; this is the other direction -- evidence belonging to a
        different execution's lease being offered as this one's, which the
        chain would otherwise accept as a newly learned field. Cross-execution
        substitution is only visible where the rows are, so the SDK is what
        refuses it, by name, and records the attempt.
        """

        sdk = make_sdk()
        capability = make_capability(sdk)
        first, _ = walk_to_attempt(sdk, capability, execution_id="exec-a")
        second, _ = walk_to_attempt(sdk, capability, execution_id="exec-b")

        one = lineage_of(sdk, first.lease.lease_id)
        two = lineage_of(sdk, second.lease.lease_id)
        row_two = sdk.effects.by_lease(second.lease.lease_id)
        record_one = sdk.execution_leases.get(first.lease.lease_id)

        # The SDK's rule: the *row* is not this lease's row. The chain has
        # not fixed the effect fields yet -- they are committed at the
        # execution's close -- so the accumulate-only rule alone would take
        # them as newly learned, which is why this check exists.
        reason = sdk._advance_lineage(
            record_one,
            stage=LineageStage.OBSERVED,
            outcome=LineageOutcome.ADOPTED,
            evidence={"stolen": True},
            effect_row=row_two,
        )
        kinds = [finding.kind for finding in sdk.lineage_findings()]
        sdk.close()

        assert reason is not None
        assert reason.startswith("lineage_subject_mismatch")
        assert "subject_mismatch" in kinds
        assert two.lineage_id != one.lineage_id

    def test_the_gate_refuses_a_broken_chain_at_every_step(self):
        """Failing closed, not merely noticing: the SDK refuses to progress."""

        sdk = make_sdk()
        capability = make_capability(sdk)
        issued = sdk.authorize_execution(capability, ACTION, dict(REQUEST))
        lineage = lineage_of(sdk, issued.lease.lease_id)

        chain = list(sdk.lineages._links[lineage.lineage_id])
        sdk.lineages._links[lineage.lineage_id] = [
            replace(chain[0], evidence_digest="0" * 64)
        ]

        refused = sdk.reserve_execution(
            issued.lease, capability, ACTION, dict(REQUEST), execution_id="x"
        )
        lease = sdk.execution_leases.get(issued.lease.lease_id)
        sdk.close()

        assert not refused.allowed
        assert refused.reason.startswith("lineage_broken")
        # The refusal did not move the record: a broken chain is not a
        # statement about the execution's authority.
        assert lease.state is ExecutionState.LEASE_ISSUED

    def test_the_gate_refuses_a_sealed_lineage(self):
        sdk = make_sdk()
        capability = make_capability(sdk)
        issued = sdk.authorize_execution(capability, ACTION, dict(REQUEST))
        lineage = lineage_of(sdk, issued.lease.lease_id)
        sdk.lineages.seal(lineage_id=lineage.lineage_id, reason="operator")

        refused = sdk.reserve_execution(
            issued.lease, capability, ACTION, dict(REQUEST), execution_id="x"
        )
        sdk.close()

        assert not refused.allowed
        assert "lineage_sealed" in refused.reason

    def test_the_gate_refuses_a_stage_mismatch(self):
        """A chain that already holds EXECUTED cannot be reserved again.

        The refusal names the *chain* rather than the phase machine, because
        the lineage check runs first. That ordering is deliberate: the two
        are both correct answers, and the one that says which stage the
        execution has reached is the one an operator can act on. The record
        is left where it was either way -- a stage mismatch is not a
        statement about the execution's authority.
        """

        sdk = make_sdk()
        capability = make_capability(sdk)
        issued, started = walk_to_attempt(sdk, capability)

        refused = sdk.reserve_execution(
            issued.lease, capability, ACTION, dict(REQUEST), execution_id="x"
        )
        lease = sdk.execution_leases.get(issued.lease.lease_id)
        sdk.close()

        assert not refused.allowed
        assert refused.reason == (
            "lineage_stage_mismatch:expected_authorized_found_executed"
        )
        assert lease.state is ExecutionState.STARTED

    def test_a_missing_lineage_refuses_progression(self):
        """Delete the chain from the journal: the gate fails closed."""

        sdk = make_sdk()
        capability = make_capability(sdk)
        issued = sdk.authorize_execution(capability, ACTION, dict(REQUEST))
        lineage = lineage_of(sdk, issued.lease.lease_id)

        # Emulate the chain being unrecoverable: the journal holds no links
        # and knows no lease, and adoption cannot rebuild it either.
        sdk.lineages._lineages.pop(lineage.lineage_id, None)
        sdk.lineages._by_lease.pop(issued.lease.lease_id, None)
        sdk.lineages._links.pop(lineage.lineage_id, None)
        sdk._require_lineage = True
        sdk.lineages.open = _refuse_open

        refused = sdk.reserve_execution(
            issued.lease, capability, ACTION, dict(REQUEST), execution_id="x"
        )
        sdk.close()

        assert not refused.allowed
        assert refused.reason == "lineage_unavailable"


def _refuse_open(*args, **kwargs):
    """An unopenable journal, standing in for an unreadable store."""

    from firewall.lineage import LineageJournalError

    raise LineageJournalError("the lineage store is unreachable")


# ======================================================================
# Tamper evidence: rewrite, removal, reorder, torn tail
# ======================================================================


class TestTamperEvidence:
    def _attested(self, **kwargs):
        sdk = make_sdk(**kwargs)
        capability = make_capability(sdk)
        issued, started, _outcome = walk_completed(
            sdk, capability, with_attestation=True
        )
        return sdk, issued, started

    def _tamper(self, sdk, lease_id, mutate):
        lineage = lineage_of(sdk, lease_id)
        chain = list(sdk.lineages._links[lineage.lineage_id])
        sdk.lineages._links[lineage.lineage_id] = mutate(chain)
        return lineage

    def test_an_edited_link_is_a_violation_and_the_gate_refuses(self):
        sdk, issued, _started = self._attested()
        self._tamper(
            sdk,
            issued.lease.lease_id,
            lambda chain: [replace(chain[1], evidence_digest="0" * 64)]
            + chain[2:],
        )
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "does not re-derive" in finding for finding in result.findings
        )

    def test_a_removed_link_breaks_the_chain(self):
        sdk, issued, _started = self._attested()

        def drop(chain):
            remaining = [chain[0]] + chain[2:]
            return [
                replace(link, sequence=index)
                for index, link in enumerate(remaining)
            ]

        self._tamper(sdk, issued.lease.lease_id, drop)
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "not the link before it" in finding
            or "a stage was skipped" in finding
            or "does not re-derive" in finding
            for finding in result.findings
        )

    def test_a_reordered_pair_is_a_violation(self):
        """A reorder that renumbers, which is the only reorder that sticks.

        Swapping two links in the stored list is invisible -- and correctly
        so, because the chain is ordered by the *sequence each link carries*
        rather than by the order the store happened to return. An attacker
        who wants a different order has to renumber, and renumbering breaks
        either the parent chain or the ordinal a stage requires, which is
        exactly what this asserts.
        """

        sdk, issued, _started = self._attested()

        def swap(chain):
            swapped = list(chain)
            swapped[1] = replace(swapped[1], sequence=2)
            swapped[2] = replace(swapped[2], sequence=1)
            return swapped

        self._tamper(sdk, issued.lease.lease_id, swap)
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "not the link before it" in finding
            or "sequence is not contiguous" in finding
            or "does not re-derive" in finding
            or "does not follow ordinal" in finding
            or "repeats an ordinal" in finding
            for finding in result.findings
        )

    def test_a_torn_tail_is_a_violation(self):
        """The last link present but chained to nothing."""

        sdk, issued, _started = self._attested()
        self._tamper(
            sdk,
            issued.lease.lease_id,
            lambda chain: chain[:-1]
            + [replace(chain[-1], parent_digest="0" * 64)],
        )
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED

    def test_a_forged_genesis_anchor_is_a_violation(self):
        sdk, issued, _started = self._attested()
        self._tamper(
            sdk,
            issued.lease.lease_id,
            lambda chain: [replace(chain[0], parent_digest="0" * 64)]
            + chain[1:],
        )
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "lineage anchor" in finding for finding in result.findings
        )

    def test_a_leaf_claim_lifted_onto_another_lineage_is_a_violation(self):
        """A whole link from one execution's chain placed in another's."""

        sdk = make_sdk()
        capability = make_capability(sdk)
        first, _ = walk_to_attempt(sdk, capability, execution_id="exec-a")
        second, _ = walk_to_attempt(sdk, capability, execution_id="exec-b")

        one = lineage_of(sdk, first.lease.lease_id)
        two = lineage_of(sdk, second.lease.lease_id)

        chain_one = list(sdk.lineages._links[one.lineage_id])
        chain_two = list(sdk.lineages._links[two.lineage_id])
        # Replace the second chain's first commitment with the first
        # chain's *second* one: a real, correctly-formed link from another
        # execution.
        chain_two[0] = replace(
            chain_one[1],
            lineage_id=two.lineage_id,
            sequence=0,
        )
        sdk.lineages._links[two.lineage_id] = chain_two

        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "does not re-derive" in finding
            or "not the AUTHORIZED commitment" in finding
            or "binding changes" in finding
            for finding in result.findings
        )

    def test_a_published_view_that_disagrees_with_the_store_is_a_violation(
        self,
    ):
        """A view that reports something other than the links it holds.

        Not reachable through the journal's own reads -- those derive the
        value from the links precisely so this cannot happen -- but reachable
        for any *other* implementation of the journal the SDK accepts, which
        is why the audit compares the two instead of trusting either.
        """

        sdk, issued, _started = self._attested()
        lineage = lineage_of(sdk, issued.lease.lease_id)
        genuine = lineage.links

        sdk.lineages.lineages = lambda: (
            replace(lineage, links=genuine[:-1]),
        )
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "does not match the links the journal holds" in finding
            or "publishes a lineage it holds no links for" in finding
            for finding in result.findings
        )

    def test_a_duplicated_stage_link_is_a_violation(self):
        sdk, issued, _started = self._attested()

        def duplicate(chain):
            extra = replace(
                chain[-1],
                sequence=len(chain),
                parent_digest=chain[-1].commitment_id,
            )
            return chain + [extra]

        self._tamper(sdk, issued.lease.lease_id, duplicate)
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED

    def test_an_extra_seal_is_a_violation(self):
        sdk, issued, _started = self._attested()
        lineage = lineage_of(sdk, issued.lease.lease_id)
        chain = list(sdk.lineages._links[lineage.lineage_id])
        assert chain[-1].is_seal

        extra = replace(
            chain[-1],
            sequence=len(chain),
            parent_digest=chain[-1].commitment_id,
            seal_reason="second",
            commitment_id=link_id(
                lineage_id=lineage.lineage_id,
                sequence=len(chain),
                kind=LineageKind.SEAL,
                stage=None,
                ordinal=None,
                outcome=None,
                evidence_digest=chain[-1].evidence_digest,
                binding_digest=chain[-1].binding_digest,
                parent_digest=chain[-1].commitment_id,
            ),
        )
        sdk.lineages._links[lineage.lineage_id] = chain + [extra]

        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "second seal" in finding or "continues past its seal" in finding
            for finding in result.findings
        )


# ======================================================================
# Cross-journal soundness: the chain must describe the journals
# ======================================================================


class TestCrossJournalSoundness:
    def test_a_completion_without_the_completed_stage_is_a_violation(self):
        sdk = make_sdk()
        capability = make_capability(sdk)
        issued, _started, _outcome = walk_completed(sdk, capability)
        lineage = lineage_of(sdk, issued.lease.lease_id)

        chain = [
            link
            for link in sdk.lineages._links[lineage.lineage_id]
            if not (link.is_commitment and link.stage is LineageStage.COMPLETED)
        ]
        sdk.lineages._links[lineage.lineage_id] = chain

        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "holds no COMPLETED commitment" in finding
            or "missing completed" in finding
            for finding in result.findings
        )

    def test_a_completed_stage_on_a_live_lease_is_a_violation(self):
        sdk = make_sdk()
        capability = make_capability(sdk)
        issued, started = walk_to_attempt(sdk, capability)
        record_success(sdk, capability, started.lease)

        lineage = lineage_of(sdk, issued.lease.lease_id)
        chain = list(sdk.lineages._links[lineage.lineage_id])

        # Append a COMPLETED commitment by hand while the lease is STARTED.
        from firewall.lineage import LineageLink

        predecessor = chain[-1]
        sequence = len(chain)
        ordinal = STAGE_ORDINAL[LineageStage.COMPLETED]
        digest = binding_digest(predecessor.binding)
        forged = LineageLink(
            commitment_id=link_id(
                lineage_id=lineage.lineage_id,
                sequence=sequence,
                kind=LineageKind.COMMITMENT,
                stage=LineageStage.COMPLETED,
                ordinal=ordinal,
                outcome=LineageOutcome.ADOPTED,
                evidence_digest=canonical_evidence_digest({"forged": True}),
                binding_digest=digest,
                parent_digest=predecessor.commitment_id,
            ),
            lineage_id=lineage.lineage_id,
            sequence=sequence,
            kind=LineageKind.COMMITMENT,
            stage=LineageStage.COMPLETED,
            ordinal=ordinal,
            outcome=LineageOutcome.ADOPTED,
            evidence_digest=canonical_evidence_digest({"forged": True}),
            parent_digest=predecessor.commitment_id,
            binding=dict(predecessor.binding),
            binding_digest=digest,
            lease_digest=predecessor.lease_digest,
        )
        sdk.lineages._links[lineage.lineage_id] = chain + [forged]

        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "COMPLETED is committed while the lease" in finding
            for finding in result.findings
        )

    def test_an_executed_stage_on_an_unstarted_lease_is_a_violation(self):
        sdk = make_sdk()
        capability = make_capability(sdk)
        issued = sdk.authorize_execution(capability, ACTION, dict(REQUEST))

        lineage = lineage_of(sdk, issued.lease.lease_id)
        chain = list(sdk.lineages._links[lineage.lineage_id])

        from firewall.lineage import LineageLink

        genesis = chain[0]
        ordinal = STAGE_ORDINAL[LineageStage.EXECUTED]
        digest = binding_digest(genesis.binding)
        forged = LineageLink(
            commitment_id=link_id(
                lineage_id=lineage.lineage_id,
                sequence=1,
                kind=LineageKind.COMMITMENT,
                stage=LineageStage.EXECUTED,
                ordinal=ordinal,
                outcome=LineageOutcome.ADOPTED,
                evidence_digest=canonical_evidence_digest({"forged": True}),
                binding_digest=digest,
                parent_digest=genesis.commitment_id,
            ),
            lineage_id=lineage.lineage_id,
            sequence=1,
            kind=LineageKind.COMMITMENT,
            stage=LineageStage.EXECUTED,
            ordinal=ordinal,
            outcome=LineageOutcome.ADOPTED,
            evidence_digest=canonical_evidence_digest({"forged": True}),
            parent_digest=genesis.commitment_id,
            binding=dict(genesis.binding),
            binding_digest=digest,
            lease_digest=genesis.lease_digest,
        )
        sdk.lineages._links[lineage.lineage_id] = chain + [forged]

        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "the boundary was never crossed" in finding
            for finding in result.findings
        )

    def test_a_binding_that_disagrees_with_the_lease_is_a_violation(self):
        sdk = make_sdk()
        capability = make_capability(sdk)
        issued, _started, _outcome = walk_completed(sdk, capability)
        lineage = lineage_of(sdk, issued.lease.lease_id)

        def rebind(chain):
            out = []
            for link in chain:
                binding = dict(link.binding)
                binding["agent_id"] = "agent-attacker"
                out.append(
                    replace(
                        link,
                        binding=binding,
                        binding_digest=binding_digest(binding),
                    )
                )
            return out

        sdk.lineages._links[lineage.lineage_id] = rebind(
            list(sdk.lineages._links[lineage.lineage_id])
        )
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "bound to another execution" in finding
            or "does not re-derive" in finding
            for finding in result.findings
        )

    def test_an_orphaned_lineage_is_a_violation(self):
        sdk = make_sdk()
        capability = make_capability(sdk)
        issued, _started, _outcome = walk_completed(sdk, capability)
        lineage = lineage_of(sdk, issued.lease.lease_id)

        sdk.execution_leases._records.pop(issued.lease.lease_id, None)
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "which no longer exists" in finding for finding in result.findings
        )
        assert lineage is not None

    def test_an_unknown_finding_kind_is_a_violation(self):
        sdk = make_sdk()
        capability = make_capability(sdk)
        issued, _started, _outcome = walk_completed(sdk, capability)

        sdk.lineages._findings.append(
            runtime_module.__dict__.get("_unused", None)
            or type(
                "F",
                (),
                {
                    "kind": "something_else",
                    "lineage_id": "x",
                    "sequence": 0,
                    "detail": "?",
                    "at": 0.0,
                },
            )()
        )
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "cannot explain" in finding for finding in result.findings
        )
        assert issued.allowed

    def test_verified_committed_over_a_contradiction_is_a_violation(self):
        sdk = make_sdk(require_external_attestation=False)
        capability = make_capability(sdk)
        issued, started = walk_to_attempt(sdk, capability)
        record_success(sdk, capability, started.lease)

        # A clean verification, then an auditor's contradiction of the same
        # evidence, then a commit. v2.9's gate is what refuses here.
        first = sdk.verify_effect(
            started.lease,
            capability,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
        )
        assert not first.allowed  # provider evidence, structural method

        def contradictor(evidence):
            return VerifierVerdict(
                outcome=VerificationOutcome.CONTRADICTED,
                method="internal-auditor",
                note="the correlation id does not match the ledger",
            )

        sdk.verify_effect(
            started.lease,
            capability,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            verifier=contradictor,
            method="internal-auditor",
        )

        commit = sdk.commit_effect(
            started.lease,
            capability,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            verifier=authenticator,
            method="acme-authenticator",
        )
        lineage = lineage_of(sdk, issued.lease.lease_id)
        result = audit(sdk)
        sdk.close()

        assert not commit.allowed
        assert "effect_unverified" in commit.reason
        # No COMPLETED commitment exists, so the chain is honest about it.
        assert LineageStage.COMPLETED not in lineage.stages
        assert result.status is InvariantStatus.HOLDS


# ======================================================================
# Crash safety and restart recovery
# ======================================================================


class TestPersistenceAndRecovery:
    def test_a_chain_survives_a_restart_and_still_verifies(self, tmp_path):
        path = tmp_path / "lineage.sqlite3"

        sdk = make_sdk(lineage_store_path=path, execution_store_path=path)
        capability = make_capability(sdk)
        issued, _started, _outcome = walk_completed(sdk, capability)
        lease_id = issued.lease.lease_id
        before = lineage_of(sdk, lease_id)
        links_before = sdk.lineage_links()
        sdk.close()

        store = SQLiteLineageStore(path)
        journal = LineageJournal(backend=store)
        recovered = journal.for_lease(lease_id)
        result = None

        assert recovered is not None
        assert [stage for stage in recovered.stages] == list(STAGE_ORDER)
        assert recovered.verify() == ()
        assert recovered.completed is True
        assert len(links_before) == len(recovered.links)
        store.close()

        # And through the SDK, the invariant holds over the recovered chain.
        second = FirewallSDK(lineage_store_path=path, execution_store_path=path)
        second.generate_key("v33-restart")
        result = audit(second)
        second.close()

        assert result is not None
        assert result.status is InvariantStatus.HOLDS, result.reason
        assert before.lineage_id == recovered.lineage_id

    def test_an_in_flight_execution_is_adopted_with_the_stages_it_reached(
        self, tmp_path
    ):
        """A restart mid-execution resumes the chain rather than restarting it."""

        path = tmp_path / "lineage2.sqlite3"

        sdk = make_sdk(lineage_store_path=path, execution_store_path=path)
        capability = make_capability(sdk)
        issued, started = walk_to_attempt(sdk, capability)
        lease_id = issued.lease.lease_id
        sdk.close()

        second = FirewallSDK(lineage_store_path=path, execution_store_path=path)
        second.generate_key("v33-restart-2")
        capability_two = second.issue(
            agent="agent-a",
            capability=ACTION,
            constraints={"amount_max": 100},
        )
        lease = second.execution_leases.get(lease_id)
        assert lease.state is ExecutionState.STARTED

        lineage = second.lineage_for_lease(lease_id)
        result = audit(second)
        second.close()

        assert lineage is not None
        assert LineageStage.AUTHORIZED in lineage.stages
        assert LineageStage.EXECUTED in lineage.stages
        assert lineage.verify() == ()
        assert result.status is InvariantStatus.HOLDS, result.reason
        assert capability_two is not None

    def test_a_terminal_execution_is_adopted_and_sealed(self, tmp_path):
        path = tmp_path / "lineage3.sqlite3"

        sdk = make_sdk(lineage_store_path=path, execution_store_path=path)
        capability = make_capability(sdk)
        issued, started = walk_to_attempt(sdk, capability)
        record_success(sdk, capability, started.lease)
        committed = sdk.commit_effect(
            started.lease,
            capability,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            verifier=authenticator,
            method="acme-authenticator",
        )
        assert committed.allowed, committed.reason
        lease_id = issued.lease.lease_id
        sdk.close()

        second = FirewallSDK(lineage_store_path=path, execution_store_path=path)
        second.generate_key("v33-restart-3")
        lease = second.execution_leases.get(lease_id)
        assert lease is not None

        # Force adoption by clearing the in-memory journal, then ask.
        second.lineages._lineages.clear()
        second.lineages._by_lease.clear()
        second.lineages._by_execution.clear()
        second.lineages._links.clear()

        adopted = second.lineages.for_lease(lease_id)
        assert adopted is None
        lineage = second._lineage_for(lease)
        result = audit(second)
        second.close()

        assert lineage is not None
        assert LineageStage.COMPLETED in lineage.stages
        assert lineage.sealed is True
        assert lineage.verify() == ()
        assert result.status is InvariantStatus.HOLDS, result.reason

    def test_a_torn_chain_in_the_store_is_refused_rather_than_resumed(
        self, tmp_path
    ):
        """The one state the layer will not paper over."""

        path = tmp_path / "lineage4.sqlite3"

        sdk = make_sdk(lineage_store_path=path, execution_store_path=path)
        capability = make_capability(sdk)
        issued, _started, _outcome = walk_completed(sdk, capability)
        lease_id = issued.lease.lease_id
        lineage = lineage_of(sdk, lease_id)
        sdk.close()

        # Rewrite the store with one link's evidence digest changed: a chain
        # whose head cannot be verified.
        store = SQLiteLineageStore(path)
        chain = list(store.load_one(lineage.lineage_id))
        corrupted = [
            replace(link, evidence_digest="0" * 64)
            if link.sequence == 1
            else link
            for link in chain
        ]
        store.close()

        raw = SQLiteLineageStore(path)
        connection = raw._require_connection()
        with raw._lock:
            connection.execute(
                "DELETE FROM execution_lineage WHERE lineage_id = ?",
                (lineage.lineage_id,),
            )
            for link in corrupted:
                connection.execute(
                    """
                    INSERT INTO execution_lineage (
                        lineage_id, sequence, commitment_id, kind, stage,
                        ordinal, parent_digest, lease_id, execution_id, payload
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        link.lineage_id,
                        link.sequence,
                        link.commitment_id,
                        link.kind.value,
                        link.stage.value if link.stage else None,
                        link.ordinal,
                        link.parent_digest,
                        link.binding.get("lease_id"),
                        link.binding.get("execution_id"),
                        json.dumps(link.to_dict(), sort_keys=True),
                    ),
                )
            connection.commit()
        raw.close()

        second = FirewallSDK(lineage_store_path=path, execution_store_path=path)
        second.generate_key("v33-restart-4")
        lease = second.execution_leases.get(lease_id)
        probe = second.authorize_execution(
            make_capability(second), ACTION, dict(REQUEST)
        )
        refused = second.reserve_execution(
            lease,
            make_capability(second),
            ACTION,
            dict(REQUEST),
            execution_id="after-corruption",
        )
        result = audit(second)
        second.close()

        assert probe.allowed or probe.allowed is False
        assert not refused.allowed
        assert result.status is InvariantStatus.VIOLATED

    def test_a_crash_between_the_write_and_the_publish_is_recoverable(
        self, tmp_path
    ):
        """The link the store holds and the process does not."""

        path = tmp_path / "lineage5.sqlite3"

        sdk = make_sdk(lineage_store_path=path, execution_store_path=path)
        capability = make_capability(sdk)
        issued = sdk.authorize_execution(capability, ACTION, dict(REQUEST))
        lineage = lineage_of(sdk, issued.lease.lease_id)
        sdk.close()

        # The store holds the genesis; a second process must publish it.
        store = SQLiteLineageStore(path)
        assert len(store.load_one(lineage.lineage_id)) == 1
        store.close()

        second = FirewallSDK(lineage_store_path=path, execution_store_path=path)
        second.generate_key("v33-restart-5")
        recovered = second.lineages.for_lease(issued.lease.lease_id)
        result = audit(second)
        second.close()

        assert recovered is not None
        assert recovered.lineage_id == lineage.lineage_id
        assert recovered.verify() == ()
        assert result.status is InvariantStatus.HOLDS

    def test_the_store_key_is_structural_not_the_declared_id(self, tmp_path):
        """A forged id cannot displace a real link."""

        path = tmp_path / "lineage6.sqlite3"

        sdk = make_sdk(lineage_store_path=path, execution_store_path=path)
        capability = make_capability(sdk)
        issued = sdk.authorize_execution(capability, ACTION, dict(REQUEST))
        lineage = lineage_of(sdk, issued.lease.lease_id)
        genesis = lineage.genesis
        sdk.close()

        store = SQLiteLineageStore(path)

        with pytest.raises(Exception):
            store.insert(replace(genesis, commitment_id="0" * 64))

        # The real link is still the one at that position.
        chain = store.load_one(lineage.lineage_id)
        store.close()

        assert chain is not None
        assert chain[0].commitment_id == genesis.commitment_id

    def test_a_second_generation_cannot_fork_a_chain_on_disk(self, tmp_path):
        """One stage, one commitment -- across process generations.

        The first generation leaves the chain at EXECUTED. A second
        generation commits OBSERVED with one claim; a third then tries to
        commit *its own* answer to the same stage. That is the fork the
        storage layer refuses, and it is refused whichever order the two
        writers arrive in.
        """

        path = tmp_path / "lineage7.sqlite3"

        sdk = make_sdk(lineage_store_path=path, execution_store_path=path)
        capability = make_capability(sdk)
        issued, started = walk_to_attempt(sdk, capability)
        record_success(sdk, capability, started.lease)
        lease_id = issued.lease.lease_id
        lineage = lineage_of(sdk, lease_id)
        binding = {
            name: value
            for name, value in lineage.binding.items()
            if value is not None
        }
        sdk.close()

        from firewall.lineage import LineageForkError

        store = SQLiteLineageStore(path)
        journal = LineageJournal(backend=store)
        first = journal.advance(
            lineage_id=lineage.lineage_id,
            stage=LineageStage.OBSERVED,
            outcome=LineageOutcome.ADOPTED,
            evidence={"winner": True},
            binding=dict(binding),
            lease_digest="winner",
        )
        assert first.outcome_of(LineageStage.OBSERVED) is (
            LineageOutcome.ADOPTED
        )

        # A second generation, restored from the same file, holding the
        # chain as the first generation left it.
        second_store = SQLiteLineageStore(path)
        second_journal = LineageJournal(backend=second_store)
        row = None

        try:
            second_journal.advance(
                lineage_id=lineage.lineage_id,
                stage=LineageStage.OBSERVED,
                outcome=LineageOutcome.REFUSED,
                evidence={"loser": True},
                binding=dict(binding),
                lease_digest="loser",
            )
        except LineageForkError:
            row = "forked"
        except Exception as error:  # noqa: BLE001 - reported below
            row = type(error).__name__

        findings = [finding.kind for finding in second_journal.findings()]
        chain = second_store.load_one(lineage.lineage_id)
        second_store.close()
        store.close()

        assert row == "forked"
        assert "branch" in findings
        # Two generations, still one OBSERVED commitment, still one winner.
        assert sum(
            1
            for link in chain
            if link.stage is LineageStage.OBSERVED
        ) == 1


# ======================================================================
# Concurrency: two writers, one chain
# ======================================================================


class TestConcurrentLineage:
    def test_two_processes_cannot_both_win_one_stage(self, tmp_path):
        path = tmp_path / "lineage-concurrent.sqlite3"

        sdk = make_sdk(lineage_store_path=path)
        capability = make_capability(sdk)
        issued = sdk.authorize_execution(capability, ACTION, dict(REQUEST))
        lineage = lineage_of(sdk, issued.lease.lease_id)
        record = sdk.execution_leases.get(issued.lease.lease_id)
        binding = sdk._lineage_binding(record)
        sdk.close()

        results: list[str] = []
        lock = threading.Lock()
        barrier = threading.Barrier(2)

        def writer(index):
            store = SQLiteLineageStore(path)
            journal = LineageJournal(backend=store)
            barrier.wait()

            try:
                journal.advance(
                    lineage_id=lineage.lineage_id,
                    stage=LineageStage.EXECUTED,
                    outcome=LineageOutcome.ADOPTED,
                    evidence={"writer": index},
                    binding=dict(binding),
                    lease_digest=f"w{index}",
                )
                outcome = "advanced"
            except Exception as error:  # noqa: BLE001 - reported below
                outcome = type(error).__name__
            finally:
                store.close()

            with lock:
                results.append(outcome)

        threads = [
            threading.Thread(target=writer, args=(index,))
            for index in range(2)
        ]

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        store = SQLiteLineageStore(path)
        chain = store.load_one(lineage.lineage_id)
        store.close()

        assert len(chain) == 2
        assert sorted(
            link.stage.value for link in chain
        ) == ["authorized", "executed"]

    def test_concurrent_stage_commits_do_not_fork_a_chain(self, tmp_path):
        path = tmp_path / "lineage-race.sqlite3"

        sdk = make_sdk(lineage_store_path=path)
        capability = make_capability(sdk)
        issued = sdk.authorize_execution(capability, ACTION, dict(REQUEST))
        lineage = lineage_of(sdk, issued.lease.lease_id)
        record = sdk.execution_leases.get(issued.lease.lease_id)
        binding = sdk._lineage_binding(record)
        sdk.close()

        lock = threading.Lock()
        outcomes: list[str] = []
        barrier = threading.Barrier(4)

        def writer(index):
            store = SQLiteLineageStore(path)
            journal = LineageJournal(backend=store)
            barrier.wait()

            try:
                journal.advance(
                    lineage_id=lineage.lineage_id,
                    stage=LineageStage.EXECUTED,
                    outcome=LineageOutcome.ADOPTED,
                    evidence={"writer": "same"},
                    binding=dict(binding),
                    lease_digest="same",
                )
                result = "advanced"
            except Exception as error:  # noqa: BLE001
                result = type(error).__name__
            finally:
                store.close()

            with lock:
                outcomes.append(result)

        threads = [
            threading.Thread(target=writer, args=(index,))
            for index in range(4)
        ]

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        store = SQLiteLineageStore(path)
        chain = store.load_one(lineage.lineage_id)
        store.close()

        # Exactly one EXECUTED link exists however the race went.
        assert sum(
            1 for link in chain if link.stage is LineageStage.EXECUTED
        ) == 1
        assert len(outcomes) == 4

    def test_a_completion_brings_the_chain_up_to_attested_then_completed(self):
        sdk = make_sdk()
        capability = make_capability(sdk)
        issued, _started, _outcome = walk_completed(sdk, capability)
        lineage = lineage_of(sdk, issued.lease.lease_id)
        sdk.close()

        assert lineage.stages == STAGE_ORDER
        assert lineage.ordinal == STAGE_ORDINAL[LineageStage.COMPLETED]


# ======================================================================
# The invariant's teeth on the source census
# ======================================================================


class TestSourceCensusTeeth:
    def test_the_census_is_closed(self):
        findings, notes = _lineage_source_findings()

        assert findings == ()
        assert notes

    def test_an_undeclared_journal_caller_is_a_violation(self, monkeypatch):
        monkeypatch.setattr(
            runtime_module,
            "LINEAGE_MUTATOR_OWNERS",
            frozenset(),
        )
        findings, _ = _lineage_source_findings()

        assert any(
            "drives the lineage journal" in finding for finding in findings
        )

    def test_a_declared_caller_that_drives_nothing_is_a_violation(
        self, monkeypatch
    ):
        monkeypatch.setattr(
            runtime_module,
            "LINEAGE_MUTATOR_OWNERS",
            frozenset(
                runtime_module.LINEAGE_MUTATOR_OWNERS
                | {("firewall/sdk.py", "FirewallSDK.lineage_records")}
            ),
        )
        findings, _ = _lineage_source_findings()

        assert any(
            "drives no journal mutator" in finding for finding in findings
        )

    def test_an_allow_path_reference_is_a_violation(self, monkeypatch):
        monkeypatch.setattr(
            runtime_module,
            "LINEAGE_ALLOW_PATH_OWNERS",
            frozenset(
                runtime_module.LINEAGE_ALLOW_PATH_OWNERS
                | {"FirewallSDK._lineage_gate"}
            ),
        )
        findings, _ = _lineage_source_findings()

        assert any("ALLOW path" in finding for finding in findings)

    def test_the_gate_prefix_rule_does_not_match_lineage_helpers(
        self, monkeypatch
    ):
        """`_lineage_gate` is not a gate, and the rule must not say it is."""

        findings, _ = _lineage_source_findings()

        assert not any(
            "_lineage_gate" in finding and "ALLOW path" in finding
            for finding in findings
        )

    def test_the_lineage_module_constructs_no_verdict(self):
        import ast

        import firewall.lineage as module

        tree = ast.parse(open(module.__file__, encoding="utf-8").read())

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
            assert name not in (
                "AuthorizationResult",
                "_result",
                "authorize",
            ), name


# ======================================================================
# Boundary properties
# ======================================================================


class TestBoundaries:
    def test_the_lineage_layer_writes_no_other_journal(self):
        sdk = make_sdk()
        capability = make_capability(sdk)
        issued, started = walk_to_attempt(sdk, capability)
        record_success(sdk, capability, started.lease)

        leases = sdk.execution_leases.records()
        rows = sdk.effects.records()
        claims = sdk.verifications.records()
        attestations = sdk.attestations.records()

        # A lineage operation on its own changes nothing else.
        lineage = lineage_of(sdk, issued.lease.lease_id)
        sdk.lineages.verify(lineage.lineage_id)
        sdk.lineage_findings()
        sdk.lineage_links()

        assert sdk.execution_leases.records() == leases
        assert sdk.effects.records() == rows
        assert sdk.verifications.records() == claims
        assert sdk.attestations.records() == attestations
        sdk.close()

    def test_the_lineage_layer_changes_no_authorize_verdict(self):
        sdk = make_sdk()
        capability = make_capability(sdk)
        before = sdk.authorize(capability, ACTION, dict(REQUEST))
        assert before.allowed

        issued, _started, _outcome = walk_completed(sdk, capability)
        lineage = lineage_of(sdk, issued.lease.lease_id)
        sdk.lineages.verify(lineage.lineage_id)

        after = sdk.authorize(capability, ACTION, dict(REQUEST))
        over = sdk.authorize(capability, ACTION, {"amount": 10_000})
        sdk.close()

        assert after.allowed == before.allowed
        assert after.reason == before.reason
        assert over.allowed is False

    def test_the_lineage_does_not_touch_the_control_plane(self):
        from firewall.invariants import control_plane_snapshot

        sdk = make_sdk()
        capability = make_capability(sdk)
        issued = sdk.authorize_execution(capability, ACTION, dict(REQUEST))
        before = control_plane_snapshot(sdk)

        lineage = lineage_of(sdk, issued.lease.lease_id)
        sdk.lineages.seal(lineage_id=lineage.lineage_id, reason="probe")
        after = control_plane_snapshot(sdk)
        sdk.close()

        assert before == after

    def test_require_lineage_is_read_only(self):
        sdk = make_sdk()
        try:
            with pytest.raises(AttributeError):
                sdk.require_lineage = False
            assert sdk.require_lineage is True
        finally:
            sdk.close()

    def test_with_the_requirement_off_progression_is_ungated(self):
        sdk = make_sdk(require_lineage=False)
        capability = make_capability(sdk)
        issued = sdk.authorize_execution(capability, ACTION, dict(REQUEST))
        reserved = sdk.reserve_execution(
            issued.lease, capability, ACTION, dict(REQUEST), execution_id="x"
        )
        started = sdk.start_execution(
            reserved.lease, capability, ACTION, dict(REQUEST)
        )
        completed = sdk.complete_execution(
            started.lease, capability, ACTION, dict(REQUEST)
        )
        sdk.close()

        assert reserved.allowed
        assert started.allowed
        assert completed.allowed

    def test_with_the_requirement_off_the_side_effect_path_is_ungated(self):
        """The v3.2 behaviour holds on *every* progression path, not one.

        The lease path was covered; the side-effect path was not, and its
        gate read the requirement differently from the lease path's -- so a
        caller that had turned the requirement off was refused at
        ``record_effect_receipt`` with ``lineage_stage_missing``.
        """

        sdk = make_sdk(require_lineage=False)
        capability = make_capability(sdk)
        issued, started = walk_to_attempt(sdk, capability)
        receipt = record_success(sdk, capability, started.lease)
        committed = sdk.commit_effect(
            started.lease,
            capability,
            ACTION,
            dict(REQUEST),
            effect=dict(EFFECT),
            effect_type=EFFECT_TYPE,
            idempotency_key=KEY,
            verifier=authenticator,
            method="acme-authenticator",
        )
        sdk.close()

        assert issued.allowed
        assert receipt.allowed, receipt.reason
        assert committed.allowed, committed.reason

    def test_a_bad_construction_is_refused(self):
        with pytest.raises(ValueError):
            FirewallSDK(
                lineage_journal=LineageJournal(),
                lineage_store_path="x.sqlite3",
            )

        with pytest.raises(TypeError):
            FirewallSDK(lineage_journal=object())

        with pytest.raises(TypeError):
            FirewallSDK(require_lineage="yes")

    def test_a_caller_supplied_journal_is_not_closed_by_the_sdk(self):
        journal = LineageJournal()
        sdk = FirewallSDK(lineage_journal=journal)
        sdk.close()

        lineage = journal.open(
            lease_id="lease-x",
            execution_id=None,
            binding=dict(BINDING, lease_id="lease-x"),
            lease_digest="ld",
        )
        assert lineage.verify() == ()

    def test_the_store_is_closed_with_the_sdk(self, tmp_path):
        path = tmp_path / "lineage-close.sqlite3"
        sdk = make_sdk(lineage_store_path=path)
        store = sdk.lineage_store
        assert store is not None
        sdk.close()

        assert store._connection is None

    def test_an_unreadable_store_is_a_refusal(self, tmp_path, monkeypatch):
        path = tmp_path / "lineage-unreadable.sqlite3"

        def unreadable(self):
            raise RuntimeError("unreachable")

        monkeypatch.setattr(
            SQLiteLineageStore, "load", unreadable
        )

        with pytest.raises(Exception) as caught:
            FirewallSDK(lineage_store_path=path)

        assert "lineage" in str(caught.value).lower()


# ======================================================================
# The chain as data: the shape the invariant depends on
# ======================================================================


class TestChainShape:
    def test_the_binding_accumulates_across_stages(self):
        sdk = make_sdk()
        capability = make_capability(sdk)
        issued, _started, _outcome = walk_completed(
            sdk, capability, with_attestation=True
        )
        lineage = lineage_of(sdk, issued.lease.lease_id)
        binding = lineage.binding
        sdk.close()

        assert binding["lease_id"] == issued.lease.lease_id
        assert binding["execution_id"] == "exec-complete"
        assert binding["effect_id"]
        assert binding["attempt_id"]
        assert binding["provider"] == PROVIDER
        assert set(binding) == set(BINDING_FIELDS)

    def test_every_stage_carries_the_evidence_it_was_committed_on(self):
        sdk = make_sdk()
        capability = make_capability(sdk)
        issued, _started, _outcome = walk_completed(
            sdk, capability, with_attestation=True
        )
        lineage = lineage_of(sdk, issued.lease.lease_id)
        sdk.close()

        for stage in STAGE_ORDER:
            digest = lineage.evidence_for(stage)
            assert isinstance(digest, str) and len(digest) == 64

    def test_the_lineage_is_immutable_as_a_value(self):
        sdk = make_sdk()
        capability = make_capability(sdk)
        issued, started = walk_to_attempt(sdk, capability)
        before = lineage_of(sdk, issued.lease.lease_id)
        record_success(sdk, capability, started.lease)
        after = lineage_of(sdk, issued.lease.lease_id)
        sdk.close()

        assert before is not after
        assert len(after.links) >= len(before.links)
        assert before.verify() == ()

    def test_a_lineage_round_trips_through_its_links(self, tmp_path):
        path = tmp_path / "lineage-round.sqlite3"

        sdk = make_sdk(lineage_store_path=path)
        capability = make_capability(sdk)
        issued, _started, _outcome = walk_completed(sdk, capability)
        lineage = lineage_of(sdk, issued.lease.lease_id)
        lease_id = issued.lease.lease_id
        sdk.close()

        store = SQLiteLineageStore(path)
        chain = store.load_one(lineage.lineage_id)
        store.close()

        assert chain is not None
        rebuilt = ExecutionLineage(
            lineage_id=lineage.lineage_id,
            lease_id=lease_id,
            execution_id=lineage.execution_id,
            links=tuple(chain),
        )
        assert rebuilt.verify() == ()
        assert rebuilt.completed is True

    def test_completeness_reports_a_missing_stage(self):
        sdk = make_sdk()
        capability = make_capability(sdk)
        issued = sdk.authorize_execution(capability, ACTION, dict(REQUEST))
        lineage = lineage_of(sdk, issued.lease.lease_id)

        problems = completeness_problems(
            lineage,
            side_effect_adopted=False,
            attestation_required=False,
        )
        sdk.close()

        assert len(problems) == 1
        assert "missing" in problems[0]

    def test_completeness_reports_a_refused_stage(self):
        sdk = make_sdk()
        capability = make_capability(sdk)
        issued = sdk.authorize_execution(capability, ACTION, dict(REQUEST))
        lineage = lineage_of(sdk, issued.lease.lease_id)

        forced = replace(
            lineage,
            links=lineage.links
            + (
                replace(
                    lineage.genesis,
                    commitment_id="x",
                    sequence=1,
                    stage=LineageStage.EXECUTED,
                    ordinal=STAGE_ORDINAL[LineageStage.EXECUTED],
                    outcome=LineageOutcome.REFUSED,
                ),
            ),
        )
        problems = completeness_problems(
            forced,
            side_effect_adopted=False,
            attestation_required=False,
        )
        sdk.close()

        assert any("refused" in problem for problem in problems)

    def test_the_boundary_merge_rule_is_one_way(self):
        """A binding grows; it never changes and never shrinks.

        The rule is stated over the *real* binding fields rather than over
        stand-ins, because the stand-in version passed while the real one was
        broken: ``merge_binding`` iterates `BINDING_FIELDS`, so a probe using
        invented names exercises nothing but its own loop.
        """

        merged, bad = merge_binding(
            {"lease_id": "l", "effect_id": None},
            {"lease_id": "l", "effect_id": "eff-1"},
        )

        assert bad is None
        assert merged["effect_id"] == "eff-1"

        # A field that changes is a substitution.
        _merged, bad = merge_binding(
            {"lease_id": "l", "agent_id": "agent-a"},
            {"lease_id": "l", "agent_id": "agent-b"},
        )
        assert bad == "agent_id"

        # A field that disappears is the same substitution from the other
        # side: nothing may be forgotten, because a binding that can lose a
        # field can be made to look like another execution's.
        _merged, bad = merge_binding(
            {"lease_id": "l", "effect_id": "eff-1"},
            {"lease_id": "l"},
        )
        assert bad == "effect_id"

        # Absent on both sides is not a mismatch; it is not known yet.
        _merged, bad = merge_binding(
            {"lease_id": "l"}, {"lease_id": "l"}
        )
        assert bad is None

    def test_a_link_id_is_structural(self):
        kwargs = dict(
            lineage_id="l",
            sequence=2,
            kind=LineageKind.COMMITMENT,
            stage=LineageStage.OBSERVED,
            ordinal=STAGE_ORDINAL[LineageStage.OBSERVED],
            outcome=LineageOutcome.ADOPTED,
            evidence_digest="e" * 64,
            binding_digest="b" * 64,
            parent_digest="p" * 64,
        )

        assert link_id(**kwargs) == link_id(**kwargs)
        assert link_id(**{**kwargs, "sequence": 3}) != link_id(**kwargs)
        assert link_id(**{**kwargs, "parent_digest": "q" * 64}) != link_id(
            **kwargs
        )

    def test_the_registry_reports_the_invariant(self):
        from firewall.invariants import INVARIANTS, invariant

        entry = invariant("EXECUTION_LINEAGE_SOUNDNESS")

        assert "intact, unique, correctly bound and tamper-evident" in (
            entry.statement
        )
        assert entry.needs_state is True
        assert len(INVARIANTS) == 26
