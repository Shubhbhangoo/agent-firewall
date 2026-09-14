"""v3.5: witness quorum integrity -- attack the twenty-sixth invariant.

v3.4 moved the root of trust out of the firewall's own storage and then,
in its honest-non-guarantees list, admitted what it had actually built:
*one* witness. One key, one signature, one machine. A checkpoint became
externally confirmed because a thing said so -- and a thing that can be
compromised, subpoenaed, misconfigured or simply wrong is a single point
of failure wearing the costume of a trust root. The v3.4 release closed
the gap where the firewall vouched for itself; it did not close the gap
where the firewall's witness vouched alone.

``WITNESS_QUORUM_SOUNDNESS`` (the twenty-sixth registered invariant)
machine-checks the layer that closes it:

.. code-block:: text

    bind -> collect -> confirm -> compare

* **Bound** -- a published checkpoint is tied to the witness policy in
  force, and the binding is *derived* from the pair rather than asserted
  about it, so neither side can be swapped afterwards.
* **Collected** -- each witness's receipt re-derives to its own id, carries
  a signature that verifies under a *registered* key, comes from an
  identity the policy names, and authenticates the identical anchor kind,
  id, sequence, digest, checkpoint and policy.
* **Confirmed** -- a round is won only when at least the threshold's worth
  of *distinct* trusted witnesses authenticated that one statement. A
  duplicate identity adds nothing; a witness that signed two things is
  never counted, and both statements are kept as evidence.
* **Compared** -- a progression asks whether the position it rests on had
  quorum behind it, and refuses ``anchor_quorum_unconfirmed``,
  ``anchor_quorum_insufficient``, ``anchor_quorum_split``,
  ``anchor_checkpoint_mismatch`` or ``anchor_quorum_unverifiable`` when it
  did not.

This file attacks each of those from both sides -- the SDK boundary and
the invariant -- and asserts that the *gate* fails closed, not merely that
the audit notices afterwards.
"""

from __future__ import annotations

import ast
import sqlite3
import uuid

from dataclasses import replace
from pathlib import Path

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from firewall.anchor import (
    AnchorCheckpoint,
    AnchorKind,
    InProcessWitness,
)
from firewall.invariants import runtime as runtime_module
from firewall.invariants.registry import INVARIANTS, invariant
from firewall.quorum import (
    QUORUM_FINDING_KINDS,
    CheckpointPolicyBinding,
    EquivocationEvidence,
    InProcessQuorumWitness,
    QuorumCheckpointMismatchError,
    QuorumDecision,
    QuorumDuplicateWitnessError,
    QuorumEquivocationError,
    QuorumError,
    QuorumPolicyError,
    QuorumReceipt,
    QuorumSignatureError,
    QuorumStaleReceiptError,
    QuorumStoreError,
    QuorumUntrustedWitnessError,
    WitnessPolicy,
    WitnessQuorumJournal,
)
from firewall.quorum_store import SQLiteQuorumStore
from firewall.sdk import FirewallSDK

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st


# =====================================================================
# Fixtures and helpers
# =====================================================================

ACTION = "payments.send"
REQUEST = {"amount": 5}
PROVIDER = "acme-payments"

WITNESS_KEY_ID = "v35-anchor-witness"
WITNESS_PRIVATE = Ed25519PrivateKey.generate()
WITNESS_PUBLIC = WITNESS_PRIVATE.public_key()

ISSUER_PRIVATE = Ed25519PrivateKey.generate()

#: The three identities the default quorum policy names.
QUORUM_IDS = ("quorum-witness-a", "quorum-witness-b", "quorum-witness-c")


def make_witness(*, key_id=WITNESS_KEY_ID, private_key=None):
    return InProcessWitness(
        key_id=key_id,
        private_key=private_key or WITNESS_PRIVATE,
    )


def make_sdk(**kwargs):
    """An SDK with an anchor witness, as the v3.4 tests build one."""

    kwargs.setdefault("anchor_witness", make_witness())
    kwargs.setdefault("witness_keys", {WITNESS_KEY_ID: WITNESS_PUBLIC})

    sdk = FirewallSDK(**kwargs)
    sdk.generate_key(f"v35-{uuid.uuid4().hex[:8]}")
    sdk.trust_external_issuer(
        PROVIDER, "acme-key-1", ISSUER_PRIVATE.public_key()
    )
    return sdk


def make_capability(sdk):
    return sdk.issue(
        agent="agent-a",
        capability=ACTION,
        constraints={"amount_max": 100},
    )


def make_quorum_sdk(
    *,
    threshold=2,
    ids=QUORUM_IDS,
    require_quorum=True,
    **kwargs,
):
    """An SDK with a quorum policy, plus the witness private keys.

    The private halves are returned because the SDK is deliberately *not*
    given them -- a deployment's firewall does not hold its witnesses'
    signing keys, and a test that handed them over would be exercising a
    configuration that cannot exist.
    """

    private_keys = {
        witness_id: Ed25519PrivateKey.generate() for witness_id in ids
    }

    sdk = make_sdk(
        require_witness_quorum=require_quorum,
        quorum_policy=WitnessPolicy.derive(threshold, ids),
        quorum_witness_keys={
            witness_id: key.public_key()
            for witness_id, key in private_keys.items()
        },
        **kwargs,
    )

    witnesses = {
        witness_id: InProcessQuorumWitness(
            witness_id=witness_id,
            private_key=private_key,
        )
        for witness_id, private_key in private_keys.items()
    }

    return sdk, witnesses, WitnessPolicy.derive(threshold, ids)


def make_journal(
    *,
    threshold=2,
    ids=QUORUM_IDS,
    backend=None,
):
    """A quorum journal with the policy already in force."""

    policy = WitnessPolicy.derive(threshold, ids)
    private_keys = {
        witness_id: Ed25519PrivateKey.generate() for witness_id in ids
    }

    journal = WitnessQuorumJournal(
        backend=backend,
        witness_keys={
            witness_id: key.public_key()
            for witness_id, key in private_keys.items()
        },
        policy=policy,
    )

    witnesses = {
        witness_id: InProcessQuorumWitness(
            witness_id=witness_id,
            private_key=private_key,
        )
        for witness_id, private_key in private_keys.items()
    }

    return journal, witnesses, policy


def make_checkpoint(
    *,
    anchor_id="anchor-1",
    sequence=1,
    digest=None,
):
    """A genuinely signed v3.4 checkpoint to bind a quorum round to."""

    return make_witness().sign(
        AnchorCheckpoint(
            kind=AnchorKind.LINEAGE_HEAD,
            anchor_id=anchor_id,
            sequence=sequence,
            digest=digest or f"{sequence:064x}",
            issued_at=0.0,
        )
    )


def make_receipt(
    witnesses,
    witness_id,
    checkpoint,
    policy,
    *,
    digest=None,
    sequence=None,
    policy_id=None,
    anchor_id=None,
    checkpoint_id=None,
    at=0.0,
):
    """One witness's signed statement about ``checkpoint`` under ``policy``."""

    return witnesses[witness_id].sign(
        QuorumReceipt(
            anchor_kind=checkpoint.kind.value,
            anchor_id=anchor_id or checkpoint.anchor_id,
            sequence=(
                int(checkpoint.sequence)
                if sequence is None
                else int(sequence)
            ),
            digest=digest or checkpoint.digest,
            checkpoint_id=checkpoint_id or checkpoint.checkpoint_id,
            policy_id=policy_id or policy.policy_id,
            witness_id="",
            issued_at=at,
        )
    )


def bound_round(
    *,
    threshold=2,
    ids=QUORUM_IDS,
    anchor_id="anchor-1",
    sequence=1,
    backend=None,
):
    """A journal with one checkpoint bound and ready to collect votes."""

    journal, witnesses, policy = make_journal(
        threshold=threshold, ids=ids, backend=backend
    )
    checkpoint = make_checkpoint(anchor_id=anchor_id, sequence=sequence)
    journal.bind_checkpoint(checkpoint)

    return journal, witnesses, policy, checkpoint


def collect(journal, witnesses, policy, checkpoint, ids=QUORUM_IDS):
    """Every witness votes once. Returns the receipts in witness order."""

    receipts = []

    for witness_id in ids:
        receipt = make_receipt(
            witnesses, witness_id, checkpoint, policy
        )
        journal.submit_receipt(receipt)
        receipts.append(receipt)

    return tuple(receipts)


# =====================================================================
# Policy identity
# =====================================================================


class TestWitnessPolicy:
    def test_the_id_is_the_digest_of_its_own_content(self):
        policy = WitnessPolicy.derive(2, ["a", "b", "c"])

        assert policy.rederives()
        assert policy.policy_id == policy.rederived_id()

    def test_declaration_order_does_not_change_the_id(self):
        first = WitnessPolicy.derive(2, ["a", "b", "c"])
        second = WitnessPolicy.derive(2, ["c", "b", "a"])

        assert first.policy_id == second.policy_id

    def test_a_declared_id_that_disagrees_is_refused(self):
        policy = WitnessPolicy.derive(2, ["a", "b", "c"])

        with pytest.raises(QuorumPolicyError):
            WitnessPolicy.from_dict({**policy.to_dict(), "policy_id": "x" * 64})

    def test_a_threshold_above_the_witness_count_is_refused(self):
        with pytest.raises(QuorumPolicyError):
            WitnessPolicy.derive(4, ["a", "b", "c"])

    def test_a_zero_threshold_is_refused(self):
        with pytest.raises(QuorumPolicyError):
            WitnessPolicy.derive(0, ["a"])

    def test_duplicate_identities_collapse_rather_than_multiply(self):
        policy = WitnessPolicy.derive(2, ["a", "a", "b"])

        assert policy.witness_ids == ("a", "b")

    def test_a_forged_policy_does_not_rederive(self):
        policy = WitnessPolicy.derive(2, ["a", "b", "c"])
        weakened = replace(policy, threshold=1)

        assert not weakened.rederives()

    def test_trusts_only_named_identities(self):
        policy = WitnessPolicy.derive(2, ["a", "b", "c"])

        assert policy.trusts("a")
        assert not policy.trusts("d")
        assert not policy.trusts(None)


# =====================================================================
# Successful rounds
# =====================================================================


class TestQuorumSuccess:
    def test_two_of_three_confirms(self):
        journal, witnesses, policy, checkpoint = bound_round(threshold=2)
        collect(journal, witnesses, policy, checkpoint, ids=QUORUM_IDS[:2])

        decision = journal.confirm_quorum(
            AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
        )

        assert decision.satisfied is True
        assert decision.reason is None
        assert decision.witness_ids == (QUORUM_IDS[0], QUORUM_IDS[1])
        assert decision.votes == 2
        assert decision.rederives()

    def test_unanimous_three_of_three_confirms(self):
        journal, witnesses, policy, checkpoint = bound_round(threshold=3)
        collect(journal, witnesses, policy, checkpoint)

        decision = journal.confirm_quorum(
            AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
        )

        assert decision.satisfied is True
        assert decision.witness_ids == tuple(sorted(QUORUM_IDS))
        assert decision.votes == 3

    def test_one_of_one_confirms(self):
        journal, witnesses, policy, checkpoint = bound_round(
            threshold=1, ids=QUORUM_IDS[:1]
        )
        collect(
            journal, witnesses, policy, checkpoint, ids=QUORUM_IDS[:1]
        )

        decision = journal.confirm_quorum(
            AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
        )

        assert decision.satisfied is True
        assert decision.threshold == 1

    def test_the_status_reports_the_round_before_and_after(self):
        journal, witnesses, policy, checkpoint = bound_round(threshold=2)

        before = journal.status(
            AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
        )

        assert before.satisfied is False
        assert before.confirmed is False
        assert before.reason == "anchor_quorum_insufficient"
        assert before.votes == 0

        collect(journal, witnesses, policy, checkpoint, ids=QUORUM_IDS[:2])
        journal.confirm_quorum(
            AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
        )

        after = journal.status(
            AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
        )

        assert after.satisfied is True
        assert after.confirmed is True
        assert after.reason is None
        assert after.votes == 2
        assert after.threshold == 2
        assert after.policy_id == policy.policy_id

    def test_confirmation_is_monotone(self):
        journal, witnesses, policy, checkpoint = bound_round(threshold=2)
        collect(journal, witnesses, policy, checkpoint)

        first = journal.confirm_quorum(
            AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
        )
        second = journal.confirm_quorum(
            AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
        )

        assert first.satisfied and second.satisfied
        assert first.decision_id == second.decision_id

    def test_the_confirmed_decision_is_readable_by_anchor(self):
        journal, witnesses, policy, checkpoint = bound_round(threshold=2)
        collect(journal, witnesses, policy, checkpoint)
        journal.confirm_quorum(
            AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
        )

        decision = journal.confirmed(
            AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
        )

        assert decision is not None
        assert decision.sequence == 1
        assert decision.digest == checkpoint.digest

    def test_a_round_that_was_never_bound_does_not_confirm(self):
        journal, _witnesses, _policy = make_journal()

        decision = journal.confirm_quorum(
            AnchorKind.LINEAGE_HEAD, "never-bound"
        )

        assert decision.satisfied is False
        assert decision.reason == "anchor_quorum_unconfirmed"

    def test_no_policy_in_force_means_no_trusted_witness(self):
        journal = WitnessQuorumJournal()
        checkpoint = make_checkpoint()
        witness = InProcessQuorumWitness(
            witness_id="rogue",
            private_key=Ed25519PrivateKey.generate(),
        )
        journal.register_witness_key(
            "rogue", witness._private_key.public_key()
        )

        with pytest.raises(QuorumError) as caught:
            journal.bind_checkpoint(checkpoint)

        assert caught.value.reason == "anchor_policy_mismatch"

    def test_the_binding_rederives_and_names_the_policy(self):
        journal, _w, policy, checkpoint = bound_round()
        binding = journal.target(
            AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
        )

        assert isinstance(binding, CheckpointPolicyBinding)
        assert binding.rederives()
        assert binding.policy_id == policy.policy_id
        assert binding.checkpoint_id == checkpoint.checkpoint_id

    def test_binding_the_same_checkpoint_twice_is_idempotent(self):
        journal, _w, _p, checkpoint = bound_round()

        first = journal.bind_checkpoint(checkpoint)
        second = journal.bind_checkpoint(checkpoint)

        assert first.binding_id == second.binding_id


# =====================================================================
# Insufficient quorum
# =====================================================================


class TestInsufficientQuorum:
    def test_one_vote_against_a_threshold_of_two_is_insufficient(self):
        journal, witnesses, policy, checkpoint = bound_round(threshold=2)
        journal.submit_receipt(
            make_receipt(witnesses, QUORUM_IDS[0], checkpoint, policy)
        )

        decision = journal.confirm_quorum(
            AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
        )

        assert decision.satisfied is False
        assert decision.reason == "anchor_quorum_insufficient"
        assert decision.votes == 1

    def test_no_votes_at_all_is_insufficient(self):
        journal, _w, _p, checkpoint = bound_round(threshold=2)

        decision = journal.confirm_quorum(
            AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
        )

        assert decision.satisfied is False
        assert decision.reason == "anchor_quorum_insufficient"
        assert decision.witness_ids == ()

    def test_insufficient_is_a_finding_not_a_silence(self):
        journal, witnesses, policy, checkpoint = bound_round(threshold=2)
        journal.submit_receipt(
            make_receipt(witnesses, QUORUM_IDS[0], checkpoint, policy)
        )
        journal.confirm_quorum(
            AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
        )

        assert any(
            finding.kind == "quorum_insufficient"
            for finding in journal.findings()
        )

    def test_below_threshold_never_confirms_the_anchor(self):
        journal, witnesses, policy, checkpoint = bound_round(threshold=3)
        journal.submit_receipt(
            make_receipt(witnesses, QUORUM_IDS[0], checkpoint, policy)
        )
        journal.submit_receipt(
            make_receipt(witnesses, QUORUM_IDS[1], checkpoint, policy)
        )
        journal.confirm_quorum(
            AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
        )

        assert (
            journal.confirmed(
                AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
            )
            is None
        )

    def test_a_late_witness_completes_the_round(self):
        journal, witnesses, policy, checkpoint = bound_round(threshold=2)
        journal.submit_receipt(
            make_receipt(witnesses, QUORUM_IDS[0], checkpoint, policy)
        )
        journal.confirm_quorum(
            AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
        )
        journal.submit_receipt(
            make_receipt(witnesses, QUORUM_IDS[1], checkpoint, policy)
        )

        decision = journal.confirm_quorum(
            AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
        )

        assert decision.satisfied is True
        assert decision.votes == 2


# =====================================================================
# Forged and tampered receipts
# =====================================================================


class TestInvalidSignatures:
    def test_an_edited_signature_is_refused(self):
        journal, witnesses, policy, checkpoint = bound_round()
        good = make_receipt(witnesses, QUORUM_IDS[0], checkpoint, policy)
        forged = replace(good, signature="AAAA")

        with pytest.raises(QuorumError) as caught:
            journal.submit_receipt(forged)

        assert caught.value.reason == "anchor_witness_invalid_signature"

    def test_an_unsigned_receipt_is_refused(self):
        journal, witnesses, policy, checkpoint = bound_round()
        blank = replace(
            make_receipt(witnesses, QUORUM_IDS[0], checkpoint, policy),
            signature="",
        )

        with pytest.raises(QuorumError) as caught:
            journal.submit_receipt(blank)

        assert caught.value.reason == "anchor_witness_invalid_signature"

    def test_a_receipt_whose_id_does_not_rederive_is_refused(self):
        journal, witnesses, policy, checkpoint = bound_round()
        good = make_receipt(witnesses, QUORUM_IDS[0], checkpoint, policy)
        edited = replace(good, receipt_id="0" * 64)

        with pytest.raises(QuorumError) as caught:
            journal.submit_receipt(edited)

        assert caught.value.reason == "anchor_witness_invalid_signature"

    def test_a_signature_from_another_witnesss_key_is_refused(self):
        journal, witnesses, policy, checkpoint = bound_round()
        other = InProcessQuorumWitness(
            witness_id=QUORUM_IDS[0],
            private_key=Ed25519PrivateKey.generate(),
        )

        with pytest.raises(QuorumError) as caught:
            journal.submit_receipt(
                other.sign(
                    QuorumReceipt(
                        anchor_kind=checkpoint.kind.value,
                        anchor_id=checkpoint.anchor_id,
                        sequence=checkpoint.sequence,
                        digest=checkpoint.digest,
                        checkpoint_id=checkpoint.checkpoint_id,
                        policy_id=policy.policy_id,
                        witness_id="",
                        issued_at=0.0,
                    )
                )
            )

        assert caught.value.reason == "anchor_witness_invalid_signature"

    def test_a_forged_vote_is_never_counted(self):
        journal, witnesses, policy, checkpoint = bound_round()
        good = make_receipt(witnesses, QUORUM_IDS[0], checkpoint, policy)

        with pytest.raises(QuorumError):
            journal.submit_receipt(replace(good, signature="AAAA"))

        assert journal.votes(
            AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
        ) == ()

    def test_a_malformed_payload_is_refused_rather_than_coerced(self):
        with pytest.raises(QuorumSignatureError):
            QuorumReceipt.from_dict({"anchor_kind": "not-a-kind"})

        with pytest.raises(QuorumSignatureError):
            QuorumReceipt.from_dict("not an object")


# =====================================================================
# Duplicate identities
# =====================================================================


class TestDuplicateWitnessVotes:
    def test_a_second_receipt_from_one_witness_is_refused(self):
        journal, witnesses, policy, checkpoint = bound_round()
        journal.submit_receipt(
            make_receipt(
                witnesses, QUORUM_IDS[0], checkpoint, policy, at=1.0
            )
        )

        with pytest.raises(QuorumError) as caught:
            journal.submit_receipt(
                make_receipt(
                    witnesses, QUORUM_IDS[0], checkpoint, policy, at=2.0
                )
            )

        assert caught.value.reason == "anchor_witness_duplicate"

    def test_a_duplicate_never_adds_a_vote(self):
        journal, witnesses, policy, checkpoint = bound_round(threshold=2)
        journal.submit_receipt(
            make_receipt(
                witnesses, QUORUM_IDS[0], checkpoint, policy, at=1.0
            )
        )

        for at in (2.0, 3.0, 4.0):
            with pytest.raises(QuorumDuplicateWitnessError):
                journal.submit_receipt(
                    make_receipt(
                        witnesses, QUORUM_IDS[0], checkpoint, policy, at=at
                    )
                )

        decision = journal.confirm_quorum(
            AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
        )

        assert decision.satisfied is False
        assert decision.votes == 1
        assert decision.reason == "anchor_quorum_insufficient"

    def test_idempotent_replay_of_one_receipt_is_not_an_error(self):
        journal, witnesses, policy, checkpoint = bound_round(threshold=2)
        receipt = make_receipt(
            witnesses, QUORUM_IDS[0], checkpoint, policy
        )

        journal.submit_receipt(receipt)
        journal.submit_receipt(receipt)
        journal.submit_receipt(receipt)

        status = journal.status(
            AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
        )

        assert status.votes == 1
        assert len(journal.receipts()) == 1

    def test_idempotent_replay_does_not_complete_a_round(self):
        journal, witnesses, policy, checkpoint = bound_round(threshold=2)
        receipt = make_receipt(
            witnesses, QUORUM_IDS[0], checkpoint, policy
        )

        for _ in range(5):
            journal.submit_receipt(receipt)

        decision = journal.confirm_quorum(
            AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
        )

        assert decision.satisfied is False
        assert decision.votes == 1

    def test_a_duplicate_is_recorded_as_a_finding(self):
        journal, witnesses, policy, checkpoint = bound_round()
        journal.submit_receipt(
            make_receipt(
                witnesses, QUORUM_IDS[0], checkpoint, policy, at=1.0
            )
        )

        with pytest.raises(QuorumDuplicateWitnessError):
            journal.submit_receipt(
                make_receipt(
                    witnesses, QUORUM_IDS[0], checkpoint, policy, at=2.0
                )
            )

        assert any(
            finding.kind == "witness_duplicate"
            for finding in journal.findings()
        )


# =====================================================================
# Untrusted identities
# =====================================================================


class TestUntrustedWitnesses:
    def test_a_registered_key_the_policy_does_not_name_is_untrusted(self):
        journal, witnesses, policy, checkpoint = bound_round()
        outsider = "outsider"
        key = Ed25519PrivateKey.generate()
        journal.register_witness_key(outsider, key.public_key())

        receipt = InProcessQuorumWitness(
            witness_id=outsider, private_key=key
        ).sign(
            QuorumReceipt(
                anchor_kind=checkpoint.kind.value,
                anchor_id=checkpoint.anchor_id,
                sequence=checkpoint.sequence,
                digest=checkpoint.digest,
                checkpoint_id=checkpoint.checkpoint_id,
                policy_id=policy.policy_id,
                witness_id="",
                issued_at=0.0,
            )
        )

        with pytest.raises(QuorumError) as caught:
            journal.submit_receipt(receipt)

        assert caught.value.reason == "anchor_witness_untrusted"

    def test_an_unregistered_key_is_untrusted(self):
        journal, witnesses, policy, checkpoint = bound_round()
        receipt = make_receipt(witnesses, QUORUM_IDS[0], checkpoint, policy)
        journal._witness_keys.pop(QUORUM_IDS[0])

        with pytest.raises(QuorumError) as caught:
            journal.submit_receipt(receipt)

        assert caught.value.reason == "anchor_witness_untrusted"

    def test_an_untrusted_vote_is_never_counted(self):
        journal, witnesses, policy, checkpoint = bound_round(threshold=2)
        key = Ed25519PrivateKey.generate()
        journal.register_witness_key("outsider", key.public_key())

        receipt = InProcessQuorumWitness(
            witness_id="outsider", private_key=key
        ).sign(
            QuorumReceipt(
                anchor_kind=checkpoint.kind.value,
                anchor_id=checkpoint.anchor_id,
                sequence=checkpoint.sequence,
                digest=checkpoint.digest,
                checkpoint_id=checkpoint.checkpoint_id,
                policy_id=policy.policy_id,
                witness_id="",
                issued_at=0.0,
            )
        )

        with pytest.raises(QuorumUntrustedWitnessError):
            journal.submit_receipt(receipt)

        assert journal.votes(
            AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
        ) == ()

    def test_the_signature_is_checked_after_trust_not_instead_of_it(self):
        """An untrusted identity is refused as untrusted, not as forged.

        Both are refusals, so the ordering is not a security property --
        but the audit trail has to say which one happened, or an operator
        investigating a compromised witness sees "bad signature" and goes
        looking for a bug.
        """

        journal, witnesses, policy, checkpoint = bound_round()
        receipt = make_receipt(witnesses, QUORUM_IDS[0], checkpoint, policy)
        journal._witness_keys.pop(QUORUM_IDS[0])

        with pytest.raises(QuorumUntrustedWitnessError):
            journal.submit_receipt(receipt)

        assert all(
            finding.kind != "witness_invalid_signature"
            for finding in journal.findings()
        )


# =====================================================================
# Stale positions
# =====================================================================


class TestStaleReceipts:
    def test_a_receipt_behind_the_bound_position_is_stale(self):
        journal, witnesses, policy, checkpoint = bound_round(sequence=5)
        old = make_receipt(
            witnesses, QUORUM_IDS[0], checkpoint, policy, sequence=3
        )

        with pytest.raises(QuorumError) as caught:
            journal.submit_receipt(old)

        assert caught.value.reason == "anchor_witness_stale"

    def test_binding_behind_a_confirmed_position_is_stale(self):
        journal, witnesses, policy, checkpoint = bound_round(
            threshold=2, sequence=3
        )
        collect(journal, witnesses, policy, checkpoint)
        journal.confirm_quorum(
            AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
        )

        with pytest.raises(QuorumError) as caught:
            journal.bind_checkpoint(
                make_checkpoint(
                    anchor_id=checkpoint.anchor_id, sequence=2
                )
            )

        assert caught.value.reason == "anchor_witness_stale"

    def test_a_receipt_ahead_of_anything_anchored_is_mismatch(self):
        journal, witnesses, policy, checkpoint = bound_round(sequence=3)
        ahead = make_receipt(
            witnesses, QUORUM_IDS[0], checkpoint, policy, sequence=9
        )

        with pytest.raises(QuorumError) as caught:
            journal.submit_receipt(ahead)

        assert caught.value.reason == "anchor_checkpoint_mismatch"

    def test_a_stale_vote_is_never_counted(self):
        journal, witnesses, policy, checkpoint = bound_round(sequence=5)

        with pytest.raises(QuorumStaleReceiptError):
            journal.submit_receipt(
                make_receipt(
                    witnesses, QUORUM_IDS[0], checkpoint, policy, sequence=4
                )
            )

        assert journal.votes(
            AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id, 5
        ) == ()


# =====================================================================
# Checkpoint and policy mismatch
# =====================================================================


class TestCheckpointMismatch:
    def test_a_receipt_for_a_different_digest_is_refused(self):
        journal, witnesses, policy, checkpoint = bound_round()
        other = make_receipt(
            witnesses, QUORUM_IDS[0], checkpoint, policy, digest="f" * 64
        )

        with pytest.raises(QuorumError) as caught:
            journal.submit_receipt(other)

        assert caught.value.reason == "anchor_checkpoint_mismatch"

    def test_a_receipt_for_an_unbound_anchor_is_refused(self):
        journal, witnesses, policy, checkpoint = bound_round()
        elsewhere = make_receipt(
            witnesses,
            QUORUM_IDS[0],
            checkpoint,
            policy,
            anchor_id="anchor-elsewhere",
        )

        with pytest.raises(QuorumError) as caught:
            journal.submit_receipt(elsewhere)

        assert caught.value.reason == "anchor_checkpoint_mismatch"

    def test_a_receipt_for_a_different_checkpoint_id_is_refused(self):
        journal, witnesses, policy, checkpoint = bound_round()
        other = make_receipt(
            witnesses,
            QUORUM_IDS[0],
            checkpoint,
            policy,
            checkpoint_id="f" * 64,
        )

        with pytest.raises(QuorumError) as caught:
            journal.submit_receipt(other)

        assert caught.value.reason == "anchor_checkpoint_mismatch"


class TestPolicyMismatch:
    def test_a_receipt_under_another_policy_is_refused(self):
        journal, witnesses, policy, checkpoint = bound_round()
        other = WitnessPolicy.derive(1, QUORUM_IDS)

        with pytest.raises(QuorumError) as caught:
            journal.submit_receipt(
                make_receipt(
                    witnesses,
                    QUORUM_IDS[0],
                    checkpoint,
                    policy,
                    policy_id=other.policy_id,
                )
            )

        assert caught.value.reason == "anchor_policy_mismatch"

    def test_rebinding_a_checkpoint_to_another_policy_is_refused(self):
        journal, _w, policy, checkpoint = bound_round()
        weaker = WitnessPolicy.derive(1, QUORUM_IDS)
        journal.register_policy(weaker)

        with pytest.raises(QuorumError) as caught:
            journal.bind_checkpoint(checkpoint, policy_id=weaker.policy_id)

        assert caught.value.reason == "anchor_policy_mismatch"

    def test_activating_a_different_policy_after_use_is_refused(self):
        journal, witnesses, policy, checkpoint = bound_round()
        weaker = WitnessPolicy.derive(1, QUORUM_IDS)
        journal.register_policy(weaker)

        with pytest.raises(QuorumError) as caught:
            journal.activate_policy(weaker.policy_id)

        assert caught.value.reason == "anchor_policy_mismatch"

    def test_activating_before_any_use_is_allowed(self):
        journal, _w, _p = make_journal()
        other = WitnessPolicy.derive(3, QUORUM_IDS)
        journal.register_policy(other)

        assert journal.activate_policy(other.policy_id).policy_id == (
            other.policy_id
        )

    def test_a_policy_mismatch_is_recorded_as_a_finding(self):
        journal, witnesses, policy, checkpoint = bound_round()
        other = WitnessPolicy.derive(1, QUORUM_IDS)

        with pytest.raises(QuorumPolicyError):
            journal.submit_receipt(
                make_receipt(
                    witnesses,
                    QUORUM_IDS[0],
                    checkpoint,
                    policy,
                    policy_id=other.policy_id,
                )
            )

        assert any(
            finding.kind == "policy_mismatch"
            for finding in journal.findings()
        )


# =====================================================================
# Replay
# =====================================================================


class TestReplayAcrossAnchors:
    def test_a_receipt_cannot_be_counted_for_another_anchor(self):
        journal, witnesses, policy = make_journal(threshold=1)[0:3]
        first = make_checkpoint(anchor_id="anchor-1", sequence=1)
        second = make_checkpoint(anchor_id="anchor-2", sequence=1)

        journal.bind_checkpoint(first)
        journal.bind_checkpoint(second)

        journal.submit_receipt(
            make_receipt(witnesses, QUORUM_IDS[0], second, policy)
        )

        assert journal.status(
            AnchorKind.LINEAGE_HEAD, "anchor-1"
        ).votes == 0
        assert journal.status(
            AnchorKind.LINEAGE_HEAD, "anchor-2"
        ).votes == 1

    def test_offering_another_anchors_receipt_to_a_round_is_refused(self):
        journal, witnesses, policy = make_journal(threshold=2)
        first = make_checkpoint(anchor_id="anchor-1", sequence=1)
        journal.bind_checkpoint(first)

        # A receipt that authenticates a different anchor id, offered to a
        # journal that only ever bound anchor-1.
        elsewhere = make_checkpoint(anchor_id="anchor-2", sequence=1)
        receipt = make_receipt(
            witnesses, QUORUM_IDS[0], elsewhere, policy
        )

        with pytest.raises(QuorumError) as caught:
            journal.submit_receipt(receipt)

        assert caught.value.reason == "anchor_checkpoint_mismatch"

    def test_the_anchor_id_is_inside_the_signed_block(self):
        """Re-pointing a receipt at another anchor moves the signature.

        The test that makes the previous two more than policy: the bytes
        that would do it are bytes the witness never signed.
        """

        journal, witnesses, policy, checkpoint = bound_round()
        good = make_receipt(witnesses, QUORUM_IDS[0], checkpoint, policy)
        moved = replace(good, anchor_id="anchor-2")

        assert moved.rederived_id() != moved.receipt_id

        with pytest.raises(QuorumSignatureError):
            journal.submit_receipt(moved)


class TestReplayAcrossPolicies:
    def test_a_receipt_under_the_old_policy_does_not_count(self):
        journal, witnesses, policy, checkpoint = bound_round(threshold=2)
        older = WitnessPolicy.derive(1, QUORUM_IDS)

        with pytest.raises(QuorumPolicyError):
            journal.submit_receipt(
                make_receipt(
                    witnesses,
                    QUORUM_IDS[0],
                    checkpoint,
                    policy,
                    policy_id=older.policy_id,
                )
            )

        assert journal.status(
            AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
        ).votes == 0

    def test_the_policy_id_is_inside_the_signed_block(self):
        journal, witnesses, policy, checkpoint = bound_round()
        good = make_receipt(witnesses, QUORUM_IDS[0], checkpoint, policy)
        moved = replace(good, policy_id="0" * 64)

        assert moved.rederived_id() != moved.receipt_id

        with pytest.raises(QuorumSignatureError):
            journal.submit_receipt(moved)

    def test_a_weaker_policy_cannot_adopt_a_confirmed_checkpoint(self):
        """The downgrade this module exists to make impossible."""

        journal, witnesses, policy, checkpoint = bound_round(threshold=3)
        collect(journal, witnesses, policy, checkpoint)
        journal.confirm_quorum(
            AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
        )

        weaker = WitnessPolicy.derive(1, QUORUM_IDS)
        journal.register_policy(weaker)

        with pytest.raises(QuorumPolicyError):
            journal.bind_checkpoint(
                checkpoint, policy_id=weaker.policy_id
            )


# =====================================================================
# Equivocation
# =====================================================================


class TestWitnessEquivocation:
    def test_a_conflicting_second_statement_is_refused(self):
        journal, witnesses, policy, checkpoint = bound_round()
        journal.submit_receipt(
            make_receipt(witnesses, QUORUM_IDS[0], checkpoint, policy)
        )

        with pytest.raises(QuorumError) as caught:
            journal.submit_receipt(
                make_receipt(
                    witnesses,
                    QUORUM_IDS[0],
                    checkpoint,
                    policy,
                    digest="e" * 64,
                )
            )

        assert caught.value.reason == "anchor_witness_equivocation"

    def test_both_statements_are_preserved(self):
        journal, witnesses, policy, checkpoint = bound_round()
        first = make_receipt(
            witnesses, QUORUM_IDS[0], checkpoint, policy, at=1.0
        )
        journal.submit_receipt(first)
        second = make_receipt(
            witnesses,
            QUORUM_IDS[0],
            checkpoint,
            policy,
            digest="e" * 64,
            at=2.0,
        )

        with pytest.raises(QuorumEquivocationError):
            journal.submit_receipt(second)

        evidence = journal.equivocations()

        assert len(evidence) == 1
        assert evidence[0].first.receipt_id == first.receipt_id
        assert evidence[0].second.receipt_id == second.receipt_id
        assert evidence[0].first.digest != evidence[0].second.digest

    def test_both_statements_still_verify(self):
        """Neither half is a forgery -- that is what makes it equivocation.

        A witness that signed two things signed two things. Keeping both
        verifiable is what lets an operator prove it to a third party
        rather than asking them to take the firewall's word.
        """

        journal, witnesses, policy, checkpoint = bound_round()
        journal.submit_receipt(
            make_receipt(witnesses, QUORUM_IDS[0], checkpoint, policy)
        )

        with pytest.raises(QuorumEquivocationError):
            journal.submit_receipt(
                make_receipt(
                    witnesses,
                    QUORUM_IDS[0],
                    checkpoint,
                    policy,
                    digest="e" * 64,
                )
            )

        evidence = journal.equivocations()[0]

        assert journal.verify_receipt(evidence.first)
        assert journal.verify_receipt(evidence.second)

    def test_the_equivocating_witness_stops_counting(self):
        journal, witnesses, policy, checkpoint = bound_round(threshold=2)
        journal.submit_receipt(
            make_receipt(witnesses, QUORUM_IDS[0], checkpoint, policy)
        )
        journal.submit_receipt(
            make_receipt(witnesses, QUORUM_IDS[1], checkpoint, policy)
        )

        with pytest.raises(QuorumEquivocationError):
            journal.submit_receipt(
                make_receipt(
                    witnesses,
                    QUORUM_IDS[0],
                    checkpoint,
                    policy,
                    digest="e" * 64,
                )
            )

        status = journal.status(
            AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
        )

        assert QUORUM_IDS[0] not in status.witness_ids
        assert status.votes == 1

    def test_equivocation_is_recorded_as_a_finding(self):
        journal, witnesses, policy, checkpoint = bound_round()
        journal.submit_receipt(
            make_receipt(witnesses, QUORUM_IDS[0], checkpoint, policy)
        )

        with pytest.raises(QuorumEquivocationError):
            journal.submit_receipt(
                make_receipt(
                    witnesses,
                    QUORUM_IDS[0],
                    checkpoint,
                    policy,
                    digest="e" * 64,
                )
            )

        assert any(
            finding.kind == "witness_equivocation"
            for finding in journal.findings()
        )

    def test_equivocation_is_exposed_through_the_sdk(self):
        sdk, witnesses, policy = make_quorum_sdk(threshold=2)
        try:
            checkpoint = make_checkpoint(anchor_id="anchor-1", sequence=1)
            sdk.quorum_bind_checkpoint(checkpoint)
            sdk.quorum_submit_receipt(
                make_receipt(
                    witnesses, QUORUM_IDS[0], checkpoint, policy
                )
            )

            with pytest.raises(QuorumEquivocationError):
                sdk.quorum_submit_receipt(
                    make_receipt(
                        witnesses,
                        QUORUM_IDS[0],
                        checkpoint,
                        policy,
                        digest="e" * 64,
                    )
                )

            exposed = sdk.quorum_equivocations()

            assert len(exposed) == 1
            assert isinstance(exposed[0], EquivocationEvidence)
            assert exposed[0].witness_id == QUORUM_IDS[0]
        finally:
            sdk.close()

    def test_equivocation_survives_a_restart(self, tmp_path):
        store = SQLiteQuorumStore(tmp_path / "quorum.db")
        journal, witnesses, policy, checkpoint = bound_round(
            backend=store
        )
        journal.submit_receipt(
            make_receipt(witnesses, QUORUM_IDS[0], checkpoint, policy)
        )

        with pytest.raises(QuorumEquivocationError):
            journal.submit_receipt(
                make_receipt(
                    witnesses,
                    QUORUM_IDS[0],
                    checkpoint,
                    policy,
                    digest="e" * 64,
                )
            )

        store.close()

        reopened = SQLiteQuorumStore(tmp_path / "quorum.db")
        try:
            restored = WitnessQuorumJournal(backend=reopened)

            assert len(restored.equivocations()) == 1
        finally:
            reopened.close()


# =====================================================================
# Split votes
# =====================================================================


class TestSplitVotes:
    def test_a_dissenting_witness_makes_the_round_split(self):
        journal, witnesses, policy, checkpoint = bound_round(threshold=2)
        journal.submit_receipt(
            make_receipt(witnesses, QUORUM_IDS[0], checkpoint, policy)
        )
        journal.submit_receipt(
            make_receipt(witnesses, QUORUM_IDS[1], checkpoint, policy)
        )

        with pytest.raises(QuorumCheckpointMismatchError):
            journal.submit_receipt(
                make_receipt(
                    witnesses,
                    QUORUM_IDS[2],
                    checkpoint,
                    policy,
                    digest="z" * 64,
                )
            )

        status = journal.status(
            AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
        )

        assert status.reason == "anchor_quorum_split"
        assert status.satisfied is False

    def test_a_split_round_never_confirms(self):
        journal, witnesses, policy, checkpoint = bound_round(threshold=2)
        journal.submit_receipt(
            make_receipt(witnesses, QUORUM_IDS[0], checkpoint, policy)
        )
        journal.submit_receipt(
            make_receipt(witnesses, QUORUM_IDS[1], checkpoint, policy)
        )

        with pytest.raises(QuorumCheckpointMismatchError):
            journal.submit_receipt(
                make_receipt(
                    witnesses,
                    QUORUM_IDS[2],
                    checkpoint,
                    policy,
                    digest="z" * 64,
                )
            )

        decision = journal.confirm_quorum(
            AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
        )

        assert decision.satisfied is False
        assert decision.reason == "anchor_quorum_split"

    def test_no_threshold_of_agreeing_witnesses_confirms_over_dissent(self):
        """The whole point of a quorum is that disagreement is not averaged.

        Two of three agreeing is two of three agreeing, and it is still
        not a quorum: the third witness authenticated a different state,
        and a layer that confirmed anyway would be reporting an agreement
        that does not exist.
        """

        journal, witnesses, policy, checkpoint = bound_round(threshold=2)
        journal.submit_receipt(
            make_receipt(witnesses, QUORUM_IDS[0], checkpoint, policy)
        )
        journal.submit_receipt(
            make_receipt(witnesses, QUORUM_IDS[1], checkpoint, policy)
        )

        with pytest.raises(QuorumCheckpointMismatchError):
            journal.submit_receipt(
                make_receipt(
                    witnesses,
                    QUORUM_IDS[2],
                    checkpoint,
                    policy,
                    digest="z" * 64,
                )
            )

        assert (
            journal.confirmed(
                AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
            )
            is None
        )

    def test_dissent_is_exposed_rather_than_dropped(self):
        journal, witnesses, policy, checkpoint = bound_round()
        dissenting = make_receipt(
            witnesses, QUORUM_IDS[2], checkpoint, policy, digest="z" * 64
        )

        with pytest.raises(QuorumCheckpointMismatchError):
            journal.submit_receipt(dissenting)

        dissent = journal.dissent(
            AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
        )

        assert len(dissent) == 1
        assert dissent[0].witness_id == QUORUM_IDS[2]

    def test_a_split_is_recorded_as_a_finding(self):
        journal, witnesses, policy, checkpoint = bound_round()

        with pytest.raises(QuorumCheckpointMismatchError):
            journal.submit_receipt(
                make_receipt(
                    witnesses,
                    QUORUM_IDS[2],
                    checkpoint,
                    policy,
                    digest="z" * 64,
                )
            )

        journal.confirm_quorum(
            AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
        )

        assert any(
            finding.kind == "quorum_split"
            for finding in journal.findings()
        )


# =====================================================================
# Durability
# =====================================================================


class TestDurability:
    def test_a_confirmed_round_survives_a_restart(self, tmp_path):
        store = SQLiteQuorumStore(tmp_path / "quorum.db")
        journal, witnesses, policy, checkpoint = bound_round(
            threshold=2, backend=store
        )
        collect(journal, witnesses, policy, checkpoint, ids=QUORUM_IDS[:2])
        journal.confirm_quorum(
            AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
        )
        store.close()

        reopened = SQLiteQuorumStore(tmp_path / "quorum.db")
        try:
            restored = WitnessQuorumJournal(
                backend=reopened,
                witness_keys={
                    witness_id: witness._private_key.public_key()
                    for witness_id, witness in witnesses.items()
                },
            )

            decision = restored.confirmed(
                AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
            )

            assert decision is not None
            assert decision.satisfied is True
            assert decision.sequence == 1
            assert restored.poisoned() == ()
        finally:
            reopened.close()

    def test_the_active_policy_survives_a_restart(self, tmp_path):
        store = SQLiteQuorumStore(tmp_path / "quorum.db")
        journal, _w, policy, _c = bound_round(backend=store)
        store.close()

        reopened = SQLiteQuorumStore(tmp_path / "quorum.db")
        try:
            restored = WitnessQuorumJournal(backend=reopened)

            assert restored.active_policy() is not None
            assert restored.active_policy().policy_id == policy.policy_id
        finally:
            reopened.close()

    def test_the_store_refuses_a_receipt_that_does_not_rederive(
        self, tmp_path
    ):
        store = SQLiteQuorumStore(tmp_path / "quorum.db")
        _journal, witnesses, policy, checkpoint = bound_round()
        receipt = make_receipt(
            witnesses, QUORUM_IDS[0], checkpoint, policy
        )

        try:
            with pytest.raises(QuorumStoreError):
                store.insert_receipt(
                    replace(receipt, receipt_id="0" * 64)
                )
        finally:
            store.close()

    def test_the_store_refuses_a_policy_that_does_not_rederive(
        self, tmp_path
    ):
        store = SQLiteQuorumStore(tmp_path / "quorum.db")
        policy = WitnessPolicy.derive(2, QUORUM_IDS)

        try:
            with pytest.raises(QuorumPolicyError):
                store.insert_policy(replace(policy, threshold=1))
        finally:
            store.close()

    def test_the_store_refuses_to_unconfirm_a_decision(self, tmp_path):
        store = SQLiteQuorumStore(tmp_path / "quorum.db")
        journal, witnesses, policy, checkpoint = bound_round(
            threshold=2, backend=store
        )
        collect(journal, witnesses, policy, checkpoint, ids=QUORUM_IDS[:2])
        decision = journal.confirm_quorum(
            AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
        )

        with pytest.raises(QuorumStoreError):
            store.insert_decision(replace(decision, satisfied=False))

        store.close()

    def test_the_quorum_store_is_its_own_database(self, tmp_path):
        """Nothing unrelated shares the file the quorum reasons over."""

        store = SQLiteQuorumStore(tmp_path / "quorum.db")

        try:
            tables = {
                row[0]
                for row in store._require_connection()
                .execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
                .fetchall()
            }
        finally:
            store.close()

        assert tables
        assert all(
            name.startswith("quorum_") or name.startswith("sqlite_")
            for name in tables
        ), tables


# =====================================================================
# Tampering with persisted state
# =====================================================================


class TestTamperedPersistedState:
    def _seed(self, tmp_path, *, threshold=2):
        store = SQLiteQuorumStore(tmp_path / "quorum.db")
        journal, witnesses, policy, checkpoint = bound_round(
            threshold=threshold, backend=store
        )
        collect(journal, witnesses, policy, checkpoint, ids=QUORUM_IDS[:2])
        journal.confirm_quorum(
            AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
        )
        store.close()

        return checkpoint

    def test_a_rewritten_decision_threshold_poisons_the_anchor(
        self, tmp_path
    ):
        checkpoint = self._seed(tmp_path)

        connection = sqlite3.connect(tmp_path / "quorum.db")
        connection.execute("UPDATE quorum_decisions SET threshold = 1")
        connection.commit()
        connection.close()

        store = SQLiteQuorumStore(tmp_path / "quorum.db")
        try:
            restored = WitnessQuorumJournal(backend=store)
        finally:
            store.close()

        assert (AnchorKind.LINEAGE_HEAD.value, checkpoint.anchor_id) in (
            restored.poisoned()
        )

    def test_a_poisoned_anchor_refuses_to_confirm(self, tmp_path):
        checkpoint = self._seed(tmp_path)

        connection = sqlite3.connect(tmp_path / "quorum.db")
        connection.execute("UPDATE quorum_decisions SET threshold = 1")
        connection.commit()
        connection.close()

        store = SQLiteQuorumStore(tmp_path / "quorum.db")
        try:
            restored = WitnessQuorumJournal(backend=store)

            assert (
                restored.confirm_quorum(
                    AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
                ).reason
                == "anchor_quorum_unverifiable"
            )
            assert (
                restored.status(
                    AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
                ).reason
                == "anchor_quorum_unverifiable"
            )
        finally:
            store.close()

    def test_a_poisoned_anchor_records_a_tampered_finding(self, tmp_path):
        self._seed(tmp_path)

        connection = sqlite3.connect(tmp_path / "quorum.db")
        connection.execute("UPDATE quorum_decisions SET threshold = 1")
        connection.commit()
        connection.close()

        store = SQLiteQuorumStore(tmp_path / "quorum.db")
        try:
            restored = WitnessQuorumJournal(backend=store)

            assert any(
                finding.kind == "tampered"
                for finding in restored.findings()
            )
        finally:
            store.close()

    def test_a_rewritten_receipt_digest_poisons_the_anchor(self, tmp_path):
        checkpoint = self._seed(tmp_path)

        connection = sqlite3.connect(tmp_path / "quorum.db")
        connection.execute(
            "UPDATE quorum_receipts SET digest = ?", ("f" * 64,)
        )
        connection.commit()
        connection.close()

        store = SQLiteQuorumStore(tmp_path / "quorum.db")
        try:
            restored = WitnessQuorumJournal(backend=store)
        finally:
            store.close()

        assert (AnchorKind.LINEAGE_HEAD.value, checkpoint.anchor_id) in (
            restored.poisoned()
        )

    def test_a_rewritten_policy_threshold_is_quarantined(self, tmp_path):
        self._seed(tmp_path)

        connection = sqlite3.connect(tmp_path / "quorum.db")
        connection.execute("UPDATE quorum_policies SET threshold = 1")
        connection.commit()
        connection.close()

        store = SQLiteQuorumStore(tmp_path / "quorum.db")
        try:
            restored = WitnessQuorumJournal(backend=store)

            assert any(
                finding.kind == "tampered"
                for finding in restored.findings()
            )
        finally:
            store.close()

    def test_an_unwritable_backend_is_a_denial_not_an_empty_journal(self):
        class Broken:
            def load_policies(self):
                raise OSError("gone")

        with pytest.raises(QuorumStoreError):
            WitnessQuorumJournal(backend=Broken())


# =====================================================================
# The SDK boundary
# =====================================================================


class TestSdkSurface:
    def test_the_sdk_exposes_the_quorum_journal(self):
        sdk, _w, _p = make_quorum_sdk()

        try:
            assert isinstance(sdk.quorum, WitnessQuorumJournal)
            assert sdk.quorum_journal is sdk.quorum
        finally:
            sdk.close()

    def test_every_quorum_facing_api_is_present(self):
        sdk, _w, _p = make_quorum_sdk()

        try:
            for name in (
                "quorum_register_policy",
                "quorum_activate_policy",
                "quorum_bind_checkpoint",
                "quorum_submit_receipt",
                "quorum_status",
                "quorum_confirm",
                "quorum_confirmed",
                "quorum_receipts",
                "quorum_votes",
                "quorum_dissent",
                "quorum_decisions",
                "quorum_policies",
                "quorum_active_policy",
                "quorum_bindings",
                "quorum_equivocations",
                "quorum_findings",
                "quorum_participation",
            ):
                assert callable(getattr(sdk, name)), name
        finally:
            sdk.close()

    def test_a_round_driven_through_the_sdk(self):
        sdk, witnesses, policy = make_quorum_sdk(threshold=2)

        try:
            checkpoint = make_checkpoint(anchor_id="anchor-1", sequence=1)
            sdk.quorum_bind_checkpoint(checkpoint)

            for witness_id in QUORUM_IDS[:2]:
                sdk.quorum_submit_receipt(
                    make_receipt(witnesses, witness_id, checkpoint, policy)
                )

            decision = sdk.quorum_confirm(
                AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
            )

            assert isinstance(decision, QuorumDecision)
            assert decision.satisfied is True
            assert len(sdk.quorum_receipts()) == 2
            assert len(sdk.quorum_participation()) == 2
        finally:
            sdk.close()

    def test_read_only_enforcement_flags(self):
        sdk, _w, _p = make_quorum_sdk(require_quorum=True)

        try:
            assert sdk.require_witness_quorum is True

            with pytest.raises(AttributeError):
                sdk.require_witness_quorum = False

            assert sdk.require_witness_quorum is True
        finally:
            sdk.close()

    def test_the_v34_flag_is_still_read_only(self):
        sdk = make_sdk(require_external_anchor=True)

        try:
            with pytest.raises(AttributeError):
                sdk.require_external_anchor = False

            assert sdk.require_external_anchor is True
        finally:
            sdk.close()

    def test_a_non_boolean_flag_is_refused(self):
        with pytest.raises(TypeError):
            FirewallSDK(require_witness_quorum="yes")

    def test_quorum_witness_keys_must_be_a_mapping(self):
        with pytest.raises(TypeError):
            FirewallSDK(quorum_witness_keys=["not", "a", "mapping"])

    def test_no_policy_means_no_quorum_rather_than_a_default_one(self):
        sdk = make_sdk(require_witness_quorum=True)

        try:
            assert sdk.quorum_active_policy() is None
            assert sdk.quorum_policies() == ()

            checkpoint = make_checkpoint()

            with pytest.raises(QuorumPolicyError):
                sdk.quorum_bind_checkpoint(checkpoint)
        finally:
            sdk.close()


# =====================================================================
# The ALLOW path is untouched
# =====================================================================


class TestAllowBehaviourIsUnchanged:
    def test_authorize_is_identical_with_and_without_a_quorum(self):
        plain = make_sdk()
        quorate, _witnesses, _policy = make_quorum_sdk(threshold=3)

        try:
            plain_capability = make_capability(plain)
            quorate_capability = make_capability(quorate)

            plain_outcome = plain.authorize(
                plain_capability, ACTION, dict(REQUEST)
            )
            quorate_outcome = quorate.authorize(
                quorate_capability, ACTION, dict(REQUEST)
            )

            assert plain_outcome.allowed == quorate_outcome.allowed
            assert plain_outcome.reason == quorate_outcome.reason
            assert quorate_outcome.allowed is True
        finally:
            plain.close()
            quorate.close()

    def test_confirming_a_round_does_not_change_an_allow(self):
        sdk, witnesses, policy = make_quorum_sdk(threshold=2)
        capability = make_capability(sdk)

        try:
            before = sdk.authorize(capability, ACTION, dict(REQUEST))

            checkpoint = make_checkpoint(anchor_id="anchor-1", sequence=1)
            sdk.quorum_bind_checkpoint(checkpoint)

            for witness_id in QUORUM_IDS[:2]:
                sdk.quorum_submit_receipt(
                    make_receipt(witnesses, witness_id, checkpoint, policy)
                )

            sdk.quorum_confirm(
                AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
            )

            after = sdk.authorize(capability, ACTION, dict(REQUEST))

            assert before.allowed == after.allowed
            assert before.reason == after.reason
        finally:
            sdk.close()

    def test_a_denied_capability_stays_denied_with_a_quorum(self):
        sdk, _w, _p = make_quorum_sdk(threshold=3)
        capability = make_capability(sdk)

        try:
            outcome = sdk.authorize(capability, "other.action", dict(REQUEST))

            assert outcome.allowed is False
        finally:
            sdk.close()


# =====================================================================
# The progression gate
# =====================================================================


class TestTheProgressionGate:
    def test_the_gate_refuses_before_a_quorum_exists(self):
        sdk, _w, _p = make_quorum_sdk(
            threshold=2, require_quorum=True
        )
        capability = make_capability(sdk)

        try:
            issued = sdk.authorize_execution(
                capability, ACTION, dict(REQUEST)
            )

            assert issued.allowed, issued.reason

            refused = sdk.reserve_execution(
                issued.lease,
                capability,
                ACTION,
                dict(REQUEST),
                execution_id="v35-gate-1",
            )

            assert refused.allowed is False
            assert refused.reason == "anchor_quorum_unconfirmed"
        finally:
            sdk.close()

    def test_the_gate_agrees_after_a_quorum_is_taken(self):
        sdk, witnesses, policy = make_quorum_sdk(
            threshold=2, require_quorum=True
        )
        capability = make_capability(sdk)

        try:
            issued = sdk.authorize_execution(
                capability, ACTION, dict(REQUEST)
            )
            assert issued.allowed, issued.reason

            lineage = sdk.lineage_for_lease(issued.lease.lease_id)
            assert lineage is not None
            anchor_id = lineage.lineage_id

            checkpoint = sdk.anchor_confirm(
                sdk.anchor_publish(AnchorKind.LINEAGE_HEAD, anchor_id)
            )
            sdk.quorum_bind_checkpoint(checkpoint)

            for witness_id in QUORUM_IDS[:2]:
                sdk.quorum_submit_receipt(
                    make_receipt(witnesses, witness_id, checkpoint, policy)
                )

            sdk.quorum_confirm(AnchorKind.LINEAGE_HEAD, anchor_id)

            allowed = sdk.reserve_execution(
                issued.lease,
                capability,
                ACTION,
                dict(REQUEST),
                execution_id="v35-gate-2",
            )

            assert allowed.allowed, allowed.reason
        finally:
            sdk.close()

    def test_the_gate_is_off_by_default(self):
        sdk, _w, _p = make_quorum_sdk(
            threshold=2, require_quorum=False
        )
        capability = make_capability(sdk)

        try:
            issued = sdk.authorize_execution(
                capability, ACTION, dict(REQUEST)
            )
            assert issued.allowed, issued.reason

            allowed = sdk.reserve_execution(
                issued.lease,
                capability,
                ACTION,
                dict(REQUEST),
                execution_id="v35-gate-3",
            )

            assert allowed.allowed, allowed.reason
        finally:
            sdk.close()

    def test_the_gate_refuses_when_the_round_split(self):
        sdk, witnesses, policy = make_quorum_sdk(
            threshold=2, require_quorum=True
        )
        capability = make_capability(sdk)

        try:
            issued = sdk.authorize_execution(
                capability, ACTION, dict(REQUEST)
            )
            lineage = sdk.lineage_for_lease(issued.lease.lease_id)
            anchor_id = lineage.lineage_id

            checkpoint = sdk.anchor_confirm(
                sdk.anchor_publish(AnchorKind.LINEAGE_HEAD, anchor_id)
            )
            sdk.quorum_bind_checkpoint(checkpoint)
            sdk.quorum_submit_receipt(
                make_receipt(witnesses, QUORUM_IDS[0], checkpoint, policy)
            )

            with pytest.raises(QuorumCheckpointMismatchError):
                sdk.quorum_submit_receipt(
                    make_receipt(
                        witnesses,
                        QUORUM_IDS[1],
                        checkpoint,
                        policy,
                        digest="z" * 64,
                    )
                )

            assert (
                sdk.quorum_confirm(
                    AnchorKind.LINEAGE_HEAD, anchor_id
                ).reason
                == "anchor_quorum_split"
            )

            refused = sdk.reserve_execution(
                issued.lease,
                capability,
                ACTION,
                dict(REQUEST),
                execution_id="v35-gate-4",
            )

            assert refused.allowed is False
            assert refused.reason == "anchor_quorum_unconfirmed"
        finally:
            sdk.close()


# =====================================================================
# Source census teeth
# =====================================================================


class TestSourceCensusTeeth:
    def test_the_census_is_closed(self):
        findings, notes = runtime_module._quorum_source_findings()

        assert findings == ()
        assert notes

    def test_an_undeclared_journal_caller_is_a_violation(self, monkeypatch):
        monkeypatch.setattr(
            runtime_module, "QUORUM_MUTATOR_OWNERS", frozenset()
        )
        findings, _ = runtime_module._quorum_source_findings()

        assert any(
            "drives the quorum journal" in finding for finding in findings
        )

    def test_a_declared_caller_that_drives_nothing_is_a_violation(
        self, monkeypatch
    ):
        monkeypatch.setattr(
            runtime_module,
            "QUORUM_MUTATOR_OWNERS",
            frozenset(
                runtime_module.QUORUM_MUTATOR_OWNERS
                | {("firewall/sdk.py", "FirewallSDK.quorum_receipts")}
            ),
        )
        findings, _ = runtime_module._quorum_source_findings()

        assert any(
            "drives no journal mutator" in finding for finding in findings
        )

    def test_a_declared_caller_absent_from_the_package_is_a_violation(
        self, monkeypatch
    ):
        monkeypatch.setattr(
            runtime_module,
            "QUORUM_MUTATOR_OWNERS",
            frozenset(
                runtime_module.QUORUM_MUTATOR_OWNERS
                | {("firewall/nowhere.py", "FirewallSDK.quorum_confirm")}
            ),
        )
        findings, _ = runtime_module._quorum_source_findings()

        assert any(
            "absent from the package" in finding for finding in findings
        )

    def test_an_allow_path_reference_is_a_violation(self, monkeypatch):
        monkeypatch.setattr(
            runtime_module,
            "QUORUM_ALLOW_PATH_OWNERS",
            frozenset(
                runtime_module.QUORUM_ALLOW_PATH_OWNERS
                | {"FirewallSDK._quorum_gate"}
            ),
        )
        findings, _ = runtime_module._quorum_source_findings()

        assert any("ALLOW path" in finding for finding in findings)

    def test_the_gate_prefix_rule_does_not_match_quorum_helpers(self):
        """``_quorum_gate`` is not ``_gate_*``, and the census must not
        treat a deny-only helper as a decision anyway."""

        findings, _ = runtime_module._quorum_source_findings()

        assert not any(
            "_quorum_gate" in finding and "ALLOW path" in finding
            for finding in findings
        )

    def test_the_quorum_module_constructs_no_verdict(self):
        import firewall.quorum as module

        tree = ast.parse(
            Path(module.__file__).read_text(encoding="utf-8")
        )

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

            assert name not in ("AuthorizationResult", "_result"), name


# =====================================================================
# The invariant
# =====================================================================


class TestTheInvariant:
    def test_the_registry_reports_the_invariant(self):
        entry = invariant("WITNESS_QUORUM_SOUNDNESS")

        assert "No single external witness" in entry.statement
        assert "threshold of distinct trusted witnesses" in entry.statement
        assert entry.needs_state is True
        assert len(INVARIANTS) == 26

    def test_a_source_census_violation_is_reported(self, monkeypatch):
        monkeypatch.setattr(
            runtime_module, "QUORUM_MUTATOR_OWNERS", frozenset()
        )
        sdk, _w, _p = make_quorum_sdk()

        try:
            result = runtime_module.check_witness_quorum_soundness(sdk)

            assert result.holds is False
            assert result.status.value == "violated"
        finally:
            sdk.close()

    def test_no_decisions_is_unverifiable_rather_than_holds(self):
        sdk, _w, _p = make_quorum_sdk()

        try:
            result = runtime_module.check_witness_quorum_soundness(sdk)

            assert result.status.value == "unverifiable"
        finally:
            sdk.close()

    def test_no_sdk_is_unverifiable(self):
        result = runtime_module.check_witness_quorum_soundness(None)

        assert result.status.value == "unverifiable"

    def test_a_sdk_with_no_quorum_journal_is_a_violation(self):
        class Fake:
            quorum = "not a journal"

        result = runtime_module.check_witness_quorum_soundness(Fake())

        assert result.holds is False

    def test_a_satisfied_decision_below_threshold_is_a_violation(self):
        sdk, witnesses, policy = make_quorum_sdk(threshold=3)

        try:
            checkpoint = make_checkpoint(anchor_id="anchor-1", sequence=1)
            sdk.quorum_bind_checkpoint(checkpoint)
            sdk.quorum_submit_receipt(
                make_receipt(witnesses, QUORUM_IDS[0], checkpoint, policy)
            )
            decision = sdk.quorum_confirm(
                AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
            )

            assert decision.satisfied is False

            # Forge the state a real attack would try to produce: a
            # decision that claims satisfaction with one vote.
            forged = QuorumDecision.derive(
                anchor_kind=decision.anchor_kind,
                anchor_id=decision.anchor_id,
                sequence=decision.sequence,
                digest=decision.digest,
                checkpoint_id=decision.checkpoint_id,
                policy_id=decision.policy_id,
                threshold=decision.threshold,
                witness_ids=decision.witness_ids,
                satisfied=True,
                reason=None,
                at=decision.at,
            )
            sdk.quorum._decisions[
                (decision.anchor_kind, decision.anchor_id, decision.sequence)
            ] = forged
            sdk.quorum._confirmed[
                (decision.anchor_kind, decision.anchor_id)
            ] = forged

            result = runtime_module.check_witness_quorum_soundness(sdk)

            assert result.holds is False
            assert any(
                "distinct witness" in finding for finding in result.findings
            )
        finally:
            sdk.close()

    def test_a_counted_equivocating_witness_is_a_violation(self):
        sdk, witnesses, policy = make_quorum_sdk(threshold=2)

        try:
            checkpoint = make_checkpoint(anchor_id="anchor-1", sequence=1)
            sdk.quorum_bind_checkpoint(checkpoint)

            for witness_id in QUORUM_IDS[:2]:
                sdk.quorum_submit_receipt(
                    make_receipt(
                        witnesses, witness_id, checkpoint, policy
                    )
                )

            decision = sdk.quorum_confirm(
                AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
            )
            assert decision.satisfied is True

            # The witness now signs a second, conflicting statement. The
            # vote is withdrawn -- and the decision which still counts it
            # must therefore fail the audit rather than stand.
            with pytest.raises(QuorumEquivocationError):
                sdk.quorum_submit_receipt(
                    make_receipt(
                        witnesses,
                        QUORUM_IDS[0],
                        checkpoint,
                        policy,
                        digest="e" * 64,
                    )
                )

            result = runtime_module.check_witness_quorum_soundness(sdk)

            assert result.holds is False
            assert any(
                "equivocated" in finding for finding in result.findings
            )
        finally:
            sdk.close()

    def test_an_unexplained_finding_is_a_violation(self):
        sdk, _w, _p = make_quorum_sdk()

        try:
            sdk.quorum.record_finding("something-this-release-never-says")

            result = runtime_module.check_witness_quorum_soundness(sdk)

            assert result.status.value == "unverifiable"
        finally:
            sdk.close()

    def test_finding_kinds_are_declared(self):
        assert "quorum_insufficient" in QUORUM_FINDING_KINDS
        assert "witness_equivocation" in QUORUM_FINDING_KINDS
        assert "tampered" in QUORUM_FINDING_KINDS


# =====================================================================
# Property-based
# =====================================================================


class TestProperties:
    @settings(
        max_examples=25,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    @given(
        data=st.data(),
    )
    def test_a_round_confirms_exactly_when_the_threshold_is_met(
        self, data
    ):
        size = data.draw(st.integers(min_value=1, max_value=4), label="n")
        threshold = data.draw(
            st.integers(min_value=1, max_value=size), label="threshold"
        )
        voters = data.draw(
            st.lists(
                st.integers(min_value=0, max_value=size - 1),
                unique=True,
                max_size=size,
            ),
            label="voters",
        )

        ids = tuple(f"w-{index}" for index in range(size))
        journal, witnesses, policy, checkpoint = bound_round(
            threshold=threshold, ids=ids
        )

        for index in voters:
            journal.submit_receipt(
                make_receipt(witnesses, ids[index], checkpoint, policy)
            )

        decision = journal.confirm_quorum(
            AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
        )

        assert decision.satisfied is (len(voters) >= threshold)
        assert decision.votes == len(voters)
        assert len(set(decision.witness_ids)) == len(decision.witness_ids)
        assert decision.rederives()

    @settings(
        max_examples=25,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    @given(
        extra=st.lists(
            st.floats(allow_nan=False, allow_infinity=False),
            min_size=1,
            max_size=4,
        ),
    )
    def test_duplicate_identities_never_add_votes(self, extra):
        journal, witnesses, policy, checkpoint = bound_round(
            threshold=2, ids=QUORUM_IDS
        )
        journal.submit_receipt(
            make_receipt(
                witnesses, QUORUM_IDS[0], checkpoint, policy, at=1.0
            )
        )

        for at in extra:
            try:
                journal.submit_receipt(
                    make_receipt(
                        witnesses,
                        QUORUM_IDS[0],
                        checkpoint,
                        policy,
                        at=at,
                    )
                )
            except QuorumDuplicateWitnessError:
                pass
            except QuorumEquivocationError:
                pytest.fail("a repeated statement is not equivocation")

        assert (
            journal.status(
                AnchorKind.LINEAGE_HEAD, checkpoint.anchor_id
            ).votes
            == 1
        )

    @settings(
        max_examples=25,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    @given(
        digest=st.text(
            alphabet="0123456789abcdef", min_size=1, max_size=64
        ),
    )
    def test_only_the_exact_statement_is_counted(self, digest):
        journal, witnesses, policy, checkpoint = bound_round(
            threshold=1, ids=QUORUM_IDS[:1]
        )

        try:
            journal.submit_receipt(
                make_receipt(
                    witnesses,
                    QUORUM_IDS[0],
                    checkpoint,
                    policy,
                    digest=digest,
                )
            )
            counted = True
        except QuorumCheckpointMismatchError:
            counted = False

        assert counted is (digest == checkpoint.digest)
