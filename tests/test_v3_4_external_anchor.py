"""v3.4: external anchoring -- attack the twenty-fifth invariant.

Every release before this one raised the cost of tampering and then, in its
own honest-non-guarantees list, admitted the same thing: the root of trust
stayed inside the process. v3.0 chained the canonical state digest, v3.2
anchored every window, v3.3 chained an execution's whole lineage -- and the
*head* of each of those chains is a row in a store the same process writes.
A chain that the process can rewrite is tamper-*evident* only against a
tamperer who is not that process.

``EXTERNAL_ANCHOR_SOUNDNESS`` (the twenty-fifth registered invariant)
machine-checks the layer that closes it:

.. code-block:: text

    publish -> confirm -> compare

* **Published** -- an anchor's current value is handed to a witness that
  holds a signing key the firewall does not, and the checkpoint it returns
  re-derives to its own id and verifies under a *registered* key.
* **Confirmed** -- the signed receipt is recorded locally, and the confirmed
  sequence for each anchor is monotone: a checkpoint at or below the last
  confirmed one is refused by name, never stored.
* **Compared** -- every progression path asks whether the live anchor still
  carries the commitment the last confirmed checkpoint names, and refuses
  ``anchor_mismatch``, ``anchor_truncated``, ``anchor_unconfirmed``,
  ``anchor_missing`` or ``anchor_witness_unavailable`` when it does not.

This file attacks each of those from both sides -- the SDK boundary and the
invariant -- and asserts that the *gate* fails closed, not merely that the
audit notices afterwards.
"""

from __future__ import annotations

import ast
import json
import uuid

from dataclasses import replace
from pathlib import Path

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from firewall.anchor import (
    ANCHOR_FINDING_KINDS,
    AnchorCheckpoint,
    AnchorJournal,
    AnchorJournalError,
    AnchorKind,
    AnchorMismatchError,
    AnchorRewindError,
    AnchorSignatureError,
    AnchorWitness,
    AnchorWitnessUnavailableError,
    InProcessWitness,
    LocalFileWitness,
    NullWitness,
    RemoteWitness,
    verify_checkpoint_signature,
)
from firewall.anchor_store import SQLiteAnchorStore
from firewall.effect import (
    EffectOutcome,
    ReceiptKind,
)
from firewall.effect_verification import (
    VerificationOutcome,
    VerifierVerdict,
)
from firewall.external_attestation import (
    build_attestation,
    canonical_external_state_digest,
)
from firewall.invariants import check_external_anchor_soundness
from firewall.invariants import runtime as runtime_module
from firewall.invariants.model import InvariantStatus
from firewall.invariants.runtime import _anchor_source_findings
from firewall.sdk import FirewallSDK

ACTION = "payments.send"
REQUEST = {"amount": 5}
EFFECT = {"to": "acct-9", "amount": 5}
EFFECT_TYPE = "transfer"
KEY = "key-anchor"
PROVIDER = "acme-payments"

WITNESS_KEY_ID = "witness-1"
WITNESS_PRIVATE = Ed25519PrivateKey.generate()
WITNESS_PUBLIC = WITNESS_PRIVATE.public_key()

ISSUER_PRIVATE = Ed25519PrivateKey.generate()


# ======================================================================
# Helpers
# ======================================================================


def make_witness(*, key_id=WITNESS_KEY_ID, private_key=None):
    return InProcessWitness(
        key_id=key_id,
        private_key=private_key or WITNESS_PRIVATE,
    )


def make_sdk(**kwargs):
    kwargs.setdefault("anchor_witness", make_witness())
    kwargs.setdefault("witness_keys", {WITNESS_KEY_ID: WITNESS_PUBLIC})

    sdk = FirewallSDK(**kwargs)
    sdk.generate_key(f"v34-{uuid.uuid4().hex[:8]}")
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


def lineage_id_for(sdk, lease_id):
    lineage = sdk.lineage_for_lease(lease_id)
    assert lineage is not None, "no lineage for this lease"
    return lineage.lineage_id


def anchor_the_lineage(sdk, lease_id):
    """Publish and confirm one checkpoint at the chain's current head."""

    anchor_id = lineage_id_for(sdk, lease_id)
    checkpoint = sdk.anchor_publish(AnchorKind.LINEAGE_HEAD, anchor_id)
    return sdk.anchor_confirm(checkpoint)


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
        external_request_id="ext-anchor",
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


def walk_completed(sdk, capability, *, execution_id="exec-anchor"):
    """The whole pipeline to a COMPLETED, attested lease."""

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
        idempotency_key=KEY,
    )
    assert prepared.allowed, prepared.reason

    attempted = sdk.attempt_effect(
        started.lease,
        capability,
        ACTION,
        dict(REQUEST),
        effect=dict(EFFECT),
        effect_type=EFFECT_TYPE,
        idempotency_key=KEY,
    )
    assert attempted.allowed, attempted.reason

    record_success(sdk, capability, started.lease)

    envelope = envelope_for(sdk, started.lease)
    attested = sdk.record_attestation(
        started.lease,
        capability,
        ACTION,
        dict(REQUEST),
        effect=dict(EFFECT),
        effect_type=EFFECT_TYPE,
        idempotency_key=KEY,
        attestation=envelope,
    )
    assert attested.allowed, attested.reason

    outcome = sdk.commit_effect(
        started.lease,
        capability,
        ACTION,
        dict(REQUEST),
        effect=dict(EFFECT),
        effect_type=EFFECT_TYPE,
        idempotency_key=KEY,
        verifier=authenticator,
        method="acme-authenticator",
        attestation=envelope,
        attestation_required=True,
    )
    assert outcome.allowed, outcome.reason

    return issued, started, outcome


def walk_completed_gated(sdk, capability, *, execution_id="exec-gated"):
    """The whole pipeline with the anchor gate *on*.

    Requires ``require_external_anchor=True``, and demonstrates the workflow
    the gate imposes: every progression must be preceded by a publish and a
    confirm at the chain's current head, or the next step refuses
    ``anchor_unconfirmed``. Anchoring is skipped when the head has not moved
    since the last checkpoint, because re-publishing one position is the
    rewind the journal refuses by name.
    """

    seen: set[int] = set()

    def anchor_head(lease_id):
        anchor_id = lineage_id_for(sdk, lease_id)
        head = sdk._lineage_head_value(anchor_id)
        assert head is not None

        if int(head[0]) in seen:
            return None

        seen.add(int(head[0]))
        return sdk.anchor_confirm(
            sdk.anchor_publish(AnchorKind.LINEAGE_HEAD, anchor_id)
        )

    issued = sdk.authorize_execution(capability, ACTION, dict(REQUEST))
    assert issued.allowed, issued.reason
    anchor_head(issued.lease.lease_id)

    reserved = sdk.reserve_execution(
        issued.lease,
        capability,
        ACTION,
        dict(REQUEST),
        execution_id=execution_id,
    )
    assert reserved.allowed, reserved.reason
    anchor_head(issued.lease.lease_id)

    started = sdk.start_execution(
        reserved.lease, capability, ACTION, dict(REQUEST)
    )
    assert started.allowed, started.reason
    anchor_head(issued.lease.lease_id)

    prepared = sdk.prepare_effect(
        started.lease,
        capability,
        ACTION,
        dict(REQUEST),
        effect=dict(EFFECT),
        effect_type=EFFECT_TYPE,
        idempotency_key=KEY,
    )
    assert prepared.allowed, prepared.reason
    anchor_head(issued.lease.lease_id)

    attempted = sdk.attempt_effect(
        started.lease,
        capability,
        ACTION,
        dict(REQUEST),
        effect=dict(EFFECT),
        effect_type=EFFECT_TYPE,
        idempotency_key=KEY,
    )
    assert attempted.allowed, attempted.reason
    anchor_head(issued.lease.lease_id)

    record_success(sdk, capability, started.lease)
    anchor_head(issued.lease.lease_id)

    envelope = envelope_for(sdk, started.lease)
    attested = sdk.record_attestation(
        started.lease,
        capability,
        ACTION,
        dict(REQUEST),
        effect=dict(EFFECT),
        effect_type=EFFECT_TYPE,
        idempotency_key=KEY,
        attestation=envelope,
    )
    assert attested.allowed, attested.reason
    anchor_head(issued.lease.lease_id)

    outcome = sdk.commit_effect(
        started.lease,
        capability,
        ACTION,
        dict(REQUEST),
        effect=dict(EFFECT),
        effect_type=EFFECT_TYPE,
        idempotency_key=KEY,
        verifier=authenticator,
        method="acme-authenticator",
        attestation=envelope,
        attestation_required=True,
    )
    assert outcome.allowed, outcome.reason
    anchor_head(issued.lease.lease_id)

    return issued, started, outcome


def audit(sdk):
    return check_external_anchor_soundness(sdk)


class FakeAnchor:
    """A controllable anchor: a head, and a digest per position.

    Exists so the ``compare`` algebra can be attacked directly, on a kind the
    SDK does not bind, without building a whole execution to move a chain
    head by one stage.
    """

    def __init__(self):
        self.head = None
        self.positions: dict[int, str] = {}

    def read(self, anchor_id):
        return self.head

    def prefix(self, anchor_id, sequence):
        return self.positions.get(int(sequence))

    def place(self, sequence, digest):
        """Put the head at a position and record what it committed to there."""

        self.head = (int(sequence), str(digest))
        self.positions[int(sequence)] = str(digest)
        return self


# ======================================================================
# Calibration
# ======================================================================


class TestCalibration:
    def test_a_witnessed_sdk_publishes_and_confirms(self):
        sdk = make_sdk()
        capability = make_capability(sdk)
        issued, _started, _outcome = walk_completed(sdk, capability)

        receipt = anchor_the_lineage(sdk, issued.lease.lease_id)
        records = sdk.anchor_records()
        receipts = sdk.anchor_receipts()
        result = audit(sdk)
        sdk.close()

        assert receipt.kind is AnchorKind.LINEAGE_HEAD
        assert receipt.is_signed()
        assert receipt.rederived_id() == receipt.checkpoint_id
        assert len(records) == 1
        assert len(receipts) == 1
        assert result.status is InvariantStatus.HOLDS, result.reason
        assert result.details["checkpoints"] == 1
        assert result.details["confirmed"] == 1

    def test_a_fresh_sdk_with_no_witness_reports_unverifiable(self):
        sdk = FirewallSDK()
        sdk.generate_key(f"v34-{uuid.uuid4().hex[:8]}")
        capability = make_capability(sdk)
        issued = sdk.authorize_execution(capability, ACTION, dict(REQUEST))
        assert issued.allowed

        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.UNVERIFIABLE
        assert "no anchor checkpoint has been published" in result.reason

    def test_a_published_but_unconfirmed_checkpoint_holds_with_zero_confirmed(
        self,
    ):
        """Publishing alone is not a claim about a root of trust, but the
        record-integrity half still has something to examine -- and a
        checkpoint that re-derives and verifies is not a finding."""

        sdk = make_sdk()
        capability = make_capability(sdk)
        issued, _started, _outcome = walk_completed(sdk, capability)
        anchor_id = lineage_id_for(sdk, issued.lease.lease_id)

        sdk.anchor_publish(AnchorKind.LINEAGE_HEAD, anchor_id)
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.HOLDS, result.reason
        assert result.details["confirmed"] == 0

    def test_the_registry_reports_the_invariant(self):
        from firewall.invariants import INVARIANTS, invariant

        entry = invariant("EXTERNAL_ANCHOR_SOUNDNESS")

        assert "a root of trust" in entry.statement
        assert entry.needs_state is True
        assert len(INVARIANTS) == 26


# ======================================================================
# The checkpoint
# ======================================================================


class TestTheCheckpoint:
    def _checkpoint(self, **overrides):
        payload = dict(
            kind=AnchorKind.LINEAGE_HEAD,
            anchor_id="lineage-1",
            sequence=3,
            digest="d" * 64,
            issued_at=1_700_000_000.0,
        )
        payload.update(overrides)
        return AnchorCheckpoint(**payload)

    def test_a_checkpoint_re_derives_to_its_own_id(self):
        stamped = make_witness().sign(self._checkpoint())

        assert stamped.rederived_id() == stamped.checkpoint_id
        assert verify_checkpoint_signature(stamped, WITNESS_PUBLIC)
        assert stamped.is_signed()

    def test_an_edited_checkpoint_no_longer_re_derives(self):
        stamped = make_witness().sign(self._checkpoint())

        assert replace(stamped, digest="e" * 64).rederived_id() != (
            stamped.checkpoint_id
        )
        assert replace(stamped, sequence=4).rederived_id() != (
            stamped.checkpoint_id
        )
        assert replace(stamped, anchor_id="lineage-2").rederived_id() != (
            stamped.checkpoint_id
        )

    def test_a_signature_cannot_be_moved_to_another_witness(self):
        """The key id is inside the signed block, so re-attribution moves
        the signature and the checkpoint stops verifying."""

        stamped = make_witness().sign(self._checkpoint())
        moved = replace(stamped, witness_key_id="witness-2")

        assert not verify_checkpoint_signature(moved, WITNESS_PUBLIC)

    def test_a_checkpoint_round_trips_through_its_wire_form(self):
        stamped = make_witness().sign(self._checkpoint())
        again = AnchorCheckpoint.from_dict(
            json.loads(json.dumps(stamped.to_dict()))
        )

        assert again == stamped
        assert again.rederived_id() == again.checkpoint_id

    @pytest.mark.parametrize(
        "payload",
        [
            "not-an-object",
            {"kind": "not-a-kind", "anchor_id": "l", "sequence": 1,
             "digest": "d", "issued_at": 0.0},
            {"kind": "lineage_head", "anchor_id": "", "sequence": 1,
             "digest": "d", "issued_at": 0.0},
            {"kind": "lineage_head", "anchor_id": "l", "sequence": -1,
             "digest": "d", "issued_at": 0.0},
            {"kind": "lineage_head", "anchor_id": "l", "sequence": True,
             "digest": "d", "issued_at": 0.0},
            {"kind": "lineage_head", "anchor_id": "l", "sequence": 1,
             "digest": "", "issued_at": 0.0},
            {"kind": "lineage_head", "anchor_id": "l", "sequence": 1,
             "digest": "d", "issued_at": "soon"},
            {"kind": "lineage_head", "anchor_id": "l", "sequence": 1,
             "digest": "d", "issued_at": 0.0, "algorithm": "RSA"},
        ],
    )
    def test_from_dict_refuses_a_malformed_checkpoint(self, payload):
        """A parser that tolerated a wrong type would be inventing a
        checkpoint to verify, and the one thing this layer must never do is
        verify something nobody signed."""

        with pytest.raises(AnchorSignatureError):
            AnchorCheckpoint.from_dict(payload)


# ======================================================================
# Publish and confirm
# ======================================================================


class TestPublishAndConfirm:
    def _journal(self, **kwargs):
        return AnchorJournal(
            witness=kwargs.pop("witness", make_witness()),
            witness_keys={
                WITNESS_KEY_ID: WITNESS_PUBLIC,
            },
            **kwargs,
        )

    def _bound(self, **kwargs):
        journal = self._journal(**kwargs)
        anchor = FakeAnchor().place(3, "d" * 64)
        journal.bind_reader(AnchorKind.LINEAGE_HEAD, anchor.read)
        journal.bind_prefix_reader(AnchorKind.LINEAGE_HEAD, anchor.prefix)
        return journal, anchor

    def test_the_null_witness_refuses_publish(self):
        journal = AnchorJournal(witness=NullWitness())
        anchor = FakeAnchor().place(1, "d" * 64)
        journal.bind_reader(AnchorKind.LINEAGE_HEAD, anchor.read)

        with pytest.raises(AnchorWitnessUnavailableError):
            journal.publish(AnchorKind.LINEAGE_HEAD, "lineage-1")

    def test_publish_refuses_a_kind_with_no_reader(self):
        journal = self._journal()

        with pytest.raises(Exception) as caught:
            journal.publish(AnchorKind.TEMPORAL_WATERMARK, "wm-1")

        assert "no reader is bound" in str(caught.value)

    def test_publish_refuses_a_rewind(self):
        """The "restore an older snapshot" attack, refused before the witness
        ever sees it."""

        journal, anchor = self._bound()
        journal.publish(AnchorKind.LINEAGE_HEAD, "lineage-1")

        anchor.place(2, "c" * 64)

        with pytest.raises(AnchorRewindError):
            journal.publish(AnchorKind.LINEAGE_HEAD, "lineage-1")

    def test_publish_refuses_a_replay_at_the_same_sequence(self):
        journal, _anchor = self._bound()
        journal.publish(AnchorKind.LINEAGE_HEAD, "lineage-1")

        with pytest.raises(AnchorRewindError):
            journal.publish(AnchorKind.LINEAGE_HEAD, "lineage-1")

    def test_confirm_refuses_a_forged_signature(self):
        journal, _anchor = self._bound()
        checkpoint = journal.publish(AnchorKind.LINEAGE_HEAD, "lineage-1")
        forged = replace(checkpoint, signature="AAAA")

        with pytest.raises(AnchorSignatureError):
            journal.confirm(forged)

        assert journal.receipts() == ()

    def test_confirm_refuses_a_key_nobody_registered(self):
        other = Ed25519PrivateKey.generate()
        journal, _anchor = self._bound()
        checkpoint = journal.publish(AnchorKind.LINEAGE_HEAD, "lineage-1")

        foreign = InProcessWitness(
            key_id="witness-9", private_key=other
        ).sign(checkpoint)

        with pytest.raises(AnchorSignatureError) as caught:
            journal.confirm(foreign)

        assert "not registered" in str(caught.value)

    def test_confirm_refuses_a_checkpoint_whose_id_does_not_re_derive(self):
        journal, _anchor = self._bound()
        checkpoint = journal.publish(AnchorKind.LINEAGE_HEAD, "lineage-1")
        edited = replace(checkpoint, digest="f" * 64)

        with pytest.raises(AnchorSignatureError) as caught:
            journal.confirm(edited)

        assert "re-derive" in str(caught.value)

    def test_confirm_refuses_a_receipt_at_or_below_the_confirmed_sequence(
        self,
    ):
        journal, anchor = self._bound()
        first = journal.publish(AnchorKind.LINEAGE_HEAD, "lineage-1")
        journal.confirm(first)

        anchor.place(4, "e" * 64)
        second = journal.publish(AnchorKind.LINEAGE_HEAD, "lineage-1")
        journal.confirm(second)

        # Replaying the older, perfectly valid receipt is the rollback of
        # the confirmed set: it would make an old checkpoint "current".
        with pytest.raises(AnchorRewindError):
            journal.confirm(first)

        assert len(journal.receipts()) == 2

    def test_nothing_refused_is_stored(self):
        journal, _anchor = self._bound()
        checkpoint = journal.publish(AnchorKind.LINEAGE_HEAD, "lineage-1")

        with pytest.raises(AnchorSignatureError):
            journal.confirm(replace(checkpoint, signature="AAAA"))

        assert journal.receipts() == ()
        assert journal.findings()

    def test_a_kind_with_no_prefix_reader_can_still_publish(self):
        journal = self._journal()
        anchor = FakeAnchor().place(1, "d" * 64)
        journal.bind_reader(AnchorKind.TEMPORAL_WATERMARK, anchor.read)

        checkpoint = journal.publish(AnchorKind.TEMPORAL_WATERMARK, "wm-1")

        assert checkpoint.kind is AnchorKind.TEMPORAL_WATERMARK
        assert journal.prefix_bound_kinds() == ()


# ======================================================================
# Compare -- the gate
# ======================================================================


class TestCompareTheGate:
    def _bound(self, *, prefix=True):
        journal = AnchorJournal(
            witness=make_witness(),
            witness_keys={WITNESS_KEY_ID: WITNESS_PUBLIC},
        )
        anchor = FakeAnchor()
        journal.bind_reader(AnchorKind.TEMPORAL_WATERMARK, anchor.read)

        if prefix:
            journal.bind_prefix_reader(
                AnchorKind.TEMPORAL_WATERMARK, anchor.prefix
            )

        return journal, anchor

    def _confirmed(self, journal, anchor, sequence, digest):
        anchor.place(sequence, digest)
        checkpoint = journal.publish(
            AnchorKind.TEMPORAL_WATERMARK, "wm-1"
        )
        journal.confirm(checkpoint)
        return checkpoint

    def test_compare_refuses_before_anything_is_confirmed(self):
        journal, _anchor = self._bound()

        assert journal.compare(
            AnchorKind.TEMPORAL_WATERMARK, "wm-1"
        ) == "anchor_unconfirmed"

    def test_compare_agrees_when_the_head_is_the_confirmed_checkpoint(self):
        journal, anchor = self._bound()
        self._confirmed(journal, anchor, 3, "d" * 64)

        assert journal.compare(AnchorKind.TEMPORAL_WATERMARK, "wm-1") is None

    def test_a_consistent_rewrite_at_the_same_sequence_is_a_mismatch(self):
        """Rewrite every store to a fabricated but internally consistent
        history of the same length: the head agrees on the position and
        disagrees on the commitment, which is all the check needs."""

        journal, anchor = self._bound()
        self._confirmed(journal, anchor, 3, "d" * 64)

        anchor.head = (3, "f" * 64)

        assert journal.compare(
            AnchorKind.TEMPORAL_WATERMARK, "wm-1"
        ) == "anchor_mismatch"

    def test_a_truncated_head_is_refused(self):
        """Tail truncation after the last publish: the anchor no longer has
        the position the witness confirmed."""

        journal, anchor = self._bound()
        self._confirmed(journal, anchor, 5, "d" * 64)

        anchor.head = (4, "d" * 64)

        assert journal.compare(
            AnchorKind.TEMPORAL_WATERMARK, "wm-1"
        ) == "anchor_truncated"

    def test_a_head_that_moved_on_is_checked_against_its_prefix(self):
        """The legitimate forward-progress case: the chain advanced past the
        confirmed checkpoint, and the confirmed commitment is still there."""

        journal, anchor = self._bound()
        self._confirmed(journal, anchor, 3, "d" * 64)

        anchor.place(7, "g" * 64)

        assert journal.compare(AnchorKind.TEMPORAL_WATERMARK, "wm-1") is None

    def test_a_longer_fabricated_chain_is_a_mismatch(self):
        """The hole a head-only comparison leaves open, closed.

        An attacker who rewrites the store into a fabricated but internally
        consistent history *longer* than the confirmed one presents a head at
        a higher sequence. Comparing heads alone would return "agree" without
        ever examining the confirmed commitment; asking the anchor what it
        committed to *at* the confirmed sequence catches it.
        """

        journal, anchor = self._bound()
        self._confirmed(journal, anchor, 3, "d" * 64)

        # A longer, internally consistent chain -- whose position 3 is not
        # the commitment the witness signed.
        anchor.head = (9, "h" * 64)
        anchor.positions[3] = "f" * 64

        assert journal.compare(
            AnchorKind.TEMPORAL_WATERMARK, "wm-1"
        ) == "anchor_mismatch"

    def test_a_longer_chain_that_lost_the_confirmed_position_is_truncated(
        self,
    ):
        journal, anchor = self._bound()
        self._confirmed(journal, anchor, 3, "d" * 64)

        anchor.head = (9, "h" * 64)
        anchor.positions.pop(3)

        assert journal.compare(
            AnchorKind.TEMPORAL_WATERMARK, "wm-1"
        ) == "anchor_truncated"

    def test_a_missing_prefix_reader_is_refused_not_assumed(self):
        journal, anchor = self._bound(prefix=False)
        self._confirmed(journal, anchor, 3, "d" * 64)

        # At the confirmed sequence no prefix read is needed, so the gate
        # still answers.
        assert journal.compare(AnchorKind.TEMPORAL_WATERMARK, "wm-1") is None

        anchor.place(7, "g" * 64)

        # Once the head moves on, the question cannot be answered, and
        # "cannot answer" is a refusal rather than an assumption.
        assert journal.compare(
            AnchorKind.TEMPORAL_WATERMARK, "wm-1"
        ) == "anchor_missing"

    def test_an_unconfirmed_kind_is_refused_before_the_reader_is_consulted(
        self,
    ):
        """Order matters: a kind with nothing confirmed is
        ``anchor_unconfirmed``, not ``anchor_missing``. The distinction is
        the difference between "you never anchored this" and "the anchor is
        unreadable", and an operator diagnosing one wants to know which."""

        journal, _anchor = self._bound()

        assert journal.compare(
            AnchorKind.ISSUER_REGISTRY, "registry"
        ) == "anchor_unconfirmed"

    def test_a_kind_whose_reader_was_never_bound_is_anchor_missing(self):
        journal, anchor = self._bound()
        self._confirmed(journal, anchor, 3, "d" * 64)
        del journal._readers[AnchorKind.TEMPORAL_WATERMARK]

        assert journal.compare(
            AnchorKind.TEMPORAL_WATERMARK, "wm-1"
        ) == "anchor_missing"

    def test_an_anchor_that_reads_as_absent_is_anchor_missing(self):
        journal, anchor = self._bound()
        self._confirmed(journal, anchor, 3, "d" * 64)
        journal.bind_reader(
            AnchorKind.TEMPORAL_WATERMARK, lambda anchor_id: None
        )

        assert journal.compare(
            AnchorKind.TEMPORAL_WATERMARK, "wm-1"
        ) == "anchor_missing"

    def test_an_unreadable_anchor_is_anchor_missing(self):
        journal, anchor = self._bound()
        self._confirmed(journal, anchor, 3, "d" * 64)
        journal.bind_reader(
            AnchorKind.TEMPORAL_WATERMARK,
            lambda anchor_id: (_ for _ in ()).throw(RuntimeError("boom")),
        )

        assert journal.compare(
            AnchorKind.TEMPORAL_WATERMARK, "wm-1"
        ) == "anchor_missing"

    def test_an_unknown_kind_is_anchor_missing(self):
        journal, _anchor = self._bound()

        assert journal.compare("not-a-kind", "wm-1") == "anchor_missing"

    def test_a_blank_anchor_id_is_anchor_missing(self):
        journal, _anchor = self._bound()

        assert journal.compare(
            AnchorKind.TEMPORAL_WATERMARK, "   "
        ) == "anchor_missing"

    def test_compare_never_returns_a_permission(self):
        """One-directional by construction: a reason to refuse, or nothing.

        A layer that could return "allowed" would be a second authorization
        path, and the invariant's ALLOW-path census exists to notice one.
        """

        journal, anchor = self._bound()
        self._confirmed(journal, anchor, 3, "d" * 64)

        outcomes = {
            journal.compare(AnchorKind.TEMPORAL_WATERMARK, "wm-1"),
            journal.compare(AnchorKind.ISSUER_REGISTRY, "registry"),
            journal.compare("not-a-kind", "wm-1"),
            journal.compare(AnchorKind.TEMPORAL_WATERMARK, ""),
        }

        for outcome in outcomes:
            assert outcome is None or (
                isinstance(outcome, str)
                and outcome.startswith("anchor_")
            )

    def test_a_receipt_replayed_from_another_anchor_does_not_confirm_this_one(
        self,
    ):
        """Confirming anchor A's checkpoint says nothing about anchor B, so
        B is still ``anchor_unconfirmed`` rather than inheriting A's
        standing."""

        journal, anchor = self._bound()
        anchor.place(3, "d" * 64)
        first = journal.publish(AnchorKind.TEMPORAL_WATERMARK, "wm-1")
        journal.confirm(first)

        assert journal.compare(
            AnchorKind.TEMPORAL_WATERMARK, "wm-2"
        ) == "anchor_unconfirmed"

    def test_publish_refuses_a_witness_that_answers_about_another_value(self):
        """A witness that answers out of order, or answers about something
        it was not asked, is refused rather than believed."""

        class Confused(AnchorWitness):
            name = "confused"

            def sign(self, checkpoint):
                return make_witness().sign(
                    replace(checkpoint, digest="z" * 64)
                )

        journal = AnchorJournal(
            witness=Confused(),
            witness_keys={WITNESS_KEY_ID: WITNESS_PUBLIC},
        )
        anchor = FakeAnchor().place(3, "d" * 64)
        journal.bind_reader(AnchorKind.TEMPORAL_WATERMARK, anchor.read)

        with pytest.raises(AnchorMismatchError):
            journal.publish(AnchorKind.TEMPORAL_WATERMARK, "wm-1")

        assert journal.records() == ()

    def test_publish_refuses_a_witness_that_answers_about_another_anchor(self):
        class Elsewhere(AnchorWitness):
            name = "elsewhere"

            def sign(self, checkpoint):
                return make_witness().sign(
                    replace(checkpoint, anchor_id="wm-other")
                )

        journal = AnchorJournal(
            witness=Elsewhere(),
            witness_keys={WITNESS_KEY_ID: WITNESS_PUBLIC},
        )
        anchor = FakeAnchor().place(3, "d" * 64)
        journal.bind_reader(AnchorKind.TEMPORAL_WATERMARK, anchor.read)

        with pytest.raises(AnchorSignatureError):
            journal.publish(AnchorKind.TEMPORAL_WATERMARK, "wm-1")

    def test_publish_refuses_a_witness_that_returns_a_non_checkpoint(self):
        class Garbage(AnchorWitness):
            name = "garbage"

            def sign(self, checkpoint):
                return {"not": "a checkpoint"}

        journal = AnchorJournal(
            witness=Garbage(),
            witness_keys={WITNESS_KEY_ID: WITNESS_PUBLIC},
        )
        anchor = FakeAnchor().place(3, "d" * 64)
        journal.bind_reader(AnchorKind.TEMPORAL_WATERMARK, anchor.read)

        with pytest.raises(AnchorSignatureError):
            journal.publish(AnchorKind.TEMPORAL_WATERMARK, "wm-1")

    def test_a_remote_witness_transport_failure_is_unavailable(self):
        def transport(_payload):
            raise OSError("connection refused")

        journal = AnchorJournal(
            witness=RemoteWitness(transport),
            witness_keys={WITNESS_KEY_ID: WITNESS_PUBLIC},
        )
        anchor = FakeAnchor().place(3, "d" * 64)
        journal.bind_reader(AnchorKind.TEMPORAL_WATERMARK, anchor.read)

        with pytest.raises(AnchorWitnessUnavailableError):
            journal.publish(AnchorKind.TEMPORAL_WATERMARK, "wm-1")

        assert any(
            finding.kind == "witness_unavailable"
            for finding in journal.findings()
        )

    def test_a_local_file_witness_records_the_checkpoint(self, tmp_path):
        path = tmp_path / "witness.log"
        journal = AnchorJournal(
            witness=LocalFileWitness(
                path,
                key_id=WITNESS_KEY_ID,
                private_key=WITNESS_PRIVATE,
            ),
            witness_keys={WITNESS_KEY_ID: WITNESS_PUBLIC},
        )
        anchor = FakeAnchor().place(3, "d" * 64)
        journal.bind_reader(AnchorKind.TEMPORAL_WATERMARK, anchor.read)

        checkpoint = journal.publish(AnchorKind.TEMPORAL_WATERMARK, "wm-1")

        written = json.loads(
            Path(path).read_text(encoding="utf-8").strip()
        )
        assert written["checkpoint_id"] == checkpoint.checkpoint_id
        assert AnchorCheckpoint.from_dict(written) == checkpoint


# ======================================================================
# The progression gate
# ======================================================================


class TestTheProgressionGate:
    def test_the_gate_refuses_before_confirm_and_agrees_after(self):
        sdk = make_sdk(require_external_anchor=True)
        capability = make_capability(sdk)

        issued = sdk.authorize_execution(capability, ACTION, dict(REQUEST))
        assert issued.allowed, issued.reason

        # A fresh chain has no confirmed checkpoint, so the first
        # progression is refused -- and the refusal names the missing
        # checkpoint rather than the chain.
        refused = sdk.reserve_execution(
            issued.lease,
            capability,
            ACTION,
            dict(REQUEST),
            execution_id="gate-1",
        )
        assert refused.allowed is False
        assert refused.reason == "anchor_unconfirmed"

        anchor_the_lineage(sdk, issued.lease.lease_id)

        reserved = sdk.reserve_execution(
            issued.lease,
            capability,
            ACTION,
            dict(REQUEST),
            execution_id="gate-1",
        )
        sdk.close()

        assert reserved.allowed, reserved.reason

    def test_the_gate_agrees_after_the_head_moves_past_the_confirmed_one(self):
        """The legitimate case the prefix reader exists for: confirm at the
        AUTHORIZED head, progress, and the next gate finds the chain one
        stage further on -- still carrying the confirmed commitment."""

        sdk = make_sdk(require_external_anchor=True)
        capability = make_capability(sdk)

        issued = sdk.authorize_execution(capability, ACTION, dict(REQUEST))
        anchor_the_lineage(sdk, issued.lease.lease_id)

        reserved = sdk.reserve_execution(
            issued.lease,
            capability,
            ACTION,
            dict(REQUEST),
            execution_id="gate-2",
        )
        assert reserved.allowed, reserved.reason

        started = sdk.start_execution(
            reserved.lease, capability, ACTION, dict(REQUEST)
        )
        sdk.close()

        assert started.allowed, started.reason

    def test_the_gate_refuses_when_the_anchor_moves(self):
        sdk = make_sdk(require_external_anchor=True)
        capability = make_capability(sdk)

        issued = sdk.authorize_execution(capability, ACTION, dict(REQUEST))
        anchor_id = lineage_id_for(sdk, issued.lease.lease_id)
        anchor_the_lineage(sdk, issued.lease.lease_id)

        # Rewrite the head the anchor reads to a different commitment at the
        # same position -- the consistent-rewrite attack, seen from the gate.
        sdk.anchors.bind_reader(
            AnchorKind.LINEAGE_HEAD,
            lambda lineage_id: (0, "0" * 64),
        )

        refused = sdk.reserve_execution(
            issued.lease,
            capability,
            ACTION,
            dict(REQUEST),
            execution_id="gate-3",
        )
        sdk.close()

        assert refused.allowed is False
        assert refused.reason == "anchor_mismatch"
        assert anchor_id

    def test_an_unreachable_witness_refuses_progression(self):
        sdk = make_sdk(
            require_external_anchor=True,
            anchor_witness=NullWitness(),
        )
        capability = make_capability(sdk)
        issued = sdk.authorize_execution(capability, ACTION, dict(REQUEST))
        anchor_id = lineage_id_for(sdk, issued.lease.lease_id)

        with pytest.raises(AnchorWitnessUnavailableError):
            sdk.anchor_publish(AnchorKind.LINEAGE_HEAD, anchor_id)

        refused = sdk.reserve_execution(
            issued.lease,
            capability,
            ACTION,
            dict(REQUEST),
            execution_id="gate-4",
        )
        sdk.close()

        assert refused.allowed is False
        assert refused.reason == "anchor_unconfirmed"

    def test_require_external_anchor_is_read_only(self):
        sdk = make_sdk(require_external_anchor=True)
        sdk.close()

        with pytest.raises(AttributeError):
            sdk.require_external_anchor = False

    def test_the_allow_path_is_unaffected_by_anchor_state(self):
        """The load-bearing negative, from the outside: an SDK whose witness
        is unreachable and whose gate is on still reaches the same
        *authorization* verdict, because anchoring is never on the ALLOW
        path. Only progression is refused."""

        plain = make_sdk()
        gated = make_sdk(
            require_external_anchor=True,
            anchor_witness=NullWitness(),
        )

        plain_cap = make_capability(plain)
        gated_cap = make_capability(gated)

        plain_result = plain.authorize(plain_cap, ACTION, dict(REQUEST))
        gated_result = gated.authorize(gated_cap, ACTION, dict(REQUEST))

        assert plain_result.allowed is True
        assert gated_result.allowed is True
        assert gated_result.reason == plain_result.reason

        # The difference appears only at the progression boundary.
        gated_issued = gated.authorize_execution(
            gated_cap, ACTION, dict(REQUEST)
        )
        gated_reserved = gated.reserve_execution(
            gated_issued.lease,
            gated_cap,
            ACTION,
            dict(REQUEST),
            execution_id="allow-path",
        )
        plain.close()
        gated.close()

        assert gated_issued.allowed is True
        assert gated_reserved.allowed is False

    def test_an_sdk_with_no_witness_reports_a_null_witness(self):
        sdk = make_sdk(anchor_witness=None)
        bound = sdk.anchors

        assert bound._witness.name == "null"
        sdk.close()

    def test_the_sdk_refuses_a_witness_that_is_not_a_witness(self):
        with pytest.raises(TypeError):
            FirewallSDK(anchor_witness=object())

    def test_the_sdk_refuses_a_non_boolean_gate_flag(self):
        with pytest.raises(TypeError):
            FirewallSDK(require_external_anchor="yes")

    def test_the_sdk_refuses_a_non_mapping_witness_key_set(self):
        with pytest.raises(TypeError):
            FirewallSDK(witness_keys=["witness-1"])


# ======================================================================
# Record integrity
# ======================================================================


class TestRecordIntegrity:
    def _published(self, **kwargs):
        sdk = make_sdk(**kwargs)
        capability = make_capability(sdk)
        issued, _started, _outcome = walk_completed(sdk, capability)
        anchor_the_lineage(sdk, issued.lease.lease_id)
        return sdk, issued

    def test_an_edited_checkpoint_is_a_violation(self):
        sdk, _issued = self._published()
        sdk.anchors._published.append(
            replace(sdk.anchor_records()[0], digest="0" * 64)
        )
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "does not re-derive" in finding for finding in result.findings
        )

    def test_an_unsigned_checkpoint_is_a_violation(self):
        sdk, _issued = self._published()
        base = sdk.anchor_records()[0]
        unsigned = AnchorCheckpoint(
            kind=base.kind,
            anchor_id=base.anchor_id,
            sequence=99,
            digest="7" * 64,
            issued_at=0.0,
        )
        unsigned = replace(
            unsigned, checkpoint_id=unsigned.rederived_id()
        )
        assert not unsigned.is_signed()
        assert unsigned.rederived_id() == unsigned.checkpoint_id

        sdk.anchors._published.append(unsigned)
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "carries no signature" in finding for finding in result.findings
        )

    def test_a_confirmed_checkpoint_not_in_the_published_set_is_a_violation(
        self,
    ):
        sdk, _issued = self._published()
        ghost = make_witness().sign(
            AnchorCheckpoint(
                kind=AnchorKind.LINEAGE_HEAD,
                anchor_id=sdk.anchor_records()[0].anchor_id,
                sequence=42,
                digest="9" * 64,
                issued_at=0.0,
            )
        )
        sdk.anchors._confirmed.append(ghost)
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "not in the published set" in finding
            for finding in result.findings
        )

    def test_a_duplicate_sequence_is_a_violation(self):
        sdk, _issued = self._published()
        first = sdk.anchor_records()[0]
        twin = make_witness().sign(
            AnchorCheckpoint(
                kind=first.kind,
                anchor_id=first.anchor_id,
                sequence=first.sequence,
                digest="8" * 64,
                issued_at=0.0,
            )
        )
        sdk.anchors._published.append(twin)
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "two checkpoints claim one sequence" in finding
            for finding in result.findings
        )

    def test_an_unexplained_finding_kind_is_a_violation(self):
        sdk, _issued = self._published()
        sdk.anchors.record_finding(
            "not-a-kind",
            anchor_kind=AnchorKind.LINEAGE_HEAD,
            anchor_id=sdk.anchor_records()[0].anchor_id,
            detail="invented",
        )
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "is not one this release can explain" in finding
            for finding in result.findings
        )

    def test_every_declared_finding_kind_is_explainable(self):
        sdk, _issued = self._published()

        for kind in sorted(ANCHOR_FINDING_KINDS):
            sdk.anchors.record_finding(
                kind,
                anchor_kind=AnchorKind.LINEAGE_HEAD,
                anchor_id=sdk.anchor_records()[0].anchor_id,
                detail="declared",
            )

        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.HOLDS, result.reason

    def test_a_completed_execution_whose_anchor_disagrees_is_a_violation(
        self,
    ):
        sdk = make_sdk(require_external_anchor=True)
        capability = make_capability(sdk)
        issued, _started, _outcome = walk_completed_gated(sdk, capability)

        # The gate was on and a checkpoint was confirmed at every stage; now
        # move the anchor. A COMPLETED execution whose anchor no longer
        # agrees is a completion that rested on a root of trust the firewall
        # cannot prove is the one the witness confirmed.
        anchor_id = lineage_id_for(sdk, issued.lease.lease_id)
        confirmed = sdk.anchors.last_confirmed(
            AnchorKind.LINEAGE_HEAD, anchor_id
        )
        assert confirmed is not None

        sdk.anchors.bind_reader(
            AnchorKind.LINEAGE_HEAD,
            lambda lineage_id: (int(confirmed.sequence), "0" * 64),
        )
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any(
            "COMPLETED but its anchor refuses" in finding
            for finding in result.findings
        )

    def test_a_gated_estate_holds_the_invariant(self):
        """Calibration for the test above: the same estate, with the anchor
        left alone, is sound."""

        sdk = make_sdk(require_external_anchor=True)
        capability = make_capability(sdk)
        walk_completed_gated(sdk, capability)
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.HOLDS, result.reason
        assert result.details["checkpoints"] > 1


# ======================================================================
# Source census teeth
# ======================================================================


class TestSourceCensusTeeth:
    def test_the_census_is_closed(self):
        findings, notes = _anchor_source_findings()

        assert findings == ()
        assert notes

    def test_an_undeclared_journal_caller_is_a_violation(self, monkeypatch):
        monkeypatch.setattr(
            runtime_module, "ANCHOR_MUTATOR_OWNERS", frozenset()
        )
        findings, _ = _anchor_source_findings()

        assert any(
            "drives the anchor journal" in finding for finding in findings
        )

    def test_a_declared_caller_that_drives_nothing_is_a_violation(
        self, monkeypatch
    ):
        monkeypatch.setattr(
            runtime_module,
            "ANCHOR_MUTATOR_OWNERS",
            frozenset(
                runtime_module.ANCHOR_MUTATOR_OWNERS
                | {("firewall/sdk.py", "FirewallSDK.anchor_records")}
            ),
        )
        findings, _ = _anchor_source_findings()

        assert any(
            "drives no journal mutator" in finding for finding in findings
        )

    def test_a_declared_caller_absent_from_the_package_is_a_violation(
        self, monkeypatch
    ):
        monkeypatch.setattr(
            runtime_module,
            "ANCHOR_MUTATOR_OWNERS",
            frozenset(
                runtime_module.ANCHOR_MUTATOR_OWNERS
                | {("firewall/nowhere.py", "FirewallSDK.anchor_publish")}
            ),
        )
        findings, _ = _anchor_source_findings()

        assert any(
            "absent from the package" in finding for finding in findings
        )

    def test_an_allow_path_reference_is_a_violation(self, monkeypatch):
        monkeypatch.setattr(
            runtime_module,
            "ANCHOR_ALLOW_PATH_OWNERS",
            frozenset(
                runtime_module.ANCHOR_ALLOW_PATH_OWNERS
                | {"FirewallSDK._anchor_gate"}
            ),
        )
        findings, _ = _anchor_source_findings()

        assert any("ALLOW path" in finding for finding in findings)

    def test_the_gate_prefix_rule_does_not_match_anchor_helpers(
        self, monkeypatch
    ):
        """``_anchor_gate`` is a gate and ``anchor_publish`` is not; the
        prefix rule must not turn a helper into a decision."""

        findings, _ = _anchor_source_findings()

        assert not any(
            "_anchor_gate" in finding and "ALLOW path" in finding
            for finding in findings
        )

    def test_the_anchor_module_constructs_no_verdict(self):
        import firewall.anchor as module

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
            assert name not in (
                "AuthorizationResult",
                "_result",
                "authorize",
            ), name

    def test_the_declared_reference_names_are_all_absent_from_the_allow_path(
        self,
    ):
        """The census reports how many names it checked; if a name were
        silently dropped from the set the count would move, and this is the
        test that would notice."""

        _findings, notes = _anchor_source_findings()

        assert f"{len(runtime_module.ANCHOR_REFERENCE_NAMES)} anchor " in (
            notes[0]
        )


# ======================================================================
# Persistence
# ======================================================================


class TestPersistence:
    def test_a_checkpoint_at_position_zero_round_trips(self):
        """Regression: a lineage's genesis link sits at sequence 0, so the
        first checkpoint a deployment publishes is a checkpoint at 0.

        The parser originally refused anything below 1. That made such a
        checkpoint *storable* -- the store does not validate -- but
        *unreadable*, so a durable anchor store failed to load at
        construction and the process refused to start after a perfectly
        ordinary first run. Found by the store round-trip test below; this
        one pins the narrow cause.
        """

        checkpoint = AnchorCheckpoint(
            kind=AnchorKind.LINEAGE_HEAD,
            anchor_id="lineage-1",
            sequence=0,
            digest="d" * 64,
            issued_at=1_700_000_000.0,
        )

        assert AnchorCheckpoint.from_dict(checkpoint.to_dict()) == checkpoint

    def test_the_sdk_round_trips_an_anchor_at_the_genesis_position(
        self, tmp_path
    ):
        """The same defect, end to end: publish and confirm at the head of a
        fresh chain, restart against the same store, and the confirmed set
        must still load."""

        path = tmp_path / "anchor.sqlite3"

        sdk = make_sdk(anchor_store_path=path)
        capability = make_capability(sdk)
        issued = sdk.authorize_execution(capability, ACTION, dict(REQUEST))
        checkpoint = anchor_the_lineage(sdk, issued.lease.lease_id)
        assert checkpoint.sequence == 0
        sdk.close()

        reopened = make_sdk(anchor_store_path=path)
        receipts = reopened.anchor_receipts()
        reopened.close()

        assert len(receipts) == 1
        assert receipts[0] == checkpoint

    def _journal(self, path):
        return AnchorJournal(
            backend=SQLiteAnchorStore(path),
            witness=make_witness(),
            witness_keys={WITNESS_KEY_ID: WITNESS_PUBLIC},
        )

    def _bind(self, journal, anchor):
        journal.bind_reader(AnchorKind.TEMPORAL_WATERMARK, anchor.read)
        journal.bind_prefix_reader(
            AnchorKind.TEMPORAL_WATERMARK, anchor.prefix
        )

    def test_the_store_round_trips(self, tmp_path):
        path = tmp_path / "anchor.sqlite3"
        anchor = FakeAnchor().place(3, "d" * 64)

        journal = self._journal(path)
        self._bind(journal, anchor)
        checkpoint = journal.publish(
            AnchorKind.TEMPORAL_WATERMARK, "wm-1"
        )
        journal.confirm(checkpoint)
        journal._backend.close()

        reopened = self._journal(path)
        self._bind(reopened, anchor)
        records = reopened.records()
        receipts = reopened.receipts()

        assert len(records) == 1
        assert len(receipts) == 1
        assert receipts[0] == checkpoint
        assert reopened.compare(
            AnchorKind.TEMPORAL_WATERMARK, "wm-1"
        ) is None
        reopened._backend.close()

    def test_a_restart_does_not_lose_the_confirmed_sequence(self, tmp_path):
        """A confirmation is durable, so a restart cannot make an old
        checkpoint current again."""

        path = tmp_path / "anchor.sqlite3"
        anchor = FakeAnchor().place(3, "d" * 64)

        journal = self._journal(path)
        self._bind(journal, anchor)
        first = journal.publish(AnchorKind.TEMPORAL_WATERMARK, "wm-1")
        journal.confirm(first)
        journal._backend.close()

        reopened = self._journal(path)
        self._bind(reopened, anchor)

        with pytest.raises(AnchorRewindError):
            reopened.confirm(first)

        reopened._backend.close()

    def test_a_rejected_insert_is_reported_as_a_rewind(self, tmp_path):
        path = tmp_path / "anchor.sqlite3"
        anchor = FakeAnchor().place(3, "d" * 64)

        journal = self._journal(path)
        self._bind(journal, anchor)
        first = journal.publish(AnchorKind.TEMPORAL_WATERMARK, "wm-1")
        journal.confirm(first)

        anchor.place(2, "c" * 64)

        with pytest.raises(AnchorRewindError):
            journal.publish(AnchorKind.TEMPORAL_WATERMARK, "wm-1")

        journal._backend.close()

    def test_an_unreadable_store_refuses_construction(self, tmp_path):
        path = tmp_path / "anchor.sqlite3"
        path.write_bytes(b"not a database at all")

        with pytest.raises(AnchorJournalError) as caught:
            self._journal(path)

        assert "failed to initialize" in str(caught.value)

    def test_the_sdk_owns_its_anchor_store(self, tmp_path):
        sdk = make_sdk(
            anchor_store_path=tmp_path / "anchor.sqlite3",
            require_external_anchor=True,
        )
        capability = make_capability(sdk)
        issued = sdk.authorize_execution(capability, ACTION, dict(REQUEST))
        anchor_the_lineage(sdk, issued.lease.lease_id)

        assert sdk.anchor_store is not None
        assert sdk.anchor_store.size() == 1
        sdk.close()

    def test_the_anchor_store_never_shares_a_file_with_another_store(
        self, tmp_path
    ):
        """Two connections to one SQLite file is not a naming preference.

        SQLite keeps a write-ahead log beside each database, and only the
        *last* connection to close folds that log back into the main file.
        A second live connection leaves the log in place -- and a leftover
        log is exactly what makes a rolled-back store file *replay* rather
        than be detected, because the log still holds the write the
        rollback was meant to undo. So the derivation in
        ``FirewallSDK.__init__`` appends a suffix: the anchors get a
        sibling file, never another store's own path.

        The derivation originally reused whichever durable path the caller
        named, which put the anchor schema *inside* the state-commit
        journal's file. The v3.0 crash test is what found it: the journal
        was rolled back, the stale log replayed the revoke, and
        ``SECURITY_STATE_COHERENCE`` reported HOLDS on a torn state.
        """

        import sqlite3

        journal = tmp_path / "journal.db"
        lineage = tmp_path / "lineage.db"

        sdk = make_sdk(
            state_commit_store_path=str(journal),
            lineage_store_path=str(lineage),
        )
        anchored = sdk.anchor_store
        sdk.close()

        assert anchored is not None
        assert Path(anchored.path) != journal
        assert Path(anchored.path) != lineage

        # And the file the caller named is still only what the caller
        # named: the anchor schema was not written into it.
        connection = sqlite3.connect(str(journal))
        try:
            names = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
        finally:
            connection.close()

        assert "anchor_checkpoints" not in names

    def test_an_sdk_that_did_not_ask_for_anchoring_leaves_no_anchor_file(
        self, tmp_path
    ):
        """A subsystem that is switched off must not create state.

        The estate makes this choice for its witness -- deliberately
        in-process, so that building an estate leaves no scratch on disk
        -- and the anchor store follows the same rule. The path named here
        *is* one the derivation would otherwise accept, so this also pins
        the boundary: naming a durable store is not the same as asking for
        anchoring. With no file named for the anchors, no witness supplied
        and anchoring not required, the journal is in-memory and nothing is
        written for it to be read back from.
        """

        journal = tmp_path / "journal.db"

        sdk = FirewallSDK(state_commit_store_path=str(journal))

        assert sdk.anchor_store is None
        sdk.close()

        assert list(tmp_path.glob("*.anchors")) == []
        assert not Path(f"{journal}.anchors").exists()

    def test_a_rolled_back_store_file_is_not_replayed_from_a_stale_log(
        self, tmp_path
    ):
        """The consequence, pinned rather than the spelling.

        This is the v3.0 crash, reached through a v3.4 SDK: a revocation
        store write lands, the state-commit journal is rolled back to the
        snapshot taken before it, and the booted live state is therefore
        ahead of its chain head. The invariant must report VIOLATED.

        It reported HOLDS for as long as the anchor store held a second
        connection on the journal's file, because the log it left behind
        replayed the very commitment the rollback removed. Asserting the
        invariant's verdict -- not the file names -- means this still bites
        if the path derivation is ever pointed back at another store.
        """

        import shutil
        import sqlite3

        from firewall.invariants import check_security_state_coherence

        rev_db = tmp_path / "rev.db"
        jnl_db = tmp_path / "journal.db"
        before = tmp_path / "journal-before.db"

        sdk = make_sdk(
            revocation_store_path=str(rev_db),
            state_commit_store_path=str(jnl_db),
        )
        # One key, named, and passed explicitly to both issues. ``make_sdk``
        # mints a fresh key per call, so a capability signed by *its* active
        # key would be refused as invalid_signature on the reboot long
        # before the state-coherence gate was reached -- and this test is
        # about the gate, not about key resolution.
        key = sdk.generate_key("v34-rolled-back").private_key
        good = sdk.issue(
            agent="agent-good",
            capability=ACTION,
            constraints={"amount_max": 100},
            private_key=key,
        )
        victim = sdk.issue(
            agent="agent-v",
            capability=ACTION,
            constraints={"amount_max": 100},
            private_key=key,
        )
        sdk.close()

        # Consistent snapshot of the committed journal before the write.
        src = sqlite3.connect(str(jnl_db))
        dst = sqlite3.connect(str(before))
        src.backup(dst)
        dst.close()
        src.close()

        sdk = make_sdk(
            revocation_store_path=str(rev_db),
            state_commit_store_path=str(jnl_db),
        )
        sdk.revoke(victim)
        sdk.close()

        # The crash: the store write survived, the commitment did not.
        shutil.copyfile(before, jnl_db)

        reboot = make_sdk(
            revocation_store_path=str(rev_db),
            state_commit_store_path=str(jnl_db),
        )
        result = check_security_state_coherence(reboot)
        denied_good = reboot.authorize(good, ACTION, dict(REQUEST))
        reboot.close()

        assert result.status is InvariantStatus.VIOLATED
        assert denied_good.allowed is False
        assert denied_good.reason.startswith("state_incoherent")

    def test_an_in_memory_journal_is_fully_checkable(self):
        """No backend, no excuse: the journal holds its own account of what
        it published and confirmed, so an in-memory deployment is auditable
        rather than reported as unreadable."""

        journal = AnchorJournal(
            witness=make_witness(),
            witness_keys={WITNESS_KEY_ID: WITNESS_PUBLIC},
        )
        anchor = FakeAnchor().place(3, "d" * 64)
        journal.bind_reader(AnchorKind.TEMPORAL_WATERMARK, anchor.read)
        checkpoint = journal.publish(
            AnchorKind.TEMPORAL_WATERMARK, "wm-1"
        )
        journal.confirm(checkpoint)

        assert journal.records() == (checkpoint,)
        assert journal.receipts() == (checkpoint,)
        assert journal.last_confirmed(
            AnchorKind.TEMPORAL_WATERMARK, "wm-1"
        ) == checkpoint
        assert journal.size() == 1
