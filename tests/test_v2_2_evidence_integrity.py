"""v2.2 evidence integrity verification.

These tests exist because the module they cover previously reported
guarantees it did not check. Three failure shapes are pinned here:

*A report that says "verified" when nothing was verified.*
``_verify_checkpoints`` and ``_verify_signer_consistency`` returned
``True`` unconditionally, so ``checkpoint_verified`` and
``signer_verified`` were decoration on every report ever produced.

*A truncation test that cannot fire.* The old check compared
``len(events)`` with ``events[-1].seq``. Both are assigned by
``EvidenceGraph.append`` from the same counter, and deleting the tail
shrinks both together, so no input could ever trip it.

*A tamper type that names a detection nobody performs.* Six enum members
were never emitted by any code path. They are gone, and
``test_every_tamper_type_is_emitted`` keeps them gone: a member that no
scenario produces fails the suite.

Nothing here authorizes anything. ``FirewallSDK.authorize`` remains the
only authorization boundary, and a tampered graph neither grants nor
removes authority -- see the last section.
"""

from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from firewall.evidence_graph import (
    GENESIS_HASH,
    EvidenceGraph,
    IdentityEvidenceSigner,
    KeyEvidenceSigner,
    PublicKeyVerifier,
)
from firewall.evidence_integrity import (
    INTEGRITY_STATUSES,
    EvidenceIntegrityVerifier,
    IntegrityReport,
    TamperType,
    summarize_integrity,
)
from firewall.ident import IdentityRegistry
from firewall.security_memory import EvidenceCheckpoint, SecurityMemory


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def _graph(signer=None) -> EvidenceGraph:
    return EvidenceGraph(signer=signer if signer is not None else KeyEvidenceSigner())


def _seed(graph: EvidenceGraph, count: int = 3, start: float = 1_000.0):
    """Append ``count`` signed events at one-second intervals."""

    return [
        graph.append(
            "observed",
            "agent-1",
            "tool_call",
            {"index": index},
            now=start + index,
        )
        for index in range(count)
    ]


def _anchor(
    signer,
    *,
    chain_id: str,
    sequence_number: int,
    event_hash: str,
    previous: str = GENESIS_HASH,
    timestamp: float = 2_000.0,
) -> EvidenceCheckpoint:
    """Build a signed anchor the way ``SecurityMemory`` builds one.

    ``test_security_memory_checkpoints_verify_as_anchors`` checks this
    helper against the real producer, so a divergence between the two
    fails the suite rather than quietly making these tests agree only
    with themselves.
    """

    unsigned = EvidenceCheckpoint(
        checkpoint_id=f"cp-{chain_id}-{sequence_number}",
        chain_id=chain_id,
        sequence_number=sequence_number,
        event_hash=event_hash,
        previous_checkpoint_hash=previous,
        timestamp=timestamp,
        signer_fingerprint=signer.fingerprint(),
        signature="",
    )
    signature, _ = signer.sign(unsigned.canonical_bytes())
    return replace(unsigned, signature=signature)


def _anchor_chain(
    signer,
    events,
    *,
    chain_id: str = "chain-a",
    positions=None,
) -> list[EvidenceCheckpoint]:
    """Hash-linked anchors for the given 1-based event positions."""

    positions = list(positions) if positions else [len(events)]
    anchors: list[EvidenceCheckpoint] = []
    previous = GENESIS_HASH
    for position in positions:
        anchor = _anchor(
            signer,
            chain_id=chain_id,
            sequence_number=position,
            event_hash=events[position - 1].event_id,
            previous=previous,
        )
        anchors.append(anchor)
        previous = hashlib.sha256(anchor.canonical_bytes()).hexdigest()
    return anchors


def _anchored(graph: EvidenceGraph, signer, events, **kwargs):
    """A verifier whose anchor covers every event in ``graph``."""

    return EvidenceIntegrityVerifier(
        graph,
        checkpoints=_anchor_chain(signer, events),
        anchor_signer=signer,
        anchor_chain_id="chain-a",
        **kwargs,
    )


def _types(report) -> set[TamperType]:
    return {evidence.tamper_type for evidence in report.tamper_evidence}


# ----------------------------------------------------------------------
# Scenarios: one per TamperType, so no member can be advertised without
# an input that produces it.
# ----------------------------------------------------------------------


def _scenario_hash_mismatch() -> EvidenceIntegrityVerifier:
    graph = _graph()
    events = _seed(graph)
    graph._events[1] = replace(events[1], payload={"index": 99})
    return EvidenceIntegrityVerifier(graph)


def _scenario_broken_link() -> EvidenceIntegrityVerifier:
    graph = _graph()
    _seed(graph, 4)
    del graph._events[1]
    return EvidenceIntegrityVerifier(graph)


def _scenario_ordering_violation() -> EvidenceIntegrityVerifier:
    graph = _graph()
    _seed(graph, 4)
    graph._events[1], graph._events[2] = graph._events[2], graph._events[1]
    return EvidenceIntegrityVerifier(graph)


def _scenario_missing_causal_parent() -> EvidenceIntegrityVerifier:
    graph = _graph()
    events = _seed(graph)
    graph._events[2] = replace(events[2], causal_parents=("ab" * 32,))
    return EvidenceIntegrityVerifier(graph)


def _scenario_bad_signature() -> EvidenceIntegrityVerifier:
    graph = _graph()
    events = _seed(graph)
    # ``signature`` is outside ``signed_block()``, so swapping it leaves
    # the id and the hash link intact: a pure forgery signal.
    graph._events[2] = replace(events[2], signature=events[1].signature)
    return EvidenceIntegrityVerifier(graph)


def _scenario_unsigned_event() -> EvidenceIntegrityVerifier:
    graph = EvidenceGraph(signer=None)
    _seed(graph, 2)
    return EvidenceIntegrityVerifier(graph)


def _scenario_duplicate_event() -> EvidenceIntegrityVerifier:
    graph = _graph()
    events = _seed(graph)
    graph._events.append(events[1])
    return EvidenceIntegrityVerifier(graph)


def _scenario_truncated_chain() -> EvidenceIntegrityVerifier:
    signer = KeyEvidenceSigner()
    graph = _graph(signer)
    events = _seed(graph, 4)
    anchors = _anchor_chain(signer, events)
    del graph._events[3:]
    return EvidenceIntegrityVerifier(
        graph,
        checkpoints=anchors,
        anchor_signer=signer,
        anchor_chain_id="chain-a",
    )


def _scenario_anchor_mismatch() -> EvidenceIntegrityVerifier:
    signer = KeyEvidenceSigner()
    original = _graph(signer)
    anchors = _anchor_chain(signer, _seed(original, 3))

    substituted = _graph(signer)
    _seed(substituted, 3, start=5_000.0)
    return EvidenceIntegrityVerifier(
        substituted,
        checkpoints=anchors,
        anchor_signer=signer,
        anchor_chain_id="chain-a",
    )


def _scenario_replaced_checkpoint() -> EvidenceIntegrityVerifier:
    signer = KeyEvidenceSigner()
    graph = _graph(signer)
    events = _seed(graph)
    forged = _anchor(
        KeyEvidenceSigner(),
        chain_id="chain-a",
        sequence_number=3,
        event_hash=events[2].event_id,
    )
    return EvidenceIntegrityVerifier(
        graph,
        checkpoints=[forged],
        anchor_signer=signer,
        anchor_chain_id="chain-a",
    )


def _revoked_signer_graph():
    """A graph whose events postdate the revocation of their signing key."""

    registry = IdentityRegistry(clock=lambda: 1_500.0)
    registry.create("agent-1")
    graph = EvidenceGraph(signer=IdentityEvidenceSigner(registry, "agent-1"))
    _seed(graph, 2, start=2_000.0)
    registry.revoke("agent-1")
    return graph, registry


def _scenario_signer_revoked() -> EvidenceIntegrityVerifier:
    graph, registry = _revoked_signer_graph()
    return EvidenceIntegrityVerifier(graph, identity_registry=registry)


def _scenario_time_travel() -> EvidenceIntegrityVerifier:
    graph = _graph()
    graph.append("observed", "agent-1", "first", {}, now=5_000.0)
    graph.append("observed", "agent-1", "second", {}, now=1_000.0)
    return EvidenceIntegrityVerifier(graph)


_SCENARIOS = {
    TamperType.HASH_MISMATCH: _scenario_hash_mismatch,
    TamperType.BROKEN_LINK: _scenario_broken_link,
    TamperType.ORDERING_VIOLATION: _scenario_ordering_violation,
    TamperType.MISSING_CAUSAL_PARENT: _scenario_missing_causal_parent,
    TamperType.BAD_SIGNATURE: _scenario_bad_signature,
    TamperType.UNSIGNED_EVENT: _scenario_unsigned_event,
    TamperType.DUPLICATE_EVENT: _scenario_duplicate_event,
    TamperType.TRUNCATED_CHAIN: _scenario_truncated_chain,
    TamperType.ANCHOR_MISMATCH: _scenario_anchor_mismatch,
    TamperType.REPLACED_CHECKPOINT: _scenario_replaced_checkpoint,
    TamperType.SIGNER_REVOKED: _scenario_signer_revoked,
    TamperType.TIME_TRAVEL: _scenario_time_travel,
}


@pytest.mark.parametrize(
    "tamper_type",
    sorted(_SCENARIOS, key=lambda member: member.value),
)
def test_scenario_emits_its_tamper_type(tamper_type):
    report = _SCENARIOS[tamper_type]().verify()
    assert tamper_type in _types(report)
    assert report.status == "failed"


def test_every_tamper_type_is_emitted():
    """No member may advertise a detection nothing performs.

    Five members were removed for failing this: ``modified_payload``,
    ``modified_causal_parent``, ``modified_signer``, ``replayed_event``
    and ``signer_rotated`` named detections this verifier cannot make.
    """

    assert set(_SCENARIOS) == set(TamperType)


# ----------------------------------------------------------------------
# Status honesty: "verified" must mean every applicable check ran
# ----------------------------------------------------------------------


def test_clean_graph_without_an_anchor_is_incomplete_not_verified():
    """The old report said ``verified`` with ``checkpoint_verified=True``.

    Nothing had been checked: there was no anchor, and the method that
    claimed to check them returned ``True`` without looking at anything.
    """

    graph = _graph()
    _seed(graph)
    report = EvidenceIntegrityVerifier(graph).verify()

    assert report.tamper_evidence == ()
    assert report.status == "incomplete"
    assert report.checkpoint_verified is None
    assert report.total_events == 3
    assert report.verified_events == 3
    assert any("no signed anchor" in gap for gap in report.gaps)


def test_clean_anchored_graph_is_verified():
    signer = KeyEvidenceSigner()
    graph = _graph(signer)
    events = _seed(graph)

    report = _anchored(graph, signer, events).verify()

    assert report.status == "verified"
    assert report.checkpoint_verified is True
    assert report.gaps == ()
    assert report.anchors_examined == 1


def test_events_after_the_last_anchor_are_reported_as_a_gap():
    signer = KeyEvidenceSigner()
    graph = _graph(signer)
    events = _seed(graph, 4)

    report = EvidenceIntegrityVerifier(
        graph,
        checkpoints=_anchor_chain(signer, events, positions=[2]),
        anchor_signer=signer,
        anchor_chain_id="chain-a",
    ).verify()

    assert report.tamper_evidence == ()
    assert report.checkpoint_verified is True
    assert report.status == "incomplete"
    assert any("covered by no anchor" in gap for gap in report.gaps)


def test_empty_graph_is_incomplete():
    report = EvidenceIntegrityVerifier(_graph()).verify()

    assert report.status == "incomplete"
    assert report.total_events == 0
    assert report.checkpoint_verified is None
    assert report.signer_verified is None
    assert report.gaps


def test_unsigned_graph_is_unverifiable_never_verified():
    signer = KeyEvidenceSigner()
    graph = EvidenceGraph(signer=None)
    events = _seed(graph, 3)

    report = _anchored(
        graph, signer, events, require_signed_events=False
    ).verify()

    assert report.tamper_evidence == ()
    assert report.status == "unverifiable"
    assert report.verified_events == 0
    assert report.checkpoint_verified is True


def test_status_is_failed_even_when_no_finding_is_critical():
    """A proven violation is not "unverifiable".

    The old status rule was ``"failed" if any critical else
    "unverifiable"``, so a proven reordering (severity ``high``) or a
    proven backwards timestamp (``medium``) was reported as a check that
    had not run.
    """

    report = _scenario_time_travel().verify()

    assert [e.severity for e in report.tamper_evidence] == ["medium"]
    assert report.status == "failed"


# ----------------------------------------------------------------------
# Truncation needs an anchor
# ----------------------------------------------------------------------


def test_truncation_is_a_gap_without_an_anchor_and_a_finding_with_one():
    """The regression the old tautological check could never catch.

    A chain with its tail removed is internally consistent: hashes,
    links, sequence numbers and signatures all still agree. Comparing
    ``len(events)`` with ``events[-1].seq`` compares two numbers that
    were both shortened. Only an outside signed statement notices.
    """

    signer = KeyEvidenceSigner()
    graph = _graph(signer)
    events = _seed(graph, 4)
    anchors = _anchor_chain(signer, events)
    del graph._events[3:]

    blind = EvidenceIntegrityVerifier(graph).verify()
    assert blind.tamper_evidence == ()
    assert blind.status == "incomplete"
    assert any("cannot be ruled out" in gap for gap in blind.gaps)

    anchored = EvidenceIntegrityVerifier(
        graph,
        checkpoints=anchors,
        anchor_signer=signer,
        anchor_chain_id="chain-a",
    ).verify()
    truncation = [
        e for e in anchored.tamper_evidence
        if e.tamper_type is TamperType.TRUNCATED_CHAIN
    ]
    assert len(truncation) == 1
    assert truncation[0].expected == "4"
    assert truncation[0].actual == "3"
    assert anchored.checkpoint_verified is False
    assert anchored.status == "failed"


def _anchor_reasons(report, tamper_type) -> list[str]:
    return [
        str(e.details.get("reason", ""))
        for e in report.tamper_evidence
        if e.tamper_type is tamper_type
    ]


def test_anchor_sequence_number_must_agree_with_the_event_seq():
    """Anchor position and ``event.seq`` are checked, not assumed equal.

    ``security_memory`` numbers anchors by position within one chain,
    while a graph numbers events across every chain it holds. The two
    coincide for a single-chain graph and diverge otherwise, so the
    verifier compares them instead of trusting the coincidence.
    """

    signer = KeyEvidenceSigner()
    graph = _graph(signer)
    graph._seq = 5  # this graph's numbering does not start at 1
    events = _seed(graph, 2)

    report = EvidenceIntegrityVerifier(
        graph,
        checkpoints=[_anchor(
            signer,
            chain_id="chain-a",
            sequence_number=1,
            event_hash=events[0].event_id,
        )],
        anchor_signer=signer,
        anchor_chain_id="chain-a",
    ).verify()

    reasons = _anchor_reasons(report, TamperType.ANCHOR_MISMATCH)
    assert any("anchored sequence number" in reason for reason in reasons)


def test_removing_a_middle_anchor_breaks_the_anchor_chain():
    signer = KeyEvidenceSigner()
    graph = _graph(signer)
    events = _seed(graph, 3)
    anchors = _anchor_chain(signer, events, positions=[1, 2, 3])

    report = EvidenceIntegrityVerifier(
        graph,
        checkpoints=[anchors[0], anchors[2]],
        anchor_signer=signer,
        anchor_chain_id="chain-a",
    ).verify()

    reasons = _anchor_reasons(report, TamperType.REPLACED_CHECKPOINT)
    assert any("removed or replaced" in reason for reason in reasons)
    assert report.checkpoint_verified is False
    # The first anchor still pins its event, and the third makes no claim
    # about the events at all: an untrusted anchor is not consulted.
    assert TamperType.ANCHOR_MISMATCH not in _types(report)


def test_anchor_for_another_chain_is_rejected():
    signer = KeyEvidenceSigner()
    graph = _graph(signer)
    events = _seed(graph)

    report = EvidenceIntegrityVerifier(
        graph,
        checkpoints=[_anchor(
            signer,
            chain_id="chain-b",
            sequence_number=3,
            event_hash=events[2].event_id,
        )],
        anchor_signer=signer,
        anchor_chain_id="chain-a",
    ).verify()

    reasons = _anchor_reasons(report, TamperType.REPLACED_CHECKPOINT)
    assert any("different chain" in reason for reason in reasons)


def test_repeated_anchor_sequence_is_rejected():
    signer = KeyEvidenceSigner()
    graph = _graph(signer)
    events = _seed(graph)

    report = EvidenceIntegrityVerifier(
        graph,
        checkpoints=_anchor_chain(signer, events, positions=[3, 3]),
        anchor_signer=signer,
        anchor_chain_id="chain-a",
    ).verify()

    reasons = _anchor_reasons(report, TamperType.REPLACED_CHECKPOINT)
    assert any("strictly increasing" in reason for reason in reasons)


def test_anchor_sequence_number_below_one_identifies_no_event():
    signer = KeyEvidenceSigner()
    graph = _graph(signer)
    events = _seed(graph)

    report = EvidenceIntegrityVerifier(
        graph,
        checkpoints=[_anchor(
            signer,
            chain_id="chain-a",
            sequence_number=0,
            event_hash=events[0].event_id,
        )],
        anchor_signer=signer,
        anchor_chain_id="chain-a",
    ).verify()

    reasons = _anchor_reasons(report, TamperType.REPLACED_CHECKPOINT)
    assert any("no event position" in reason for reason in reasons)


def test_anchors_without_a_signer_are_assertions_not_anchors():
    signer = KeyEvidenceSigner()
    graph = _graph(signer)
    events = _seed(graph)

    report = EvidenceIntegrityVerifier(
        graph, checkpoints=_anchor_chain(signer, events)
    ).verify()

    assert report.tamper_evidence == ()
    assert report.checkpoint_verified is False
    assert report.status == "incomplete"
    assert any("without a" in gap for gap in report.gaps)


# ----------------------------------------------------------------------
# Signer lifecycle
# ----------------------------------------------------------------------


def _identity_graph(clock):
    registry = IdentityRegistry(clock=clock)
    registry.create("agent-1")
    graph = EvidenceGraph(signer=IdentityEvidenceSigner(registry, "agent-1"))
    events = _seed(graph, 2, start=2_000.0)
    return registry, graph, events


def test_active_signer_resolves_and_the_report_can_be_verified():
    registry, graph, events = _identity_graph(lambda: 1_000.0)
    anchor_signer = KeyEvidenceSigner()

    report = EvidenceIntegrityVerifier(
        graph,
        identity_registry=registry,
        checkpoints=_anchor_chain(anchor_signer, events),
        anchor_signer=anchor_signer,
        anchor_chain_id="chain-a",
    ).verify()

    assert report.signer_verified is True
    assert report.gaps == ()
    assert report.status == "verified"


def test_revocation_does_not_retroactively_brand_history_as_tampered():
    """Revoking a key does not turn the evidence it signed into forgery.

    The old code reported ``SIGNER_REVOKED`` -- ``critical`` -- for every
    event signed by a non-active identity, so one routine revocation
    rewrote an entire authentic history as tampered. Withdrawal of trust
    in a key is not proof that anything was altered.
    """

    registry, graph, _ = _identity_graph(lambda: 9_000.0)
    registry.revoke("agent-1")  # revoked_at 9000, events at 2000-2001

    report = EvidenceIntegrityVerifier(
        graph, identity_registry=registry
    ).verify()

    assert report.tamper_evidence == ()
    assert report.status == "unverifiable"
    assert report.signer_verified is False
    assert any("no longer trusted" in gap for gap in report.gaps)
    assert any("not proof of forgery" in gap for gap in report.gaps)


def test_signing_after_revocation_is_tampering():
    report = _scenario_signer_revoked().verify()

    revoked = [
        e for e in report.tamper_evidence
        if e.tamper_type is TamperType.SIGNER_REVOKED
    ]
    assert len(revoked) == 2
    assert revoked[0].details["agent_id"] == "agent-1"
    assert "after the key was revoked" in revoked[0].details["reason"]
    assert report.signer_verified is False
    assert report.status == "failed"


def test_retired_signer_is_a_gap_not_a_finding():
    registry, graph, _ = _identity_graph(lambda: 1_000.0)
    registry.retire("agent-1")

    report = EvidenceIntegrityVerifier(
        graph, identity_registry=registry
    ).verify()

    assert report.tamper_evidence == ()
    assert report.signer_verified is False
    assert report.status == "unverifiable"
    assert any("is retired" in gap for gap in report.gaps)


def test_rotated_out_key_is_a_gap_that_names_the_ambiguity():
    """``rotate`` keeps no superseded fingerprint, so the old key is lost.

    After a rotation, every historical event is signed by a fingerprint
    the registry no longer holds. That is indistinguishable from a key
    that was never issued, which is why there is no ``signer_rotated``
    finding: naming it would claim a distinction the data does not
    support.
    """

    registry, graph, _ = _identity_graph(lambda: 1_000.0)
    registry.rotate("agent-1")

    report = EvidenceIntegrityVerifier(
        graph, identity_registry=registry
    ).verify()

    assert report.tamper_evidence == ()
    assert report.signer_verified is False
    assert report.status == "unverifiable"
    assert any("rotated out" in gap for gap in report.gaps)
    assert any("indistinguishable" in gap for gap in report.gaps)


def test_signer_verified_is_none_when_there_is_nothing_to_resolve():
    graph = EvidenceGraph(signer=None)
    _seed(graph, 1)

    report = EvidenceIntegrityVerifier(
        graph, identity_registry=IdentityRegistry()
    ).verify()

    assert report.signer_verified is None


def test_signer_verified_is_none_without_a_registry():
    """The old method returned ``True`` here, checking nothing."""

    signer = KeyEvidenceSigner()
    graph = _graph(signer)
    events = _seed(graph)

    report = _anchored(graph, signer, events).verify()

    assert report.signer_verified is None
    assert report.status == "verified"


# ----------------------------------------------------------------------
# Signatures: proof versus gap
# ----------------------------------------------------------------------


def test_signature_from_a_key_the_verifier_does_not_hold_is_a_gap():
    """Ed25519 cannot tell "not my key" from "forged"."""

    graph = _graph()
    _seed(graph)
    graph._signer = KeyEvidenceSigner()  # a verifier holding the wrong key

    report = EvidenceIntegrityVerifier(graph).verify()

    assert report.tamper_evidence == ()
    assert report.status == "unverifiable"
    assert report.verified_events == 0
    assert any(
        "cannot be distinguished from a forged one" in gap
        for gap in report.gaps
    )


def test_public_key_verifier_verifies_without_signing_authority():
    """Independent verification needs the public key, not the private one."""

    signer = KeyEvidenceSigner()
    graph = _graph(signer)
    events = _seed(graph)
    graph._signer = PublicKeyVerifier.from_signer(signer)

    report = _anchored(graph, signer, events).verify()

    assert report.status == "verified"
    assert report.verified_events == 3


def test_signed_events_with_no_signer_configured_are_a_gap():
    signer = KeyEvidenceSigner()
    graph = _graph(signer)
    _seed(graph)
    graph._signer = None

    report = EvidenceIntegrityVerifier(graph).verify()

    assert report.tamper_evidence == ()
    assert report.status == "unverifiable"
    assert any("no signer is configured" in gap for gap in report.gaps)


# ----------------------------------------------------------------------
# Report surface
# ----------------------------------------------------------------------


def test_integrity_statuses_are_exactly_the_four_reachable_values():
    """Every declared status is produced by some real report."""

    signer = KeyEvidenceSigner()
    produced = set()

    graph = _graph(signer)
    events = _seed(graph)
    produced.add(_anchored(graph, signer, events).verify().status)  # verified
    produced.add(EvidenceIntegrityVerifier(graph).verify().status)  # incomplete

    unsigned = EvidenceGraph(signer=None)
    unsigned_events = _seed(unsigned, 1)
    produced.add(_anchored(
        unsigned, signer, unsigned_events, require_signed_events=False
    ).verify().status)  # unverifiable

    produced.add(_SCENARIOS[TamperType.HASH_MISMATCH]().verify().status)  # failed

    assert produced == set(INTEGRITY_STATUSES)


def test_unknown_status_is_rejected_by_the_report():
    with pytest.raises(ValueError, match="unknown integrity status"):
        IntegrityReport(status="fine", verified_events=0, total_events=0)


def test_to_dict_preserves_the_three_valued_flags():
    graph = _graph()
    _seed(graph)

    report = EvidenceIntegrityVerifier(graph).verify()
    payload = report.to_dict()

    assert payload["status"] == "incomplete"
    assert payload["checkpoint_verified"] is None
    assert payload["signer_verified"] is None
    assert payload["anchors_examined"] == 0
    assert payload["gaps"] == list(report.gaps)


def test_detect_specific_tamper_filters_without_hiding_gaps():
    verifier = _SCENARIOS[TamperType.HASH_MISMATCH]()

    hits = verifier.detect_specific_tamper(TamperType.HASH_MISMATCH)
    misses = verifier.detect_specific_tamper(TamperType.TRUNCATED_CHAIN)

    assert [e.tamper_type for e in hits] == [TamperType.HASH_MISMATCH]
    assert misses == []
    # An empty result for one type says nothing about the rest of the graph.
    assert verifier.verify().status == "failed"


def test_summarize_integrity_counts_findings_by_type():
    signer = KeyEvidenceSigner()
    graph = _graph(signer)
    events = _seed(graph)
    graph._events[1] = replace(events[1], payload={"i": 99})

    summary = summarize_integrity(graph)

    assert summary["status"] == "failed"
    assert summary["findings_by_type"]["hash_mismatch"] == 1
    assert summary["total_events"] == 3
    assert summary["gaps"]


def test_verification_does_not_mutate_the_graph():
    signer = KeyEvidenceSigner()
    graph = _graph(signer)
    events = _seed(graph)
    before = [e.to_dict() for e in graph.events()]

    verifier = _anchored(graph, signer, events)
    verifier.verify()
    verifier.verify()

    assert [e.to_dict() for e in graph.events()] == before


# ----------------------------------------------------------------------
# Interop with the real anchor producer
# ----------------------------------------------------------------------


def test_security_memory_checkpoints_verify_as_anchors():
    """The anchors these tests build must match the ones the codebase makes.

    ``SecurityMemory`` is the only producer of :class:`EvidenceCheckpoint`
    values. If ``_anchor`` and ``_create_checkpoint`` ever diverge --
    a renamed field, a different previous-hash rule -- the tests above
    would keep agreeing with themselves while the verifier rejected
    every real anchor. This test is what makes that impossible.
    """

    signer = KeyEvidenceSigner()
    memory = SecurityMemory(signer=signer, checkpoint_interval=1)

    memory.create_chain(
        "c1",
        initial_event={"kind": "observed", "event_type": "created", "payload": {"i": 0}},
        now=1_000.0,
    )
    memory.append_to_chain(
        "c1", "observed", "c1", "step", {"i": 1}, now=1_001.0
    )
    memory.append_to_chain(
        "c1", "observed", "c1", "step", {"i": 2}, now=1_002.0
    )

    anchors = memory._checkpoints["c1"]
    assert [cp.sequence_number for cp in anchors] == [2, 3]

    graph = memory._evidence_graph
    report = EvidenceIntegrityVerifier(
        graph,
        checkpoints=anchors,
        anchor_signer=signer,
        anchor_chain_id="c1",
    ).verify()

    assert report.status == "verified"
    assert report.tamper_evidence == ()
    assert report.gaps == ()
    assert report.checkpoint_verified is True
    assert report.anchors_examined == 2

    # Now delete the tail the real anchors cover.
    del graph._events[2:]

    truncated = EvidenceIntegrityVerifier(
        graph,
        checkpoints=anchors,
        anchor_signer=signer,
        anchor_chain_id="c1",
    ).verify()

    assert truncated.status == "failed"
    assert TamperType.TRUNCATED_CHAIN in _types(truncated)
    assert truncated.checkpoint_verified is False


# ----------------------------------------------------------------------
# Integrity findings are not an authorization authority
# ----------------------------------------------------------------------


def test_integrity_findings_are_not_an_authorization_authority():
    """A tampered evidence graph neither grants nor removes authority.

    ``FirewallSDK.authorize`` is the only authorization boundary. It does
    not consult this module, so a ``failed`` report cannot deny a request
    that policy allows, and -- the direction that would actually matter --
    a report forced to ``verified`` cannot allow one that policy denies.
    """

    from firewall.sdk import FirewallSDK

    sdk = FirewallSDK()
    sdk.generate_key("evidence-authority-key")
    token = sdk.issue(
        agent="agent-integrity",
        capability="payments.send",
        constraints={"amount_max": 100},
    )

    allowed_before = sdk.authorize(
        token, action="payments.send", request={"amount": 50}
    )
    denied_before = sdk.authorize(
        token, action="payments.send", request={"amount": 5_000}
    )
    assert allowed_before.allowed is True
    assert denied_before.allowed is False

    signer = KeyEvidenceSigner()
    graph = _graph(signer)
    events = _seed(graph)
    graph._events[1] = replace(events[1], payload={"tampered": True})

    report = EvidenceIntegrityVerifier(graph).verify()
    assert report.status == "failed"

    # A fresh SDK: the denial above trips refusal state, and a positive
    # control has to be able to succeed for this assertion to mean
    # anything.
    fresh = FirewallSDK()
    fresh.generate_key("evidence-authority-key")
    fresh_token = fresh.issue(
        agent="agent-integrity",
        capability="payments.send",
        constraints={"amount_max": 100},
    )

    allowed_after = fresh.authorize(
        fresh_token, action="payments.send", request={"amount": 50}
    )
    denied_after = fresh.authorize(
        fresh_token, action="payments.send", request={"amount": 5_000}
    )

    assert allowed_after.allowed is True
    assert denied_after.allowed is False
