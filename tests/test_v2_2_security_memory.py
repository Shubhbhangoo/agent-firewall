"""Tests for the v2.2 Security Memory verification core.

The subject here is not "does an evidence chain verify" -- the previous
implementation answered yes, for exactly one chain, and would have gone
on answering yes through a truncation. The subject is what the
verification *establishes*, so each test names the way the old code could
report success while checking nothing.

Two failure shapes get the most weight:

* **A chain that verifies vacuously.** Truncation was undetectable
  because nothing bound ``chain.length`` or ``head_hash`` to
  ``chain.events``, and the checkpoint that would have caught it compared
  a chain position against a graph position.
* **Foreign evidence treated as local.** Import merged the exporter's
  events into the local graph, which broke the local graph's own hash
  chain and moved every local chain to ``failed``.

Nothing in this module is an authorization authority. The last section
pins that.
"""

from __future__ import annotations

import copy
import dataclasses
import json

import pytest

from firewall.evidence_graph import (
    EvidenceError,
    KeyEvidenceSigner,
    PublicKeyVerifier,
)
from firewall.sdk import FirewallSDK
from firewall.security_memory import (
    EvidenceCheckpoint,
    CrossArtifactReference,
    EvidenceChain,
    SecurityMemory,
)


class _UnsignedSigner:
    """A signer that produces no signature.

    Not a mock of a broken key: it is how an operator who configured no
    evidence key would actually behave, and the point is that the memory
    must then report ``unverifiable`` rather than ``verified``.
    """

    def sign(self, data: bytes) -> tuple[str, str]:
        return "", ""

    def verify(self, data: bytes, signature_b64: str) -> bool:
        return False

    def fingerprint(self) -> str:
        return ""


def _memory(**kwargs) -> SecurityMemory:
    return SecurityMemory(**kwargs)


def _seeded(memory: SecurityMemory, chain_id: str, steps: int = 3) -> None:
    """Give a chain a first event and ``steps`` more."""

    memory.create_chain(
        chain_id,
        initial_event={
            "subject": chain_id,
            "event_type": "chain_opened",
            "payload": {"chain": chain_id},
        },
    )
    for index in range(steps):
        memory.append_to_chain(
            chain_id,
            "observed",
            chain_id,
            "step",
            {"index": index},
        )


# ----------------------------------------------------------------------
# A chain is verifiable because it is intact, not because it is alone
# ----------------------------------------------------------------------


def test_two_chains_on_one_memory_both_verify():
    """The headline regression.

    ``verify_chain`` walked ``event.prev_hash`` as though the chain owned
    the whole graph's hash chain. That holds only for the first chain
    created in a memory, so the second was permanently unverifiable --
    reported as ``broken link at seq N``, i.e. as tampering, for a memory
    that was perfectly intact. An evidence store that calls its own
    correct state a tamper event trains its operators to ignore it.
    """

    memory = _memory()
    _seeded(memory, "chain-one", steps=4)
    _seeded(memory, "chain-two", steps=2)

    first = memory.verify_chain("chain-one")
    second = memory.verify_chain("chain-two")

    assert first["verified"] is True, first["problems"]
    assert second["verified"] is True, second["problems"]

    # And the first is not disturbed by the second existing.
    assert memory.verify_chain("chain-one")["verified"] is True


def test_verification_reports_every_problem_not_the_first():
    """An operator needs the extent of the damage, not one symptom.

    The old code returned on the first mismatch, so one edited event and
    a wholesale rewrite produced the same single-line answer.
    """

    memory = _memory()
    _seeded(memory, "chain", steps=3)
    chain = memory.get_chain("chain")

    # Two independent problems: a truncated event list, and a length
    # field that no longer matches it.
    memory._chains["chain"] = dataclasses.replace(
        chain, events=chain.events[:2]
    )

    result = memory.verify_chain("chain")

    assert result["verified"] is False
    assert len(result["problems"]) >= 2
    assert result["reason"] == result["problems"][0]


def test_unknown_chain_is_not_verified():
    """A chain that does not exist has not been shown to be intact."""

    result = _memory().verify_chain("nope")

    assert result["verified"] is False
    assert result["problems"]


def test_unsigned_evidence_is_unverifiable_not_verified():
    """No key means no attribution, and unverifiable is not a pass.

    ``EvidenceGraph`` already distinguishes ``unverifiable`` from
    ``failed``; the chain-level answer must not collapse either into
    ``verified``.
    """

    memory = _memory(signer=_UnsignedSigner())
    _seeded(memory, "chain", steps=2)

    result = memory.verify_chain("chain")

    assert result["verified"] is False
    assert result["graph_status"] == "unverifiable"


# ----------------------------------------------------------------------
# Truncation
# ----------------------------------------------------------------------


def test_a_truncated_chain_does_not_verify():
    """Dropping the tail must be detectable even when the metadata agrees.

    This is the attack the old code could not see. Nothing bound
    ``length`` or ``head_hash`` to ``events``, so an attacker who removed
    the last two events and rewrote both fields produced a chain that
    walked cleanly from its first event to its new head.
    """

    memory = _memory(checkpoint_interval=2)
    _seeded(memory, "chain", steps=5)
    chain = memory.get_chain("chain")

    assert memory.verify_chain("chain")["verified"] is True
    assert len(chain.events) == 6

    memory._chains["chain"] = dataclasses.replace(
        chain,
        events=chain.events[:4],
        length=4,
        head_hash=chain.events[3].event_id,
    )

    result = memory.verify_chain("chain")

    assert result["verified"] is False
    assert any("truncated" in problem for problem in result["problems"])


def test_length_and_head_hash_must_agree_with_the_events():
    """The cheap consistency checks, pinned separately.

    A chain with no checkpoints yet has no cryptographic anchor, so these
    two are all that stand between it and silent tail removal. They are
    weaker than a checkpoint -- an attacker editing the in-memory object
    can fix them, which is why the checkpoint test above exists -- but
    they catch the same edit in a persisted file.
    """

    memory = _memory()
    _seeded(memory, "chain", steps=3)
    chain = memory.get_chain("chain")

    memory._chains["chain"] = dataclasses.replace(chain, length=99)
    problems = memory.verify_chain("chain")["problems"]
    assert any("disagrees with" in problem for problem in problems)

    memory._chains["chain"] = dataclasses.replace(
        chain, head_hash="0" * 64
    )
    problems = memory.verify_chain("chain")["problems"]
    assert any("head hash" in problem for problem in problems)


def test_removing_a_checkpoint_from_the_middle_is_detected():
    """Otherwise the truncation detector could itself be truncated.

    The checkpoints form their own hash chain through
    ``previous_checkpoint_hash``. Without checking it, an attacker who
    removed events would simply also remove the checkpoint that covered
    them.
    """

    memory = _memory(checkpoint_interval=2)
    _seeded(memory, "chain", steps=5)

    assert len(memory._checkpoints["chain"]) == 3
    assert memory.verify_chain("chain")["verified"] is True

    del memory._checkpoints["chain"][1]

    result = memory.verify_chain("chain")

    assert result["verified"] is False
    assert any(
        "does not follow the previous checkpoint" in problem
        for problem in result["problems"]
    )


def test_a_forged_checkpoint_does_not_verify():
    """A checkpoint is only worth its signature.

    Re-pointing a checkpoint at a different event is the direct way to
    make a truncated chain look anchored, so the signature check has to
    cover ``event_hash`` -- which is what ``canonical_bytes`` is for.
    """

    memory = _memory(checkpoint_interval=2)
    _seeded(memory, "chain", steps=3)

    original = memory._checkpoints["chain"][0]
    memory._checkpoints["chain"][0] = dataclasses.replace(
        original, event_hash="f" * 64
    )

    result = memory.verify_chain("chain")

    assert result["verified"] is False
    assert any(
        "invalid signature" in problem for problem in result["problems"]
    )


# ----------------------------------------------------------------------
# Edited events
# ----------------------------------------------------------------------


def test_an_edited_event_does_not_verify():
    """The event digest covers the payload, so an edit is detectable."""

    memory = _memory()
    _seeded(memory, "chain", steps=3)
    chain = memory.get_chain("chain")

    edited = dataclasses.replace(
        chain.events[1], payload={"index": 10_000}
    )
    memory._chains["chain"] = dataclasses.replace(
        chain, events=(chain.events[0], edited) + chain.events[2:]
    )

    result = memory.verify_chain("chain")

    assert result["verified"] is False
    assert any(
        "hash mismatch" in problem for problem in result["problems"]
    )


def test_a_chain_event_missing_from_the_graph_does_not_verify():
    """The chain and the graph must hold the same evidence.

    A chain naming an event the graph does not have is a chain citing
    evidence nobody kept.
    """

    memory = _memory()
    _seeded(memory, "chain", steps=2)
    chain = memory.get_chain("chain")

    del memory._evidence_graph._by_id[chain.events[1].event_id]

    result = memory.verify_chain("chain")

    assert result["verified"] is False
    assert any(
        "not in the evidence graph" in problem
        for problem in result["problems"]
    )


def test_a_replayed_event_inside_a_chain_does_not_verify():
    """The same event twice is one observation recorded twice.

    Counting it twice would inflate any measure taken over the chain, and
    the duplicate is free to an attacker: it needs no signing key.
    """

    memory = _memory()
    _seeded(memory, "chain", steps=2)
    chain = memory.get_chain("chain")

    memory._chains["chain"] = dataclasses.replace(
        chain,
        events=chain.events + (chain.events[1],),
        length=chain.length + 1,
        head_hash=chain.events[1].event_id,
    )

    result = memory.verify_chain("chain")

    assert result["verified"] is False
    assert any("appears twice" in problem for problem in result["problems"])


# ----------------------------------------------------------------------
# ``verified`` is a checked result, not a claim
# ----------------------------------------------------------------------


def test_the_verified_flag_is_set_by_an_actual_check():
    """It used to be assigned ``True`` by construction.

    ``create_chain`` set it on the first event and ``append_to_chain`` set
    it at every checkpoint interval, neither having verified anything. The
    flag was therefore a statement about the chain's integrity issued by
    the code that would have been wrong about it.
    """

    memory = _memory(checkpoint_interval=2)
    _seeded(memory, "chain", steps=3)

    assert memory.get_chain("chain").verified is True

    unsigned = _memory(signer=_UnsignedSigner(), checkpoint_interval=2)
    _seeded(unsigned, "chain", steps=3)

    # Same code path, no verifiable signatures: the flag must follow the
    # check rather than the construction.
    assert unsigned.get_chain("chain").verified is False


def test_an_empty_chain_is_not_marked_verified():
    """A chain with no events has had nothing verified about it."""

    memory = _memory()
    chain = memory.create_chain("empty")

    assert chain.verified is False


# ----------------------------------------------------------------------
# Import: foreign evidence is not local evidence
# ----------------------------------------------------------------------


def _exported_chain(steps: int = 3) -> tuple[dict, PublicKeyVerifier]:
    """An export plus the verify-only key a third party would hold."""

    exporter = _memory(checkpoint_interval=2)
    _seeded(exporter, "incident", steps=steps)

    # Round-tripped through JSON because that is how an export travels,
    # and a checkpoint signature that only survives in-process is not a
    # checkpoint signature.
    export = json.loads(json.dumps(exporter.export_chain("incident")))

    return export, PublicKeyVerifier.from_signer(exporter._signer)


def test_importing_a_chain_leaves_local_evidence_verifiable():
    """The regression that mattered most.

    The old importer appended the exporter's events straight into the
    local ``EvidenceGraph``. Those events carry the *exporter's*
    ``prev_hash`` and ``seq`` and are signed by the exporter's key, and
    ``EvidenceGraph.verify`` is whole-graph -- so a single import moved
    every local chain from ``verified`` to ``failed``. An attacker who
    could get one chain imported destroyed the verifiability of all
    existing evidence, and the status said "tampered" rather than
    "foreign".
    """

    export, verifier = _exported_chain()

    memory = _memory()
    _seeded(memory, "local", steps=3)
    assert memory.verify_chain("local")["verified"] is True

    memory.import_chain(export, signer=verifier)

    assert memory.verify_chain("local")["verified"] is True
    assert memory._evidence_graph.verify()["status"] == "verified"


def test_an_imported_chain_is_verifiable_against_the_exporters_key():
    """Quarantine is not a bin. The evidence stays checkable."""

    export, verifier = _exported_chain()

    memory = _memory()
    memory.import_chain(export, signer=verifier)

    result = memory.verify_imported_chain("incident", verifier)

    assert result["verified"] is True, result["problems"]
    assert result["imported"] is True


def test_an_imported_chain_is_not_a_local_chain():
    """A caller that cannot tell them apart will conflate them."""

    export, verifier = _exported_chain()

    memory = _memory()
    memory.import_chain(export, signer=verifier)

    assert memory.get_chain("incident") is None
    assert memory.list_chains() == []
    assert memory.list_imported_chains() == ["incident"]
    assert memory.get_imported_chain("incident") is not None


def test_verifying_an_unknown_imported_chain_is_not_a_pass():
    export, verifier = _exported_chain()
    memory = _memory()
    memory.import_chain(export, signer=verifier)

    result = memory.verify_imported_chain("other", verifier)

    assert result["verified"] is False
    assert result["problems"]


# ----------------------------------------------------------------------
# Import: what it refuses
# ----------------------------------------------------------------------


def test_importing_the_same_export_twice_is_refused():
    """Replay. The old importer appended the events again each time.

    Every event ended up in ``_events`` twice while ``_by_id`` kept one
    copy, so the graph's length and its lookups disagreed permanently --
    and the chain's own history claimed each step happened twice.
    """

    export, verifier = _exported_chain()
    memory = _memory()
    memory.import_chain(export, signer=verifier)

    with pytest.raises(ValueError, match="already imported"):
        memory.import_chain(export, signer=verifier)


def test_importing_over_a_local_chain_id_is_refused():
    """Otherwise an import is evidence substitution.

    A foreign chain arriving under the name of a local one would replace
    the local record of an incident with the attacker's account of it.
    """

    export, verifier = _exported_chain()

    memory = _memory()
    _seeded(memory, "incident", steps=2)
    local_head = memory.get_chain("incident").head_hash

    with pytest.raises(ValueError, match="local chain"):
        memory.import_chain(export, signer=verifier)

    assert memory.get_chain("incident").head_hash == local_head


def test_importing_an_event_the_graph_already_holds_is_refused():
    """A doctored copy of a local event must not overwrite the original.

    The old importer assigned into ``_by_id`` unconditionally, so an
    export containing an event id the graph already held replaced the
    graph's copy with the imported one.
    """

    memory = _memory(checkpoint_interval=2)
    _seeded(memory, "local", steps=3)

    # Export from this memory, then offer it back under a new chain id:
    # every event id already exists locally.
    export = json.loads(json.dumps(memory.export_chain("local")))
    export["chain"]["chain_id"] = "smuggled"
    for checkpoint in export["checkpoints"]:
        checkpoint["chain_id"] = "smuggled"

    verifier = PublicKeyVerifier.from_signer(memory._signer)

    with pytest.raises(ValueError, match="collides with local evidence"):
        memory.import_chain(export, signer=verifier)

    assert memory.verify_chain("local")["verified"] is True


def test_importing_a_tampered_chain_is_refused():
    export, verifier = _exported_chain()
    tampered = copy.deepcopy(export)
    tampered["chain"]["events"][1]["payload"] = {"index": 10_000}

    memory = _memory()

    with pytest.raises(ValueError, match="hash mismatch"):
        memory.import_chain(tampered, signer=verifier)

    assert memory.list_imported_chains() == []


def test_importing_under_the_wrong_key_is_refused():
    """Signed by somebody is not signed by the exporter."""

    export, _ = _exported_chain()
    memory = _memory()
    stranger = PublicKeyVerifier.from_signer(KeyEvidenceSigner())

    with pytest.raises(ValueError, match="signature"):
        memory.import_chain(export, signer=stranger)

    assert memory.list_imported_chains() == []


def test_importing_with_verification_requires_a_key():
    """``verify=True`` with no signer verified nothing at all.

    Refusing is the fail-closed reading: the alternative -- accept it and
    record that it could not be checked -- produces a store whose
    contents are read as evidence regardless of the flag beside them.
    """

    export, _ = _exported_chain()

    with pytest.raises(ValueError, match="needs the exporter's signer"):
        _memory().import_chain(export)


def test_an_explicitly_unverified_import_still_checks_structure():
    """``verify=False`` waives attribution, not arithmetic.

    An operator with no copy of the exporter's key can still hold the
    artifact, but a chain whose own length contradicts its events is
    broken regardless of who signed it.
    """

    export, _ = _exported_chain()
    memory = _memory()

    held = memory.import_chain(export, verify=False)
    assert held.verified is False
    assert memory.list_imported_chains() == ["incident"]

    broken = copy.deepcopy(export)
    broken["chain"]["chain_id"] = "other"
    broken["chain"]["length"] = 99
    broken["checkpoints"] = []

    with pytest.raises(ValueError, match="disagrees with"):
        _memory().import_chain(broken, verify=False)


def test_the_exports_own_verification_claim_is_not_trusted():
    """A verdict travelling inside the artifact it describes is worthless.

    The old importer read ``verified`` off the exported chain and stored
    it, so an attacker's export asserted its own integrity.
    """

    export, verifier = _exported_chain()
    export["chain"]["verified"] = True
    export["verification"] = {"verified": True, "problems": []}
    export["chain"]["events"][1]["payload"] = {"index": 10_000}

    with pytest.raises(ValueError):
        _memory().import_chain(export, signer=verifier)


def test_a_malformed_export_is_refused_as_data_not_as_a_crash():
    """Untrusted JSON must produce a diagnosis, not a ``TypeError``.

    ``EvidenceCheckpoint(**cp_data)`` was the old construction: an unexpected or
    missing key surfaced as a dataclass ``TypeError`` from inside the
    import, which a caller wrapping imports in ``except ValueError``
    would not catch at all.
    """

    export, verifier = _exported_chain()
    memory = _memory()

    with pytest.raises(ValueError, match="must be an object"):
        memory.import_chain([], signer=verifier)

    with pytest.raises(ValueError, match="no chain"):
        memory.import_chain({}, signer=verifier)

    missing_id = copy.deepcopy(export)
    del missing_id["chain"]["chain_id"]
    with pytest.raises(ValueError, match="no chain_id"):
        memory.import_chain(missing_id, signer=verifier)

    bad_checkpoint = copy.deepcopy(export)
    del bad_checkpoint["checkpoints"][0]["signature"]
    with pytest.raises(ValueError, match="missing field 'signature'"):
        memory.import_chain(bad_checkpoint, signer=verifier)

    junk_checkpoint = copy.deepcopy(export)
    junk_checkpoint["checkpoints"][0]["sequence_number"] = "not a number"
    with pytest.raises(ValueError, match="malformed field"):
        memory.import_chain(junk_checkpoint, signer=verifier)


# ----------------------------------------------------------------------
# Untrusted-JSON reconstruction
# ----------------------------------------------------------------------


def test_checkpoint_survives_a_json_round_trip_byte_identically():
    """Coercion, not just validation.

    ``sequence_number`` must come back an ``int`` and ``timestamp`` a
    ``float``: ``canonical_bytes`` serialises them, so a checkpoint whose
    ``sequence_number`` returned as the string ``"2"`` would hash
    differently and its own signature would stop verifying.
    """

    signer = KeyEvidenceSigner()
    memory = SecurityMemory(signer=signer, checkpoint_interval=2)
    _seeded(memory, "chain", steps=3)

    original = memory._checkpoints["chain"][0]
    restored = EvidenceCheckpoint.from_dict(
        json.loads(json.dumps(original.to_dict()))
    )

    assert restored == original
    assert restored.canonical_bytes() == original.canonical_bytes()
    assert signer.verify(restored.canonical_bytes(), restored.signature)


def test_checkpoint_from_dict_rejects_non_objects():
    for junk in ([], "cp", 7, None):
        with pytest.raises(ValueError, match="must be an object"):
            EvidenceCheckpoint.from_dict(junk)


def test_cross_reference_never_restores_a_verified_claim():
    """Nothing sets it to ``True``, so honouring it only imports an
    attacker's assertion."""

    reference = CrossArtifactReference.from_dict(
        {
            "source_chain_id": "a",
            "source_event_id": "e1",
            "target_chain_id": "b",
            "target_event_id": "e2",
            "relationship": "caused_by",
            "created_at": 1.0,
            "verified": True,
        }
    )

    assert reference.verified is False


def test_cross_reference_from_dict_reports_missing_fields():
    with pytest.raises(ValueError, match="missing field 'relationship'"):
        CrossArtifactReference.from_dict(
            {
                "source_chain_id": "a",
                "source_event_id": "e1",
                "target_chain_id": "b",
                "target_event_id": "e2",
                "created_at": 1.0,
            }
        )


# ----------------------------------------------------------------------
# Persistence: the state file is untrusted input
# ----------------------------------------------------------------------


def test_state_survives_a_reload_with_the_same_key(tmp_path):
    """The positive control for the loader.

    Without it, every test below is satisfiable by a loader that refuses
    everything.
    """

    signer = KeyEvidenceSigner()
    path = tmp_path / "memory.json"

    export, exporter_key = _exported_chain()

    memory = SecurityMemory(
        signer=signer, state_path=path, checkpoint_interval=2
    )
    _seeded(memory, "local", steps=3)
    memory.import_chain(export, signer=exporter_key)
    memory.close()

    reloaded = SecurityMemory(
        signer=signer, state_path=path, checkpoint_interval=2
    )

    assert reloaded.verify_chain("local")["verified"] is True
    assert reloaded.list_imported_chains() == ["incident"]
    assert (
        reloaded.verify_imported_chain("incident", exporter_key)[
            "verified"
        ]
        is True
    )


def test_a_reload_without_the_key_does_not_report_verified(tmp_path):
    """Fail closed: no key means no attribution.

    Ed25519 cannot distinguish "signed by a key I do not hold" from
    "forged", so this reports a failure rather than a softer status. That
    is the safe direction, and it is why the signer is a constructor
    argument.
    """

    path = tmp_path / "memory.json"
    memory = SecurityMemory(
        signer=KeyEvidenceSigner(), state_path=path, checkpoint_interval=2
    )
    _seeded(memory, "local", steps=3)
    memory.close()

    stranger = SecurityMemory(state_path=path, checkpoint_interval=2)

    assert stranger.verify_chain("local")["verified"] is False


def test_the_persisted_verified_flag_is_not_restored(tmp_path):
    """The file must not be able to assert its own integrity.

    The loader used to read ``verified`` back off disk. Combined with the
    old truncation blindness, an attacker editing the file could hand back
    a shortened chain that announced itself as verified.
    """

    signer = KeyEvidenceSigner()
    path = tmp_path / "memory.json"

    memory = SecurityMemory(
        signer=signer, state_path=path, checkpoint_interval=2
    )
    _seeded(memory, "local", steps=3)
    memory.close()

    on_disk = json.loads(path.read_text(encoding="utf-8"))
    chain = on_disk["chains"][0]

    # Truncate the tail and rewrite every field that used to be believed.
    chain["events"] = chain["events"][:2]
    chain["length"] = 2
    chain["head_hash"] = chain["events"][-1]["event_id"]
    chain["verified"] = True
    path.write_text(json.dumps(on_disk), encoding="utf-8")

    reloaded = SecurityMemory(
        signer=signer, state_path=path, checkpoint_interval=2
    )

    assert reloaded.get_chain("local").verified is False

    result = reloaded.verify_chain("local")
    assert result["verified"] is False
    assert any("truncated" in problem for problem in result["problems"])


def test_a_duplicated_event_in_the_state_file_is_refused(tmp_path):
    """Loading it twice desynchronised the graph's list from its index."""

    signer = KeyEvidenceSigner()
    path = tmp_path / "memory.json"

    memory = SecurityMemory(signer=signer, state_path=path)
    _seeded(memory, "local", steps=2)
    memory.close()

    on_disk = json.loads(path.read_text(encoding="utf-8"))
    on_disk["events"].append(on_disk["events"][0])
    path.write_text(json.dumps(on_disk), encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate event"):
        SecurityMemory(signer=signer, state_path=path)


def test_a_non_object_state_file_is_refused(tmp_path):
    path = tmp_path / "memory.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")

    with pytest.raises(ValueError, match="must be an object"):
        SecurityMemory(state_path=path)


def test_an_unreadable_state_file_is_refused(tmp_path):
    path = tmp_path / "memory.json"
    path.write_text("{not json", encoding="utf-8")

    with pytest.raises(ValueError, match="cannot load"):
        SecurityMemory(state_path=path)


# ----------------------------------------------------------------------
# Independent verification needs no signing authority
# ----------------------------------------------------------------------


def test_public_key_verifier_verifies_without_the_private_key():
    """The point of an export is that a third party can check it.

    Before this, the only objects satisfying the signer protocol were a
    keypair holder and an identity-registry proxy, so verifying an export
    meant being handed signing authority.
    """

    signer = KeyEvidenceSigner()
    verifier = PublicKeyVerifier.from_signer(signer)

    signature, fingerprint = signer.sign(b"evidence")

    assert verifier.verify(b"evidence", signature) is True
    assert verifier.verify(b"other evidence", signature) is False
    assert verifier.fingerprint() == fingerprint


def test_public_key_verifier_refuses_to_sign():
    """A placeholder signature would be worse than an error.

    Returning something unverifiable would let evidence be appended to a
    graph that could never verify it again -- and the graph reports that
    as tampering.
    """

    verifier = PublicKeyVerifier.from_signer(KeyEvidenceSigner())

    with pytest.raises(EvidenceError, match="cannot sign"):
        verifier.sign(b"evidence")


def test_public_key_verifier_rejects_junk_signatures():
    verifier = PublicKeyVerifier.from_signer(KeyEvidenceSigner())

    for junk in ("", "not base64!", "AAAA"):
        assert verifier.verify(b"evidence", junk) is False


# ----------------------------------------------------------------------
# Security memory is not an authorization authority
# ----------------------------------------------------------------------


def test_evidence_does_not_grant_or_remove_authority():
    """Recording evidence is not a decision, in either direction.

    ``FirewallSDK.authorize`` is the only thing that decides. A verified
    chain describing an agent does not widen what it may do, and a chain
    that fails verification does not narrow it -- a failing chain is
    something an operator acts on by calling ``revoke``.
    """

    memory = _memory(checkpoint_interval=2)
    _seeded(memory, "agent-a", steps=3)
    assert memory.verify_chain("agent-a")["verified"] is True

    sdk = FirewallSDK()
    sdk.generate_key("evidence-authority-key")
    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints={"amount_max": 100},
    )

    # Allowed first: a denial trips the refusal state, after which every
    # later call on this capability answers ``refusal_state`` and this
    # test would be measuring that instead.
    assert (
        sdk.authorize(
            capability, action="payments.send", request={"amount": 10}
        ).allowed
        is True
    )
    assert (
        sdk.authorize(
            capability, action="payments.send", request={"amount": 10_000}
        ).allowed
        is False
    )

    # Break the chain: the verdicts must not move.
    chain = memory.get_chain("agent-a")
    memory._chains["agent-a"] = dataclasses.replace(
        chain, events=chain.events[:2]
    )
    assert memory.verify_chain("agent-a")["verified"] is False

    fresh = FirewallSDK()
    fresh.generate_key("evidence-authority-key")
    other = fresh.issue(
        agent="agent-a",
        capability="payments.send",
        constraints={"amount_max": 100},
    )
    assert (
        fresh.authorize(
            other, action="payments.send", request={"amount": 10}
        ).allowed
        is True
    )


def test_verification_does_not_mutate_the_chain_it_checks():
    """Checking evidence must not be a way to edit it."""

    memory = _memory(checkpoint_interval=2)
    _seeded(memory, "chain", steps=3)

    before = memory.get_chain("chain")
    events_before = memory._evidence_graph.events()

    memory.verify_chain("chain")

    after = memory.get_chain("chain")

    assert after.events == before.events
    assert after.length == before.length
    assert after.head_hash == before.head_hash
    assert memory._evidence_graph.events() == events_before
