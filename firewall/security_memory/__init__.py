"""v2.2 Security Memory 2.0 (firewall.security_memory).

Extends the evidence system with:
- Long-lived evidence chains
- Checkpoint continuity
- Signed checkpoints
- Cross-artifact relationships
- Provenance verification
- Incident reconstruction
- Secure import/export
- Independent verification
- Tamper detection
- Evidence indexing

Maintains strict distinction between observed, derived, inferred, simulated, unknown.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from firewall.evidence_graph import (
    EvidenceGraph,
    EvidenceEvent,
    EvidenceKind,
    EvidenceSigner,
    KeyEvidenceSigner,
    GENESIS_HASH,
)


@dataclass(frozen=True)
class EvidenceChain:
    """A verified chain of evidence events.

    ``verified`` records the outcome of an actual :meth:`
    SecurityMemory.verify_chain` call at the moment the chain was last
    written. It is never restored from disk or from an import, and no
    code path sets it without running the check: it was previously set to
    ``True`` by construction whenever a chain got its first event or hit
    a checkpoint interval, which made it a statement that the chain was
    intact issued by the same code that would have been wrong about it.

    It is a cached result, not an authority. Anything relying on chain
    integrity must call ``verify_chain`` and read the problems.
    """

    chain_id: str
    events: tuple[EvidenceEvent, ...] = ()
    head_hash: str = GENESIS_HASH
    length: int = 0
    verified: bool = False
    created_at: float = 0.0
    last_checkpoint_at: float = 0.0
    checkpoint_signatures: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "events": [e.to_dict() for e in self.events],
            "head_hash": self.head_hash,
            "length": self.length,
            "verified": self.verified,
            "created_at": self.created_at,
            "last_checkpoint_at": self.last_checkpoint_at,
            "checkpoint_signatures": list(self.checkpoint_signatures),
        }


@dataclass(frozen=True)
class EvidenceCheckpoint:
    """A signed checkpoint anchoring an evidence chain.

    Named for the chain it anchors. This commits to a point in a
    :class:`~firewall.evidence_graph.EvidenceGraph` chain and is what
    :mod:`firewall.evidence_integrity` verifies against.

    It is *not* :class:`firewall.recorder.checkpoint.Checkpoint`, which
    commits to a point in the decision recorder's event log and is what
    ``firewall verify`` reads out of an audit artifact. The two sign
    different field sets over different chains, so neither verifier can
    check the other's checkpoints. Both were called ``Checkpoint`` until
    v2.3, which invited reading a verified evidence chain as a verified
    audit artifact, or the reverse.
    """

    checkpoint_id: str
    chain_id: str
    sequence_number: int
    event_hash: str
    previous_checkpoint_hash: str
    timestamp: float
    signer_fingerprint: str
    signature: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "checkpoint_id": self.checkpoint_id,
            "chain_id": self.chain_id,
            "sequence_number": self.sequence_number,
            "event_hash": self.event_hash,
            "previous_checkpoint_hash": self.previous_checkpoint_hash,
            "timestamp": self.timestamp,
            "signer_fingerprint": self.signer_fingerprint,
            "signature": self.signature,
        }

    def canonical_bytes(self) -> bytes:
        return json.dumps({
            "checkpoint_id": self.checkpoint_id,
            "chain_id": self.chain_id,
            "sequence_number": self.sequence_number,
            "event_hash": self.event_hash,
            "previous_checkpoint_hash": self.previous_checkpoint_hash,
            "timestamp": self.timestamp,
            "signer_fingerprint": self.signer_fingerprint,
        }, sort_keys=True, separators=(",", ":")).encode()

    @classmethod
    def from_dict(cls, data: Any) -> "EvidenceCheckpoint":
        """Rebuild a checkpoint from untrusted JSON.

        ``EvidenceCheckpoint(**data)`` was the previous construction, in both the
        state loader and the importer. It turns an attacker-chosen JSON
        object into keyword arguments: an unexpected key raises
        ``TypeError`` from deep inside a dataclass rather than being
        reported as a bad checkpoint, a missing key does the same, and
        ``sequence_number`` arrives as whatever type the file said -- a
        string ``"1"`` compares unequal to every ``int`` position, so a
        checkpoint could be made to silently anchor nothing.

        Types are coerced here rather than merely checked so that a
        checkpoint round-tripped through JSON stays byte-identical under
        :meth:`canonical_bytes`; otherwise its signature would stop
        verifying after a save/load cycle.
        """

        if not isinstance(data, dict):
            raise ValueError(
                f"checkpoint must be an object, got {type(data).__name__}"
            )

        try:
            sequence_number = int(data["sequence_number"])
            timestamp = float(data["timestamp"])
            fields = {
                "checkpoint_id": str(data["checkpoint_id"]),
                "chain_id": str(data["chain_id"]),
                "event_hash": str(data["event_hash"]),
                "previous_checkpoint_hash": str(
                    data["previous_checkpoint_hash"]
                ),
                "signer_fingerprint": str(data["signer_fingerprint"]),
                "signature": str(data["signature"]),
            }
        except KeyError as error:
            raise ValueError(
                f"checkpoint is missing field {error.args[0]!r}"
            ) from error
        except (TypeError, ValueError) as error:
            raise ValueError(
                f"checkpoint has a malformed field: {error}"
            ) from error

        return cls(
            sequence_number=sequence_number,
            timestamp=timestamp,
            **fields,
        )


@dataclass(frozen=True)
class CrossArtifactReference:
    """A reference linking evidence across artifacts."""

    source_chain_id: str
    source_event_id: str
    target_chain_id: str
    target_event_id: str
    relationship: str  # "caused_by", "derived_from", "contradicts", "promotes"
    created_at: float
    verified: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_chain_id": self.source_chain_id,
            "source_event_id": self.source_event_id,
            "target_chain_id": self.target_chain_id,
            "target_event_id": self.target_event_id,
            "relationship": self.relationship,
            "created_at": self.created_at,
            "verified": self.verified,
        }

    @classmethod
    def from_dict(cls, data: Any) -> "CrossArtifactReference":
        """Rebuild a reference from untrusted JSON.

        ``verified`` is deliberately *not* read back. It was persisted and
        restored, which made it a claim the file could assert about
        itself; nothing in this module ever sets it to ``True``, so
        honouring it on load would only ever import an attacker's
        assertion.
        """

        if not isinstance(data, dict):
            raise ValueError(
                f"cross reference must be an object, got "
                f"{type(data).__name__}"
            )

        try:
            return cls(
                source_chain_id=str(data["source_chain_id"]),
                source_event_id=str(data["source_event_id"]),
                target_chain_id=str(data["target_chain_id"]),
                target_event_id=str(data["target_event_id"]),
                relationship=str(data["relationship"]),
                created_at=float(data["created_at"]),
                verified=False,
            )
        except KeyError as error:
            raise ValueError(
                f"cross reference is missing field {error.args[0]!r}"
            ) from error
        except (TypeError, ValueError) as error:
            raise ValueError(
                f"cross reference has a malformed field: {error}"
            ) from error


class SecurityMemory:
    """
    Long-lived, tamper-evident security memory with checkpoint continuity
    and cross-artifact relationships.
    """

    def __init__(
        self,
        *,
        signer: Optional[EvidenceSigner] = None,
        clock: Optional[Callable[[], float]] = None,
        state_path: Optional[str | Path] = None,
        checkpoint_interval: int = 100,
    ) -> None:
        self._signer = signer or KeyEvidenceSigner()
        self._clock = clock or time.time
        self._checkpoint_interval = checkpoint_interval
        self._lock = threading.RLock()

        self._evidence_graph = EvidenceGraph(signer=self._signer, clock=self._clock)
        self._chains: dict[str, EvidenceChain] = {}
        self._checkpoints: dict[str, list[EvidenceCheckpoint]] = defaultdict(list)
        self._cross_references: list[CrossArtifactReference] = []
        self._index: dict[str, set[str]] = defaultdict(set)  # subject -> event_ids

        # Imported chains are held apart from the local evidence graph.
        #
        # The previous importer appended foreign events straight into
        # ``self._evidence_graph._events``. Three things followed from
        # that, and the third is why quarantine is structural rather than
        # tidiness:
        #
        # 1. Foreign events carry the exporting graph's ``prev_hash`` and
        #    ``seq``, so ``EvidenceGraph.detect_tampering`` reported
        #    ``broken_link`` and ``ordering`` for them.
        # 2. They are signed by the exporter's key, which the local
        #    signer cannot verify, so it reported ``bad_signature``.
        # 3. ``EvidenceGraph.verify`` is whole-graph. One import
        #    therefore moved every *local* chain from ``verified`` to
        #    ``failed`` -- an attacker who could get one chain imported
        #    destroyed the verifiability of all existing evidence, and
        #    the resulting status said "tampered" rather than "foreign".
        #
        # Foreign evidence is not local evidence. It is held, indexed and
        # verifiable against the exporter's key, and it is never merged.
        self._imported_chains: dict[str, EvidenceChain] = {}
        self._imported_checkpoints: dict[str, list[EvidenceCheckpoint]] = defaultdict(list)
        self._imported_events: dict[str, EvidenceEvent] = {}

        self._path = Path(state_path) if state_path else None
        if self._path:
            self._load()

    def _load(self) -> None:
        """Restore persisted state.

        The state file is untrusted input: it is the artifact an attacker
        edits when they cannot reach the running process. So nothing here
        treats a field as a finding. Specifically:

        * ``verified`` is not read back on chains. It was, and it is
          written by :meth:`append_to_chain` at each checkpoint interval,
          so restoring it let the file assert its own integrity. Chains
          load unverified; :meth:`verify_chain` is what establishes the
          claim, against the signing key.
        * duplicate event ids are rejected rather than appended twice.
          The previous loader wrote every entry into ``_events`` and
          ``_by_id`` unconditionally, so a file with a repeated event
          grew the list while the id map kept one copy -- the graph's
          length and its lookups then disagreed permanently.
        * ``_seq`` is restored from the maximum ``seq`` present, as
          before, so newly appended events cannot collide with loaded
          ones.

        A malformed file raises. Loading half a memory and continuing
        would leave the process running on evidence it could not account
        for.
        """

        if not self._path or not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            raise ValueError(f"cannot load security memory: {e}") from e

        if not isinstance(data, dict):
            raise ValueError(
                f"security memory state must be an object, got "
                f"{type(data).__name__}"
            )

        with self._lock:
            # Load evidence graph
            for entry in data.get("events", []):
                event = EvidenceEvent.from_dict(entry)
                if event.event_id in self._evidence_graph._by_id:
                    raise ValueError(
                        f"duplicate event in state file: "
                        f"{event.event_id}"
                    )
                self._evidence_graph._events.append(event)
                self._evidence_graph._by_id[event.event_id] = event
                self._evidence_graph._seq = max(self._evidence_graph._seq, event.seq)
                self._index[event.subject].add(event.event_id)

            # Load chains
            for chain_data in data.get("chains", []):
                events = tuple(EvidenceEvent.from_dict(e) for e in chain_data.get("events", []))
                chain = EvidenceChain(
                    chain_id=chain_data["chain_id"],
                    events=events,
                    head_hash=chain_data.get("head_hash", GENESIS_HASH),
                    length=chain_data.get("length", 0),
                    verified=False,
                    created_at=chain_data.get("created_at", 0.0),
                    last_checkpoint_at=chain_data.get("last_checkpoint_at", 0.0),
                    checkpoint_signatures=tuple(chain_data.get("checkpoint_signatures", [])),
                )
                if chain.chain_id in self._chains:
                    raise ValueError(
                        f"duplicate chain in state file: {chain.chain_id}"
                    )
                self._chains[chain.chain_id] = chain

            # Load checkpoints
            for cp_data in data.get("checkpoints", []):
                cp = EvidenceCheckpoint.from_dict(cp_data)
                self._checkpoints[cp.chain_id].append(cp)

            # Load cross-references
            for ref_data in data.get("cross_references", []):
                self._cross_references.append(
                    CrossArtifactReference.from_dict(ref_data)
                )

            # Load quarantined imports, still apart from the graph.
            for chain_data in data.get("imported_chains", []):
                events = tuple(
                    EvidenceEvent.from_dict(e)
                    for e in chain_data.get("events", [])
                )
                imported = EvidenceChain(
                    chain_id=chain_data["chain_id"],
                    events=events,
                    head_hash=chain_data.get("head_hash", GENESIS_HASH),
                    length=chain_data.get("length", 0),
                    verified=False,
                    created_at=chain_data.get("created_at", 0.0),
                    last_checkpoint_at=chain_data.get(
                        "last_checkpoint_at", 0.0
                    ),
                    checkpoint_signatures=tuple(
                        chain_data.get("checkpoint_signatures", [])
                    ),
                )
                self._imported_chains[imported.chain_id] = imported
                for event in imported.events:
                    self._imported_events[event.event_id] = event

            for cp_data in data.get("imported_checkpoints", []):
                cp = EvidenceCheckpoint.from_dict(cp_data)
                self._imported_checkpoints[cp.chain_id].append(cp)

    def _save(self) -> None:
        if not self._path:
            return

        data = {
            "events": [e.to_dict() for e in self._evidence_graph.events()],
            "chains": [c.to_dict() for c in self._chains.values()],
            "checkpoints": [cp.to_dict() for cps in self._checkpoints.values() for cp in cps],
            "cross_references": [r.to_dict() for r in self._cross_references],
            # Kept under separate keys so a reload cannot promote a
            # foreign chain into local evidence by accident.
            "imported_chains": [
                c.to_dict() for c in self._imported_chains.values()
            ],
            "imported_checkpoints": [
                cp.to_dict()
                for cps in self._imported_checkpoints.values()
                for cp in cps
            ],
        }

        directory = self._path.parent
        dir_text = str(directory) if str(directory) != "." else "."
        fd, temp_path = tempfile.mkstemp(
            prefix=".security-memory.", suffix=".tmp", dir=dir_text
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2, default=str)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, self._path)
        except Exception:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
            raise

    def create_chain(
        self,
        chain_id: str,
        *,
        initial_event: Optional[dict[str, Any]] = None,
        now: Optional[float] = None,
    ) -> EvidenceChain:
        """Create a new evidence chain."""
        timestamp = float(now) if now is not None else float(self._clock())

        with self._lock:
            if chain_id in self._chains:
                raise ValueError(f"chain already exists: {chain_id}")

            chain = EvidenceChain(
                chain_id=chain_id,
                events=(),
                head_hash=GENESIS_HASH,
                length=0,
                verified=False,
                created_at=timestamp,
                last_checkpoint_at=timestamp,
            )

            if initial_event:
                event = self._evidence_graph.append(
                    kind=initial_event.get("kind", "observed"),
                    subject=initial_event.get("subject", chain_id),
                    event_type=initial_event.get("event_type", "chain_created"),
                    payload=initial_event.get("payload", {}),
                    causal_parents=initial_event.get("causal_parents", ()),
                    now=timestamp,
                )
                chain = EvidenceChain(
                    chain_id=chain_id,
                    events=(event,),
                    head_hash=event.event_id,
                    length=1,
                    verified=False,
                    created_at=timestamp,
                    last_checkpoint_at=timestamp,
                )

            self._chains[chain_id] = chain
            if chain.events:
                chain = self._record_verification(chain_id)
            self._save()
            return chain

    def append_to_chain(
        self,
        chain_id: str,
        kind: str,
        subject: str,
        event_type: str,
        payload: Optional[dict[str, Any]] = None,
        *,
        causal_parents: Iterable[str] = (),
        now: Optional[float] = None,
    ) -> tuple[EvidenceEvent, EvidenceChain]:
        """Append an event to an existing chain."""
        timestamp = float(now) if now is not None else float(self._clock())

        with self._lock:
            chain = self._chains.get(chain_id)
            if chain is None:
                raise ValueError(f"unknown chain: {chain_id}")

            # Verify causal parents exist in this chain
            chain_event_ids = {e.event_id for e in chain.events}
            for parent in causal_parents:
                if parent != GENESIS_HASH and parent not in chain_event_ids:
                    raise ValueError(f"causal parent not in chain: {parent}")

            event = self._evidence_graph.append(
                kind=kind,
                subject=subject,
                event_type=event_type,
                payload=payload,
                causal_parents=tuple(causal_parents),
                now=timestamp,
            )

            new_events = chain.events + (event,)
            new_chain = EvidenceChain(
                chain_id=chain_id,
                events=new_events,
                head_hash=event.event_id,
                length=chain.length + 1,
                verified=chain.verified,
                created_at=chain.created_at,
                last_checkpoint_at=chain.last_checkpoint_at,
                checkpoint_signatures=chain.checkpoint_signatures,
            )

            self._chains[chain_id] = new_chain
            self._index[subject].add(event.event_id)

            # Create checkpoint if interval reached
            if new_chain.length % self._checkpoint_interval == 0:
                checkpoint = self._create_checkpoint(new_chain, event, timestamp)
                self._checkpoints[chain_id].append(checkpoint)
                new_chain = EvidenceChain(
                    chain_id=chain_id,
                    events=new_events,
                    head_hash=event.event_id,
                    length=new_chain.length,
                    verified=False,
                    created_at=chain.created_at,
                    last_checkpoint_at=timestamp,
                    checkpoint_signatures=chain.checkpoint_signatures + (checkpoint.signature,),
                )
                self._chains[chain_id] = new_chain
                new_chain = self._record_verification(chain_id)

            self._save()
            return event, new_chain

    def _create_checkpoint(
        self,
        chain: EvidenceChain,
        event: EvidenceEvent,
        timestamp: float,
    ) -> EvidenceCheckpoint:
        """Create a signed checkpoint for the chain."""
        previous_cp_hash = GENESIS_HASH
        checkpoints = self._checkpoints.get(chain.chain_id, [])
        if checkpoints:
            previous_cp_hash = hashlib.sha256(checkpoints[-1].canonical_bytes()).hexdigest()

        cp = EvidenceCheckpoint(
            checkpoint_id=f"cp-{chain.chain_id}-{chain.length}",
            chain_id=chain.chain_id,
            sequence_number=chain.length,
            event_hash=event.event_id,
            previous_checkpoint_hash=previous_cp_hash,
            timestamp=timestamp,
            signer_fingerprint=self._signer.fingerprint(),
            signature="",
        )

        signature, _ = self._signer.sign(cp.canonical_bytes())
        cp = EvidenceCheckpoint(
            checkpoint_id=cp.checkpoint_id,
            chain_id=cp.chain_id,
            sequence_number=cp.sequence_number,
            event_hash=cp.event_hash,
            previous_checkpoint_hash=cp.previous_checkpoint_hash,
            timestamp=cp.timestamp,
            signer_fingerprint=cp.signer_fingerprint,
            signature=signature,
        )

        return cp

    def _record_verification(self, chain_id: str) -> EvidenceChain:
        """Recompute a stored chain's ``verified`` flag from a real check.

        Called wherever the old code assigned ``verified=True`` by
        construction. The lock is an ``RLock`` so re-entering through
        :meth:`verify_chain` is safe, and the cost is one whole-graph
        verification per checkpoint interval rather than per append.
        """

        with self._lock:
            chain = self._chains[chain_id]
            result = self.verify_chain(chain_id)
            updated = replace(chain, verified=bool(result["verified"]))
            self._chains[chain_id] = updated
            return updated

    def _event_problems(
        self,
        chain: EvidenceChain,
        *,
        require_in_graph: bool,
        signer: Optional[EvidenceSigner] = None,
    ) -> list[str]:
        """Integrity problems in a chain's own event list.

        Shared by :meth:`verify_chain` and :meth:`import_chain` so there
        is one definition of "this chain is intact". The earlier code had
        two copies of the walk, and they had already drifted: the import
        copy raised on the first problem, so a caller could not see the
        rest, and neither copy noticed truncation.

        ``require_in_graph`` is false for an import, where the events are
        being offered rather than already held. ``signer`` is supplied in
        that case, because nothing else will check the signatures: for a
        local chain the graph verifies them, but a quarantined chain is
        not in the graph, so an import with no verifying key has
        established nothing about authenticity.

        What is deliberately *not* checked here: the global hash link.
        ``EvidenceEvent.prev_hash`` chains across the whole
        :class:`~firewall.evidence_graph.EvidenceGraph`, not within a
        chain, so requiring ``event.prev_hash == previous_chain_event``
        is only satisfiable when a single chain owns every event in the
        graph. It was the previous behaviour, and it meant the second
        chain created in a memory could never verify. The graph owns that
        link and :meth:`EvidenceGraph.verify` checks it; duplicating it
        here with a different meaning was a second, wrong representation
        of the same property.
        """

        problems: list[str] = []

        if chain.length != len(chain.events):
            problems.append(
                f"chain length {chain.length} disagrees with "
                f"{len(chain.events)} recorded events, so events have "
                "been added or removed since the length was written"
            )

        expected_head = (
            chain.events[-1].event_id if chain.events else GENESIS_HASH
        )

        if chain.head_hash != expected_head:
            problems.append(
                f"head hash {chain.head_hash[:16]}... does not match "
                f"the last recorded event {expected_head[:16]}..., so "
                "the chain has been truncated or reordered"
            )

        seen: set[str] = set()
        previous_seq = -1

        for position, event in enumerate(chain.events):
            if event.event_id != event.compute_hash():
                problems.append(
                    f"hash mismatch at position {position} "
                    f"(graph seq {event.seq})"
                )

            if event.event_id in seen:
                problems.append(
                    f"event {event.event_id[:16]}... appears twice in "
                    f"the chain at position {position}: a replayed "
                    "event is not a second observation"
                )

            seen.add(event.event_id)

            if event.seq <= previous_seq:
                problems.append(
                    f"position {position} has graph seq {event.seq} "
                    f"after {previous_seq}, so the chain is not in "
                    "recorded order"
                )

            previous_seq = event.seq

            if signer is not None:
                if not event.signature:
                    problems.append(
                        f"position {position} holds an unsigned event: "
                        "an unsigned event is not attributable, and "
                        "unattributable is not trusted"
                    )
                else:
                    try:
                        signature_ok = signer.verify(
                            event.signed_bytes(), event.signature
                        )
                    except Exception:  # noqa: BLE001
                        signature_ok = False

                    if not signature_ok:
                        problems.append(
                            f"position {position} holds event "
                            f"{event.event_id[:16]}... whose signature "
                            "the supplied key does not verify"
                        )

            if not require_in_graph:
                continue

            held = self._evidence_graph.by_id(event.event_id)

            if held is None:
                problems.append(
                    f"position {position} holds event "
                    f"{event.event_id[:16]}... which is not in the "
                    "evidence graph"
                )
            elif held != event:
                problems.append(
                    f"position {position} disagrees with the graph's "
                    f"copy of event {event.event_id[:16]}..."
                )

        return problems

    def _checkpoint_problems(
        self,
        chain: EvidenceChain,
        checkpoints: Iterable[EvidenceCheckpoint],
        *,
        signer: Optional[EvidenceSigner] = None,
        check_signatures: bool = True,
    ) -> list[str]:
        """Problems in a chain's checkpoints.

        The checkpoints are what make truncation detectable. Each one is
        a signed statement that at chain position ``sequence_number`` the
        event was ``event_hash``; a chain that has since lost or reordered
        its tail can no longer produce that event at that position, and
        cannot forge a replacement checkpoint without the signing key.

        ``previous_checkpoint_hash`` is verified as a chain from
        ``GENESIS_HASH``, so removing a checkpoint from the middle is
        detectable too -- otherwise an attacker could drop the checkpoint
        that covers the events they removed.

        ``check_signatures`` is false only on an explicitly unverified
        import, where the caller has no key to check against. The
        structural checks still run: an unverifiable signature is not a
        licence to skip the truncation detector.
        """

        verifier = signer if signer is not None else self._signer
        problems: list[str] = []
        expected_previous = GENESIS_HASH
        previous_sequence = 0

        for index, checkpoint in enumerate(checkpoints):
            if check_signatures:
                try:
                    signature_ok = verifier.verify(
                        checkpoint.canonical_bytes(),
                        checkpoint.signature,
                    )
                except Exception:  # noqa: BLE001
                    signature_ok = False

                if not signature_ok:
                    problems.append(
                        f"checkpoint {checkpoint.checkpoint_id} has an "
                        "invalid signature"
                    )

            if checkpoint.previous_checkpoint_hash != expected_previous:
                problems.append(
                    f"checkpoint {checkpoint.checkpoint_id} does not "
                    "follow the previous checkpoint, so a checkpoint "
                    "has been removed or reordered"
                )

            expected_previous = hashlib.sha256(
                checkpoint.canonical_bytes()
            ).hexdigest()

            if checkpoint.chain_id != chain.chain_id:
                problems.append(
                    f"checkpoint {checkpoint.checkpoint_id} belongs to "
                    f"chain {checkpoint.chain_id!r}"
                )

            if checkpoint.sequence_number <= previous_sequence:
                problems.append(
                    f"checkpoint {checkpoint.checkpoint_id} is at "
                    f"sequence {checkpoint.sequence_number} after "
                    f"{previous_sequence}"
                )

            previous_sequence = checkpoint.sequence_number

            # ``sequence_number`` is a 1-based position within the
            # chain, which is what _create_checkpoint records. The
            # earlier check compared it against the graph-wide
            # ``event.seq``; those coincide only for the first chain in a
            # memory, so a legitimate second chain was reported as
            # "checkpoint points to wrong event".
            position = checkpoint.sequence_number - 1

            if position < 0 or position >= len(chain.events):
                problems.append(
                    f"checkpoint {checkpoint.checkpoint_id} anchors "
                    f"chain position {checkpoint.sequence_number} but "
                    f"the chain holds {len(chain.events)} events: it "
                    "has been truncated"
                )
                continue

            if chain.events[position].event_id != checkpoint.event_hash:
                problems.append(
                    f"checkpoint {checkpoint.checkpoint_id} anchors "
                    f"event {checkpoint.event_hash[:16]}... at position "
                    f"{checkpoint.sequence_number}, but that position "
                    f"now holds "
                    f"{chain.events[position].event_id[:16]}..."
                )

        return problems

    def verify_chain(self, chain_id: str) -> dict[str, Any]:
        """Verify an entire evidence chain.

        Returns ``verified: False`` with every problem found, rather than
        the first. An operator deciding whether an incident record can be
        relied on needs the whole picture; "broken link at seq 6" alone
        does not distinguish one edited event from a wholesale rewrite.
        """

        with self._lock:
            chain = self._chains.get(chain_id)

            if chain is None:
                return {
                    "verified": False,
                    "reason": "chain not found",
                    "problems": [f"unknown chain: {chain_id}"],
                }

            problems: list[str] = []

            graph_result = self._evidence_graph.verify()
            graph_status = graph_result.get("status")

            # ``unverifiable`` is not a pass. An unsigned graph cannot
            # speak to whether its events are authentic, so a chain over
            # it is not verified either.
            if graph_status != "verified":
                problems.append(
                    f"the evidence graph reports {graph_status!r}"
                )

            problems.extend(
                self._event_problems(chain, require_in_graph=True)
            )

            checkpoints = list(self._checkpoints.get(chain_id, []))
            problems.extend(
                self._checkpoint_problems(chain, checkpoints)
            )

            if problems:
                return {
                    "verified": False,
                    "reason": problems[0],
                    "problems": problems,
                    "chain_id": chain_id,
                    "graph_status": graph_status,
                    "checkpoints": len(checkpoints),
                }

            return {
                "verified": True,
                "chain_id": chain_id,
                "length": chain.length,
                "checkpoints": len(checkpoints),
                "head_hash": chain.head_hash,
                "problems": [],
            }

    def add_cross_reference(
        self,
        source_chain_id: str,
        source_event_id: str,
        target_chain_id: str,
        target_event_id: str,
        relationship: str,
        *,
        now: Optional[float] = None,
    ) -> CrossArtifactReference:
        """Add a cross-artifact reference."""
        timestamp = float(now) if now is not None else float(self._clock())

        with self._lock:
            if source_chain_id not in self._chains:
                raise ValueError(f"unknown source chain: {source_chain_id}")
            if target_chain_id not in self._chains:
                raise ValueError(f"unknown target chain: {target_chain_id}")

            source_event = self._evidence_graph.by_id(source_event_id)
            if not source_event:
                raise ValueError(f"unknown source event: {source_event_id}")
            target_event = self._evidence_graph.by_id(target_event_id)
            if not target_event:
                raise ValueError(f"unknown target event: {target_event_id}")

            ref = CrossArtifactReference(
                source_chain_id=source_chain_id,
                source_event_id=source_event_id,
                target_chain_id=target_chain_id,
                target_event_id=target_event_id,
                relationship=relationship,
                created_at=timestamp,
            )

            self._cross_references.append(ref)
            self._save()
            return ref

    def reconstruct_incident(
        self,
        chain_id: str,
        *,
        include_cross_references: bool = True,
    ) -> dict[str, Any]:
        """Reconstruct an incident timeline from an evidence chain."""
        with self._lock:
            chain = self._chains.get(chain_id)
            if not chain:
                return {"error": "chain not found"}

            # Get cross-references
            cross_refs = []
            if include_cross_references:
                cross_refs = [
                    ref.to_dict()
                    for ref in self._cross_references
                    if ref.source_chain_id == chain_id or ref.target_chain_id == chain_id
                ]

            return {
                "chain": chain.to_dict(),
                "checkpoints": [cp.to_dict() for cp in self._checkpoints.get(chain_id, [])],
                "cross_references": cross_refs,
                "verification": self.verify_chain(chain_id),
            }

    def export_chain(
        self,
        chain_id: str,
        *,
        include_checkpoints: bool = True,
        include_cross_refs: bool = True,
    ) -> dict[str, Any]:
        """Export a chain for independent verification.

        ``verification`` is the exporter's own report on the chain. It is
        advisory only: :meth:`import_chain` recomputes everything and
        ignores it, because a claim travelling inside the artifact it
        describes is worth exactly as much as the artifact.
        """

        with self._lock:
            chain = self._chains.get(chain_id)
            if not chain:
                raise ValueError(f"unknown chain: {chain_id}")

            return {
                "chain": chain.to_dict(),
                "checkpoints": [cp.to_dict() for cp in self._checkpoints.get(chain_id, [])] if include_checkpoints else [],
                "cross_references": [
                    ref.to_dict() for ref in self._cross_references
                    if ref.source_chain_id == chain_id or ref.target_chain_id == chain_id
                ] if include_cross_refs else [],
                "verification": self.verify_chain(chain_id),
                "exported_at": float(self._clock()),
                "signer_fingerprint": self._signer.fingerprint(),
            }

    def import_chain(
        self,
        export_data: dict[str, Any],
        *,
        signer: Optional[EvidenceSigner] = None,
        verify: bool = True,
    ) -> EvidenceChain:
        """Import a previously exported chain into quarantine.

        The imported chain is held apart from the local evidence graph
        and is never merged into it. See the note in :meth:`__init__` for
        why: the graph's hash link and sequence are global to one graph,
        and its verification is whole-graph, so merging foreign events
        made every local chain report ``failed``.

        ``signer`` verifies the exporter's signatures. With ``verify``
        true it is required, and an import that cannot be verified is
        refused rather than stored as unverified -- an evidence store
        that accepts unattributable chains and remembers that it could
        not check them will, in practice, be read as if it had.

        Refuses, rather than partially applies:

        * a chain id already held locally or already imported. Silently
          replacing a local chain with a foreign one of the same name
          would be evidence substitution.
        * an event id already held anywhere. The previous importer
          appended events unconditionally, so re-importing the same
          export duplicated every event, and importing a doctored copy
          of a local event overwrote the graph's ``_by_id`` entry with
          the attacker's version.
        * any structural problem in the events or checkpoints, reported
          in full via :exc:`ValueError`.

        Nothing is written until every check has passed.
        """

        if not isinstance(export_data, dict):
            raise ValueError(
                f"export must be an object, got "
                f"{type(export_data).__name__}"
            )

        if verify and signer is None:
            raise ValueError(
                "importing with verify=True needs the exporter's signer; "
                "pass verify=False to hold a chain that is explicitly "
                "unverified"
            )

        try:
            chain_data = export_data["chain"]
        except KeyError as error:
            raise ValueError("export has no chain") from error

        if not isinstance(chain_data, dict):
            raise ValueError(
                f"exported chain must be an object, got "
                f"{type(chain_data).__name__}"
            )

        try:
            chain_id = str(chain_data["chain_id"])
        except KeyError as error:
            raise ValueError("exported chain has no chain_id") from error

        chain = EvidenceChain(
            chain_id=chain_id,
            events=tuple(EvidenceEvent.from_dict(e) for e in chain_data.get("events", [])),
            head_hash=str(chain_data.get("head_hash", GENESIS_HASH)),
            length=int(chain_data.get("length", 0)),
            # Never read back: the exporter's claim about its own chain.
            verified=False,
            created_at=float(chain_data.get("created_at", 0.0)),
            last_checkpoint_at=float(chain_data.get("last_checkpoint_at", 0.0)),
            checkpoint_signatures=tuple(chain_data.get("checkpoint_signatures", [])),
        )

        checkpoints = [
            EvidenceCheckpoint.from_dict(cp_data)
            for cp_data in export_data.get("checkpoints", [])
        ]
        references = [
            CrossArtifactReference.from_dict(ref_data)
            for ref_data in export_data.get("cross_references", [])
        ]

        with self._lock:
            if chain.chain_id in self._chains:
                raise ValueError(
                    f"refusing to import over local chain: "
                    f"{chain.chain_id}"
                )
            if chain.chain_id in self._imported_chains:
                raise ValueError(
                    f"chain already imported: {chain.chain_id}"
                )

            for event in chain.events:
                if self._evidence_graph.by_id(event.event_id) is not None:
                    raise ValueError(
                        f"imported event collides with local evidence: "
                        f"{event.event_id}"
                    )
                if event.event_id in self._imported_events:
                    raise ValueError(
                        f"imported event is a replay of an event "
                        f"already imported: {event.event_id}"
                    )

            problems = self._event_problems(
                chain,
                require_in_graph=False,
                signer=signer if verify else None,
            )
            problems.extend(
                self._checkpoint_problems(
                    chain,
                    checkpoints,
                    signer=signer,
                    check_signatures=verify,
                )
            )

            if problems:
                raise ValueError(
                    f"refusing to import chain {chain.chain_id}: "
                    + "; ".join(problems)
                )

            self._imported_chains[chain.chain_id] = chain
            for event in chain.events:
                self._imported_events[event.event_id] = event
            self._imported_checkpoints[chain.chain_id].extend(checkpoints)
            self._cross_references.extend(references)

            self._save()

        return chain

    def verify_imported_chain(
        self,
        chain_id: str,
        signer: EvidenceSigner,
    ) -> dict[str, Any]:
        """Re-verify a quarantined chain against the exporter's key.

        Separate from :meth:`verify_chain` because the two answer
        different questions. ``verify_chain`` asks whether the local
        evidence graph still holds this chain intact; this asks whether a
        foreign artifact is internally consistent and signed by the key
        the caller believes in. Merging them would need a single method
        to be silently authoritative about a key it was not given.
        """

        with self._lock:
            chain = self._imported_chains.get(chain_id)

            if chain is None:
                return {
                    "verified": False,
                    "reason": "imported chain not found",
                    "problems": [f"unknown imported chain: {chain_id}"],
                    "imported": True,
                }

            problems = self._event_problems(
                chain, require_in_graph=False, signer=signer
            )
            problems.extend(
                self._checkpoint_problems(
                    chain,
                    self._imported_checkpoints.get(chain_id, []),
                    signer=signer,
                )
            )

            return {
                "verified": not problems,
                "reason": problems[0] if problems else "",
                "problems": problems,
                "chain_id": chain_id,
                "length": chain.length,
                "imported": True,
            }

    def get_imported_chain(self, chain_id: str) -> Optional[EvidenceChain]:
        """Get a quarantined chain by ID.

        Deliberately not folded into :meth:`get_chain`: a caller that
        cannot tell local evidence from imported evidence will treat
        imported evidence as local.
        """

        with self._lock:
            return self._imported_chains.get(chain_id)

    def list_imported_chains(self) -> list[str]:
        """List quarantined chain IDs."""

        with self._lock:
            return list(self._imported_chains.keys())

    def get_chain(self, chain_id: str) -> Optional[EvidenceChain]:
        """Get a chain by ID."""
        with self._lock:
            return self._chains.get(chain_id)

    def list_chains(self) -> list[str]:
        """List all chain IDs."""
        with self._lock:
            return list(self._chains.keys())

    def search_events(
        self,
        subject: Optional[str] = None,
        event_type: Optional[str] = None,
        kind: Optional[str] = None,
        since: Optional[float] = None,
        until: Optional[float] = None,
    ) -> list[EvidenceEvent]:
        """Search events across all chains."""
        with self._lock:
            results = []
            candidate_ids = set()

            if subject:
                candidate_ids = self._index.get(subject, set())
            else:
                for ids in self._index.values():
                    candidate_ids.update(ids)

            for event_id in candidate_ids:
                event = self._evidence_graph.by_id(event_id)
                if not event:
                    continue
                if event_type and event.event_type != event_type:
                    continue
                if kind and event.kind != kind:
                    continue
                if since and event.timestamp < since:
                    continue
                if until and event.timestamp > until:
                    continue
                results.append(event)

            return sorted(results, key=lambda e: e.timestamp)

    def close(self) -> None:
        """Persist and close."""
        with self._lock:
            self._save()
            self._evidence_graph.close()