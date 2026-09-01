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

from __future__ import __future__

import hashlib
import json
import os
import tempfile
import threading
import time
from dataclasses import dataclass, field
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
    """A verified chain of evidence events."""

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
class Checkpoint:
    """A signed checkpoint anchoring an evidence chain."""

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
        self._checkpoints: dict[str, list[Checkpoint]] = defaultdict(list)
        self._cross_references: list[CrossArtifactReference] = []
        self._index: dict[str, set[str]] = defaultdict(set)  # subject -> event_ids

        self._path = Path(state_path) if state_path else None
        if self._path:
            self._load()

    def _load(self) -> None:
        if not self._path or not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            raise ValueError(f"cannot load security memory: {e}") from e

        with self._lock:
            # Load evidence graph
            for entry in data.get("events", []):
                event = EvidenceEvent.from_dict(entry)
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
                    verified=chain_data.get("verified", False),
                    created_at=chain_data.get("created_at", 0.0),
                    last_checkpoint_at=chain_data.get("last_checkpoint_at", 0.0),
                    checkpoint_signatures=tuple(chain_data.get("checkpoint_signatures", [])),
                )
                self._chains[chain.chain_id] = chain

            # Load checkpoints
            for cp_data in data.get("checkpoints", []):
                cp = Checkpoint(**cp_data)
                self._checkpoints[cp.chain_id].append(cp)

            # Load cross-references
            for ref_data in data.get("cross_references", []):
                self._cross_references.append(CrossArtifactReference(**ref_data))

    def _save(self) -> None:
        if not self._path:
            return

        data = {
            "events": [e.to_dict() for e in self._evidence_graph.events()],
            "chains": [c.to_dict() for c in self._chains.values()],
            "checkpoints": [cp.to_dict() for cps in self._checkpoints.values() for cp in cps],
            "cross_references": [r.to_dict() for r in self._cross_references],
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
                    verified=True,
                    created_at=timestamp,
                    last_checkpoint_at=timestamp,
                )

            self._chains[chain_id] = chain
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
                    verified=True,
                    created_at=chain.created_at,
                    last_checkpoint_at=timestamp,
                    checkpoint_signatures=chain.checkpoint_signatures + (checkpoint.signature,),
                )
                self._chains[chain_id] = new_chain

            self._save()
            return event, new_chain

    def _create_checkpoint(
        self,
        chain: EvidenceChain,
        event: EvidenceEvent,
        timestamp: float,
    ) -> Checkpoint:
        """Create a signed checkpoint for the chain."""
        previous_cp_hash = GENESIS_HASH
        checkpoints = self._checkpoints.get(chain.chain_id, [])
        if checkpoints:
            previous_cp_hash = hashlib.sha256(checkpoints[-1].canonical_bytes()).hexdigest()

        cp = Checkpoint(
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
        cp = Checkpoint(
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

    def verify_chain(self, chain_id: str) -> dict[str, Any]:
        """Verify an entire evidence chain."""
        with self._lock:
            chain = self._chains.get(chain_id)
            if not chain:
                return {"verified": False, "reason": "chain not found"}

            # Verify evidence graph
            graph_result = self._evidence_graph.verify()
            if graph_result["status"] != "verified":
                return {"verified": False, "reason": "evidence graph verification failed", "details": graph_result}

            # Verify chain integrity
            prev_hash = GENESIS_HASH
            for event in chain.events:
                if event.prev_hash != prev_hash:
                    return {"verified": False, "reason": f"broken link at seq {event.seq}", "event": event.to_dict()}
                if event.event_id != event.compute_hash():
                    return {"verified": False, "reason": f"hash mismatch at seq {event.seq}", "event": event.to_dict()}
                prev_hash = event.event_id

            # Verify checkpoints
            checkpoints = self._checkpoints.get(chain_id, [])
            for cp in checkpoints:
                # Verify checkpoint signature
                cp_bytes = cp.canonical_bytes()
                if not self._signer.verify(cp_bytes, cp.signature):
                    return {"verified": False, "reason": f"invalid checkpoint signature: {cp.checkpoint_id}"}
                # Verify checkpoint points to correct event
                event = self._evidence_graph.by_id(cp.event_hash)
                if not event or event.seq != cp.sequence_number:
                    return {"verified": False, "reason": f"checkpoint points to wrong event: {cp.checkpoint_id}"}

            return {
                "verified": True,
                "chain_id": chain_id,
                "length": chain.length,
                "checkpoints": len(checkpoints),
                "head_hash": chain.head_hash,
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
        """Export a chain for independent verification."""
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
        verify: bool = True,
    ) -> EvidenceChain:
        """Import a previously exported chain."""
        chain_data = export_data["chain"]
        chain = EvidenceChain(
            chain_id=chain_data["chain_id"],
            events=tuple(EvidenceEvent.from_dict(e) for e in chain_data.get("events", [])),
            head_hash=chain_data.get("head_hash", GENESIS_HASH),
            length=chain_data.get("length", 0),
            verified=chain_data.get("verified", False),
            created_at=chain_data.get("created_at", 0.0),
            last_checkpoint_at=chain_data.get("last_checkpoint_at", 0.0),
            checkpoint_signatures=tuple(chain_data.get("checkpoint_signatures", [])),
        )

        if verify:
            # Verify the imported chain
            prev_hash = GENESIS_HASH
            for event in chain.events:
                if event.prev_hash != prev_hash:
                    raise ValueError(f"imported chain has broken link at seq {event.seq}")
                if event.event_id != event.compute_hash():
                    raise ValueError(f"imported chain has hash mismatch at seq {event.seq}")
                prev_hash = event.event_id

        with self._lock:
            self._chains[chain.chain_id] = chain
            for event in chain.events:
                self._evidence_graph._events.append(event)
                self._evidence_graph._by_id[event.event_id] = event
                self._evidence_graph._seq = max(self._evidence_graph._seq, event.seq)
                self._index[event.subject].add(event.event_id)

            for cp_data in export_data.get("checkpoints", []):
                cp = Checkpoint(**cp_data)
                self._checkpoints[chain.chain_id].append(cp)

            for ref_data in export_data.get("cross_references", []):
                self._cross_references.append(CrossArtifactReference(**ref_data))

            self._save()

        return chain

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


from collections import defaultdict