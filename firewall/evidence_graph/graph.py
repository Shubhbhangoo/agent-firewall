"""v2.1 Cryptographic Evidence Graph (firewall.evidence_graph).

A tamper-evident security graph of signed, hash-linked evidence events
with causal relationships and explicit evidence kinds.

Design:

* **Signed events** -- every event carries an Ed25519 signature from an
  evidence signer (a dedicated key, or an agent identity key via
  ``IdentityEvidenceSigner``).
* **Hash-linked evidence** -- every event's digest covers its own
  canonical payload *and* the previous event's digest, so events can
  never be reordered, removed, or edited without breaking the chain.
* **Causal relationships** -- each event names its causal parents
  (event ids it derives from / caused by), so the graph is more than a
  linear log.
* **Event ordering** -- sequence numbers are strictly increasing; a
  verify failure on ordering is a tamper signal.
* **Evidence verification** -- ``verify`` recomputes every digest and
  checks every signature; ``detect_tampering`` reports the first
  concrete violation.
* **Replayable incident timelines** -- ``timeline(subject)`` returns the
  ordered, causal history of one subject (agent, incident, capability).
* **Cryptographic provenance chains** -- ``provenance_chain`` walks
  causal parents to the root.

Evidence kinds are **structural and never silently promoted**:

``observed``   a fact recorded from the real world (a decision, an event).
``inference``  a conclusion drawn from observed facts.
``prediction`` a forecast about future state.
``simulation`` output of a counterfactual or simulator.
``unknown``    the evidence is missing or unverifiable.

``promote`` creates a *new* observed event that explicitly references
the inferred/simulated event it confirms (``promoted_from``). The
original event is never rewritten, so the graph always shows what was
inferred and what was later observed.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Optional, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

#: Evidence kinds, never conflated.
EVIDENCE_KINDS = (
    "observed",
    "inference",
    "prediction",
    "simulation",
    "unknown",
)

#: Genesis chain head.
GENESIS_HASH = "0" * 64

#: Maximum payload keys and string lengths (mirrors recorder discipline).
MAX_KEYS = 64
MAX_STRING = 1000


class EvidenceKind(str, Enum):
    OBSERVED = "observed"
    INFERENCE = "inference"
    PREDICTION = "prediction"
    SIMULATION = "simulation"
    UNKNOWN = "unknown"


class EvidenceError(ValueError):
    """Raised for an invalid evidence-graph operation."""


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(text: str, label: str) -> bytes:
    if not isinstance(text, str) or not text.strip():
        raise EvidenceError(f"{label} must be base64")
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except Exception as exc:
        raise EvidenceError(f"{label} is not valid base64") from exc


def _finite(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EvidenceError(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise EvidenceError(f"{label} must be finite")
    return result


#: Maximum nesting depth for a payload value.
MAX_DEPTH = 24


def _payload(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise EvidenceError("payload must be an object")
    if len(value) > MAX_KEYS:
        raise EvidenceError(f"payload has too many keys (>{MAX_KEYS})")
    for key in value:
        if not isinstance(key, str):
            raise EvidenceError("payload keys must be strings")
    _validate_jsonable(value, depth=0)
    return dict(value)


def _validate_jsonable(value: Any, *, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise EvidenceError("payload is nested too deeply")
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, str):
        if len(value) > MAX_STRING:
            raise EvidenceError(
                f"payload string is too long (>{MAX_STRING} characters)"
            )
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise EvidenceError("payload contains a non-finite number")
        return
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_KEYS:
            raise EvidenceError("payload list is too long")
        for item in value:
            _validate_jsonable(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > MAX_KEYS:
            raise EvidenceError("payload object is too large")
        for key, item in value.items():
            if not isinstance(key, str):
                raise EvidenceError("payload keys must be strings")
            _validate_jsonable(item, depth=depth + 1)
        return
    raise EvidenceError(
        f"payload value of type {type(value).__name__} is not allowed"
    )


def _canonical_bytes(block: dict[str, Any]) -> bytes:
    return json.dumps(
        block, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hex_digest(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise EvidenceError(f"{label} must be a hex string")
    value = value.lower()
    if len(value) != 64:
        raise EvidenceError(f"{label} must be 64 hex characters")
    try:
        int(value, 16)
    except ValueError:
        raise EvidenceError(f"{label} is not valid hex")
    return value


# ----------------------------------------------------------------------
# Signers
# ----------------------------------------------------------------------


class EvidenceSigner(Protocol):
    def sign(self, data: bytes) -> tuple[str, str]:
        """Return ``(signature_b64, key_fingerprint)``."""

        ...

    def verify(self, data: bytes, signature_b64: str) -> bool:
        ...

    def fingerprint(self) -> str:
        ...


class KeyEvidenceSigner:
    """An evidence signer with its own Ed25519 key pair."""

    def __init__(self) -> None:
        self._private = Ed25519PrivateKey.generate()
        self._public = self._private.public_key()

    def sign(self, data: bytes) -> tuple[str, str]:
        signature = self._private.sign(bytes(data))
        return _b64encode(signature), self.fingerprint()

    def verify(self, data: bytes, signature_b64: str) -> bool:
        try:
            self._public.verify(
                _b64decode(signature_b64, "signature"),
                bytes(data),
            )
            return True
        except (InvalidSignature, EvidenceError, ValueError):
            return False

    def fingerprint(self) -> str:
        return hashlib.sha256(
            self._public.public_bytes_raw()
        ).hexdigest()


class IdentityEvidenceSigner:
    """An evidence signer bound to an agent identity key.

    Verification uses the identity registry, so rotated-out or revoked
    identities make their events unverifiable - exactly right.
    """

    def __init__(
        self,
        identity_registry,
        agent_id: str,
    ) -> None:
        self._identities = identity_registry
        self._agent = agent_id

    def sign(self, data: bytes) -> tuple[str, str]:
        identity = self._identities.get(self._agent)
        if identity is None or identity.status != "active":
            raise EvidenceError(
                f"identity is not active: {self._agent}"
            )
        signature = self._identities.sign(self._agent, bytes(data))
        return signature, identity.key_fingerprint

    def verify(self, data: bytes, signature_b64: str) -> bool:
        return self._identities.verify(
            self._agent, bytes(data), signature_b64
        )

    def fingerprint(self) -> str:
        identity = self._identities.get(self._agent)
        if identity is None:
            return ""
        return identity.key_fingerprint


# ----------------------------------------------------------------------
# Events
# ----------------------------------------------------------------------


@dataclass(frozen=True)
class EvidenceEvent:
    """One signed, hash-linked evidence event."""

    seq: int
    kind: str
    subject: str
    event_type: str
    payload: dict[str, Any] = field(default_factory=dict)
    causal_parents: tuple[str, ...] = ()
    prev_hash: str = GENESIS_HASH
    timestamp: float = 0.0
    signer: str = ""
    signature: str = ""
    event_id: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.seq, bool) or not isinstance(self.seq, int):
            raise EvidenceError("seq must be an integer")
        if self.seq < 1:
            raise EvidenceError("seq must be positive")
        if self.kind not in EVIDENCE_KINDS:
            raise EvidenceError(f"unknown evidence kind: {self.kind}")
        if not isinstance(self.subject, str) or not self.subject.strip():
            raise EvidenceError("subject is required")
        if not isinstance(self.event_type, str) or not self.event_type.strip():
            raise EvidenceError("event_type is required")
        object.__setattr__(self, "payload", _payload(self.payload))
        object.__setattr__(
            self,
            "timestamp",
            _finite(self.timestamp, "timestamp"),
        )
        object.__setattr__(
            self,
            "prev_hash",
            _hex_digest(self.prev_hash, "prev_hash"),
        )

    def signed_block(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "kind": self.kind,
            "subject": self.subject,
            "event_type": self.event_type,
            "payload": dict(self.payload),
            "causal_parents": list(self.causal_parents),
            "prev_hash": self.prev_hash,
            "timestamp": self.timestamp,
            "signer": self.signer,
        }

    def signed_bytes(self) -> bytes:
        return _canonical_bytes(self.signed_block())

    def compute_hash(self) -> str:
        return _sha256(self.signed_bytes())

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "kind": self.kind,
            "subject": self.subject,
            "event_type": self.event_type,
            "payload": dict(self.payload),
            "causal_parents": list(self.causal_parents),
            "prev_hash": self.prev_hash,
            "timestamp": self.timestamp,
            "signer": self.signer,
            "signature": self.signature,
            "event_id": self.event_id,
        }

    @classmethod
    def from_dict(cls, payload: Any) -> "EvidenceEvent":
        if not isinstance(payload, dict):
            raise EvidenceError("an evidence event must be an object")
        return cls(
            seq=payload.get("seq"),
            kind=payload.get("kind"),
            subject=payload.get("subject"),
            event_type=payload.get("event_type"),
            payload=payload.get("payload"),
            causal_parents=tuple(payload.get("causal_parents", ()) or ()),
            prev_hash=payload.get("prev_hash", GENESIS_HASH),
            timestamp=payload.get("timestamp", 0.0),
            signer=payload.get("signer", ""),
            signature=payload.get("signature", ""),
            event_id=payload.get("event_id", ""),
        )


# ----------------------------------------------------------------------
# The graph
# ----------------------------------------------------------------------


class EvidenceGraph:
    """Tamper-evident, signed evidence graph with causal ordering."""

    def __init__(
        self,
        signer: Optional[EvidenceSigner] = None,
        *,
        clock: Any = None,
        state_path: Optional[str | Path] = None,
    ) -> None:
        self._signer = signer
        self._clock = clock if clock is not None else time.time
        self._lock = threading.RLock()
        self._events: list[EvidenceEvent] = []
        self._by_id: dict[str, EvidenceEvent] = {}
        self._seq = 0

        self._path = Path(state_path) if state_path else None
        if self._path is not None:
            self._load()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> None:
        if self._path is None or not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise EvidenceError(f"cannot load evidence graph: {exc}") from exc
        with self._lock:
            for entry in data.get("events", []):
                try:
                    event = EvidenceEvent.from_dict(entry)
                except EvidenceError:
                    continue
                self._events.append(event)
                self._by_id[event.event_id] = event
                self._seq = max(self._seq, event.seq)

    def _save(self) -> None:
        if self._path is None:
            return
        data = {"events": [event.to_dict() for event in self._events]}
        directory = self._path.parent
        dir_text = str(directory) if str(directory) != "." else "."
        fd, temp_path = tempfile.mkstemp(
            prefix=".evidence-state.", suffix=".tmp", dir=dir_text
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, self._path)
        except Exception:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
            raise

    # ------------------------------------------------------------------
    # Appending
    # ------------------------------------------------------------------

    def append(
        self,
        kind: str,
        subject: str,
        event_type: str,
        payload: Optional[dict[str, Any]] = None,
        *,
        causal_parents: Iterable[str] = (),
        now: Optional[float] = None,
        signer: Optional[EvidenceSigner] = None,
    ) -> EvidenceEvent:
        """Append one signed evidence event.

        ``signer`` overrides the graph's default signer for this event.
        When no signer is available the event is recorded unsigned
        (``signature=""``); verification then reports it as
        unverifiable rather than verified.
        """

        active_signer = signer or self._signer

        parents = tuple(
            _hex_digest(item, "causal_parent") if item != GENESIS_HASH else item
            for item in causal_parents
        )

        with self._lock:
            for parent in parents:
                if parent != GENESIS_HASH and parent not in self._by_id:
                    raise EvidenceError(
                        f"causal parent does not exist: {parent}"
                    )

            self._seq += 1
            seq = self._seq
            timestamp = float(now) if now is not None else float(self._clock())
            prev_hash = (
                self._events[-1].event_id
                if self._events
                else GENESIS_HASH
            )

            event = EvidenceEvent(
                seq=seq,
                kind=kind,
                subject=subject,
                event_type=event_type,
                payload=_payload(payload),
                causal_parents=parents,
                prev_hash=prev_hash,
                timestamp=timestamp,
                signer=(
                    active_signer.fingerprint()
                    if active_signer is not None
                    else ""
                ),
            )
            event_id = event.compute_hash()
            event = EvidenceEvent(
                seq=seq,
                kind=kind,
                subject=subject,
                event_type=event_type,
                payload=dict(event.payload),
                causal_parents=parents,
                prev_hash=prev_hash,
                timestamp=timestamp,
                signer=event.signer,
                signature="",
                event_id=event_id,
            )

            if active_signer is not None:
                signature, _ = active_signer.sign(event.signed_bytes())
                event = EvidenceEvent(
                    seq=seq,
                    kind=kind,
                    subject=subject,
                    event_type=event_type,
                    payload=dict(event.payload),
                    causal_parents=parents,
                    prev_hash=prev_hash,
                    timestamp=timestamp,
                    signer=event.signer,
                    signature=signature,
                    event_id=event_id,
                )

            self._events.append(event)
            self._by_id[event_id] = event
            self._save()
            return event

    def promote(
        self,
        event_id: str,
        *,
        reason: str,
        signer: Optional[EvidenceSigner] = None,
        now: Optional[float] = None,
    ) -> EvidenceEvent:
        """Explicitly promote a non-observed event to observed evidence.

        Creates a **new** observed event whose payload references the
        original (``promoted_from``) and the reason. The original event
        is never rewritten: the graph always shows what was inferred and
        what was later confirmed. Promoting an already-observed event is
        an error; promotion without a recorded reason is an error.
        """

        if not isinstance(reason, str) or not reason.strip():
            raise EvidenceError("reason is required for promotion")

        with self._lock:
            original = self._by_id.get(event_id)
            if original is None:
                raise EvidenceError(f"unknown event: {event_id}")
            if original.kind == "observed":
                raise EvidenceError(
                    "an observed event cannot be promoted further"
                )

            return self.append(
                "observed",
                subject=original.subject,
                event_type=original.event_type,
                payload={
                    "promoted_from": event_id,
                    "promoted_kind": original.kind,
                    "reason": reason,
                },
                causal_parents=(event_id,),
                now=now,
                signer=signer,
            )

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(self) -> dict[str, Any]:
        """Full-chain verification.

        Returns a status: ``verified`` (chain + signatures + causality
        all check), ``failed`` (a concrete integrity violation), or
        ``unverifiable`` (an event is unsigned or its signer rejects the
        signature). These are never conflated.
        """

        problems = self.detect_tampering()

        if problems:
            status = "failed"
            for problem in problems:
                if problem.get("type") == "unsigned":
                    status = "unverifiable"
                    break
            return {
                "status": status,
                "events": len(self._events),
                "problems": problems,
            }

        return {
            "status": "verified",
            "events": len(self._events),
            "problems": [],
        }

    def detect_tampering(self) -> list[dict[str, Any]]:
        """List every concrete integrity violation, in order.

        An empty list means the graph is intact. Checks: chain hashes,
        prev_hash linkage, sequence monotonicity, causal-parent
        existence, and signatures.
        """

        problems: list[dict[str, Any]] = []

        with self._lock:
            previous_hash = GENESIS_HASH
            previous_seq = 0
            for event in self._events:
                computed = event.compute_hash()
                if event.event_id != computed:
                    problems.append(
                        {
                            "type": "hash_mismatch",
                            "seq": event.seq,
                            "event_id": event.event_id,
                            "expected": computed,
                        }
                    )
                if event.prev_hash != previous_hash:
                    problems.append(
                        {
                            "type": "broken_link",
                            "seq": event.seq,
                            "expected_prev": previous_hash,
                            "actual_prev": event.prev_hash,
                        }
                    )
                if event.seq != previous_seq + 1:
                    problems.append(
                        {
                            "type": "ordering",
                            "seq": event.seq,
                            "expected_seq": previous_seq + 1,
                        }
                    )
                for parent in event.causal_parents:
                    if parent == GENESIS_HASH:
                        continue
                    if parent not in self._by_id:
                        problems.append(
                            {
                                "type": "missing_causal_parent",
                                "seq": event.seq,
                                "parent": parent,
                            }
                        )
                if event.signature:
                    verified = False
                    if self._signer is not None:
                        try:
                            verified = self._signer.verify(
                                event.signed_bytes(),
                                event.signature,
                            )
                        except Exception:
                            verified = False
                    if not verified:
                        problems.append(
                            {
                                "type": "bad_signature",
                                "seq": event.seq,
                            }
                        )
                else:
                    problems.append(
                        {
                            "type": "unsigned",
                            "seq": event.seq,
                        }
                    )
                previous_hash = event.event_id
                previous_seq = event.seq

        return problems

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def events(self) -> tuple[EvidenceEvent, ...]:
        with self._lock:
            return tuple(self._events)

    def event(self, seq: int) -> Optional[EvidenceEvent]:
        with self._lock:
            for event in self._events:
                if event.seq == seq:
                    return event
            return None

    def by_id(self, event_id: str) -> Optional[EvidenceEvent]:
        with self._lock:
            return self._by_id.get(event_id)

    def timeline(
        self,
        subject: str,
    ) -> list[dict[str, Any]]:
        """A replayable incident timeline for one subject.

        Returns the subject's events in causal order (sequence order,
        with causal parents emitted before dependents when they differ).
        """

        with self._lock:
            relevant = [
                event
                for event in self._events
                if event.subject == subject
            ]
            # Causal order: parents first.
            order: list[EvidenceEvent] = []
            placed: set[str] = set()
            remaining = list(relevant)
            while remaining:
                progressed = False
                for event in list(remaining):
                    if all(
                        parent == GENESIS_HASH or parent in placed
                        for parent in event.causal_parents
                    ):
                        order.append(event)
                        placed.add(event.event_id)
                        remaining.remove(event)
                        progressed = True
                if not progressed:
                    order.extend(remaining)
                    break
            return [
                event.to_dict() for event in sorted(order, key=lambda e: e.seq)
            ]

    def provenance_chain(
        self,
        event_id: str,
    ) -> list[dict[str, Any]]:
        """Walk causal parents back to the root."""

        chain: list[EvidenceEvent] = []
        seen: set[str] = set()
        current_id = event_id

        while current_id != GENESIS_HASH and current_id not in seen:
            seen.add(current_id)
            event = self._by_id.get(current_id)
            if event is None:
                break
            chain.append(event)
            parents = [
                parent
                for parent in event.causal_parents
                if parent != GENESIS_HASH
            ]
            current_id = parents[0] if parents else GENESIS_HASH

        return [event.to_dict() for event in chain]

    def subjects(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(
                sorted({event.subject for event in self._events})
            )

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "events": [event.to_dict() for event in self._events],
                "subjects": list(self.subjects()),
                "signer": (
                    self._signer.fingerprint()
                    if self._signer is not None
                    else ""
                ),
                "verification": self.verify(),
            }

    def close(self) -> None:
        with self._lock:
            self._save()
