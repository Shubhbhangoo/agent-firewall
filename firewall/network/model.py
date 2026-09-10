"""v1.9 network model: entities, provenance, and evidence refs.

The network model is the shared vocabulary of the Agent Security
Network. Everything in v1.9 -- the merged graph, correlation, behavior,
attack paths, and the simulator -- speaks in these terms.

Provenance is first-class. Every node and edge carries a ``basis`` that
says exactly what kind of fact it is, and the five values are never
conflated:

``observed``
    Recorded directly in an artifact's event chain (an issuance, a
    decision, a revocation).

``derived``
    Computed deterministically from observed facts (revocation
    propagation, effective reachability, transitive delegation).

``inferred``
    A heuristic conclusion (behavioral detections, "this agent is
    unusual"). Always labeled as inference, never as observation.

``simulated``
    Produced by a scenario simulator or counterfactual replay in an
    isolated workspace. Never presented as something that happened.

``unknown``
    The evidence is missing or unverifiable. Never promoted to
    trust.

Every node and edge also carries an ``evidence`` list: one reference per
supporting fact, pointing at an artifact id and an event sequence (and
optionally a correlation bundle). Integrity comes from the artifact
verifier; the network only *references* verified evidence and never
invents it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Provenance(str, Enum):
    """How a fact came to be known. Never conflated."""

    OBSERVED = "observed"
    DERIVED = "derived"
    INFERRED = "inferred"
    SIMULATED = "simulated"
    UNKNOWN = "unknown"


class EntityType(str, Enum):
    AGENT = "agent"
    SESSION = "session"
    TOOL = "tool"
    RESOURCE = "resource"
    CAPABILITY = "capability"
    CREDENTIAL = "credential"
    POLICY = "policy"
    INCIDENT = "incident"
    TRUST_BOUNDARY = "trust_boundary"
    EVENT = "event"


class RelationType(str, Enum):
    """Edge kinds in the network graph."""

    ISSUED = "issued"
    DELEGATED = "delegated"
    ATTENUATED = "attenuated"
    REVOKED = "revoked"
    USES = "uses"
    ALLOWED = "allowed"
    DENIED = "denied"
    BOUND_TO = "bound_to"
    BELONGS_TO = "belongs_to"
    OWNS = "owns"
    ACCESSES = "accesses"
    PARENT_OF = "parent_of"
    TRUSTS = "trusts"
    ASSOCIATED_WITH = "associated_with"
    PART_OF = "part_of"
    LEADS_TO = "leads_to"


@dataclass(frozen=True)
class EvidenceRef:
    """One reference to a piece of recorded evidence."""

    artifact_id: str
    event_seq: Optional[int] = None
    bundle_id: Optional[str] = None
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact": self.artifact_id,
            "event_seq": self.event_seq,
            "bundle_id": self.bundle_id,
            "note": self.note,
        }

    def __str__(self) -> str:
        where = (
            f"#{self.event_seq}"
            if self.event_seq is not None
            else ""
        )
        return f"{self.artifact_id}{where}"


@dataclass(frozen=True)
class NetworkNode:
    """One entity in the agent security network."""

    id: str
    type: EntityType
    label: str
    basis: Provenance
    evidence: tuple[EvidenceRef, ...] = ()
    attributes: dict[str, Any] = field(
        default_factory=dict
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "label": self.label,
            "basis": self.basis.value,
            "evidence": [
                ref.to_dict() for ref in self.evidence
            ],
            "attributes": dict(self.attributes),
        }


@dataclass(frozen=True)
class NetworkEdge:
    """One relationship in the agent security network."""

    source: str
    target: str
    type: RelationType
    basis: Provenance
    evidence: tuple[EvidenceRef, ...] = ()
    attributes: dict[str, Any] = field(
        default_factory=dict
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "type": self.type.value,
            "basis": self.basis.value,
            "evidence": [
                ref.to_dict() for ref in self.evidence
            ],
            "attributes": dict(self.attributes),
        }


def entity_id(entity_type: EntityType, key: str) -> str:
    """Canonical network id for an entity. Names are scoped per type."""

    return f"{entity_type.value}:{key}"
