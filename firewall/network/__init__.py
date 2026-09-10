"""The Agent Security Network (v1.9).

Cross-agent security intelligence over recorded, verified evidence:

* :mod:`firewall.network.model` -- entities, relations, and the
  provenance basis (observed / derived / inferred / simulated) that is
  never conflated.
* :mod:`firewall.network.graph` -- merged, evidence-backed network graph
  with reachability, why-can, who-can-reach, shortest-path, and
  shared-path queries.
* :mod:`firewall.network.correlation` -- ingest + verify + correlate
  multiple artifacts into bundles (correlation ids, incidents, agents,
  provenance).
* :mod:`firewall.network.behavior` -- deterministic, explainable
  detection rules (repeated denials, capability escalation, unexpected
  delegation, structural denials, credential-shaped access).
* :mod:`firewall.network.attack_path` -- attack-path discovery with an
  explicit status taxonomy and break-path suggestions.
* :mod:`firewall.network.simulator` -- isolated scenario simulation
  (compromised agent, stolen capability, changed policy, ...).
* :mod:`firewall.network.response` -- policy-driven graduated response
  (observe -> warn -> restrict -> quarantine -> contain) with human
  approval for high-impact stages.

Everything derives from verified artifacts; nothing here authorizes
anything, and nothing here bypasses the existing authorization
pipeline.
"""

from firewall.network.attack_path import (
    AttackPath,
    AttackPathAnalyzer,
    AttackPathError,
    PathHop,
)
from firewall.network.behavior import (
    BehaviorError,
    Detection,
    analyze_artifacts,
    analyze_index,
)
from firewall.network.correlation import (
    CorrelationBundle,
    CorrelationError,
    CorrelationIndex,
    IngestedArtifact,
)
from firewall.network.graph import (
    AgentNetworkGraph,
    NetworkError,
    ReachabilityResult,
    extract_network_entities,
)
from firewall.network.model import (
    EntityType,
    EvidenceRef,
    NetworkEdge,
    NetworkNode,
    Provenance,
    RelationType,
    entity_id,
)
from firewall.network.response import (
    APPROVAL_REQUIRED_STAGES,
    RESPONSE_STAGES,
    ResponseController,
    ResponseError,
    ResponseRecord,
    ResponseRule,
)
from firewall.network.simulator import (
    SCENARIO_KINDS,
    Scenario,
    ScenarioReport,
    Simulator,
    SimulatorError,
)

__all__ = [
    "APPROVAL_REQUIRED_STAGES",
    "AgentNetworkGraph",
    "AttackPath",
    "AttackPathAnalyzer",
    "AttackPathError",
    "BehaviorError",
    "CorrelationBundle",
    "CorrelationError",
    "CorrelationIndex",
    "Detection",
    "EntityType",
    "EvidenceRef",
    "IngestedArtifact",
    "NetworkEdge",
    "NetworkError",
    "NetworkNode",
    "PathHop",
    "Provenance",
    "ReachabilityResult",
    "RESPONSE_STAGES",
    "RelationType",
    "ResponseController",
    "ResponseError",
    "ResponseRecord",
    "ResponseRule",
    "SCENARIO_KINDS",
    "Scenario",
    "ScenarioReport",
    "Simulator",
    "SimulatorError",
    "analyze_artifacts",
    "analyze_index",
    "entity_id",
    "extract_network_entities",
]
