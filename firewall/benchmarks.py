"""v2.1 performance benchmarks (firewall.benchmarks).

Measures the critical paths of the autonomous defense layer so
bottlenecks are visible and regressions are caught:

* evidence graph append + verify (throughput),
* attack graph build + paths_to (graph scale),
* twin counterfactual (simulation cost),
* defense mesh evaluation over a large agent population,
* a2a authorization with a long delegation chain,
* capability2 policy evaluation.

Every benchmark returns a machine-readable report; the suite is
deliberately conservative (small enough to run in CI seconds, large
enough to expose O(n^2) behavior).
"""

from __future__ import annotations

import json
import time
from typing import Any, Callable, Optional

from firewall.a2a import AgentToAgent
from firewall.attackgraph import AttackGraph
from firewall.capability2 import Capability2
from firewall.defense import DefenseMesh
from firewall.evidence_graph import EvidenceGraph, KeyEvidenceSigner
from firewall.ident import IdentityRegistry
from firewall.network import AgentNetworkGraph
from firewall.network.model import (
    EntityType,
    NetworkEdge,
    NetworkNode,
    Provenance,
    RelationType,
    entity_id,
)
from firewall.twin import SecurityTwin


def _timed(fn: Callable[[], Any]) -> tuple[Any, float]:
    start = time.perf_counter()
    result = fn()
    elapsed = time.perf_counter() - start
    return result, elapsed


def benchmark_evidence_append(
    count: int = 200,
) -> dict[str, Any]:
    graph = EvidenceGraph(signer=KeyEvidenceSigner())

    def run() -> int:
        for i in range(count):
            graph.append(
                "observed" if i % 2 == 0 else "inference",
                f"subject-{i % 10}",
                "event",
                {"i": i},
            )
        return len(graph.events())

    result, elapsed = _timed(run)
    return {
        "name": "evidence_append",
        "events": result,
        "seconds": round(elapsed, 4),
        "events_per_second": round(result / elapsed, 1) if elapsed else None,
    }


def benchmark_evidence_verify(count: int = 200) -> dict[str, Any]:
    graph = EvidenceGraph(signer=KeyEvidenceSigner())
    for i in range(count):
        graph.append("observed", "x", "event", {"i": i})

    _, elapsed = _timed(graph.verify)
    return {
        "name": "evidence_verify",
        "events": count,
        "seconds": round(elapsed, 4),
        "events_per_second": round(count / elapsed, 1) if elapsed else None,
    }


def _large_network(agents: int = 60, caps_per_agent: int = 3) -> AgentNetworkGraph:
    g = AgentNetworkGraph()
    for i in range(agents):
        agent = f"agent-{i}"
        g._nodes[entity_id(EntityType.AGENT, agent)] = NetworkNode(
            entity_id(EntityType.AGENT, agent),
            EntityType.AGENT,
            agent,
            Provenance.OBSERVED,
        )
        for c in range(caps_per_agent):
            cap = f"cap-{i}-{c}"
            g._nodes[entity_id(EntityType.CAPABILITY, cap)] = NetworkNode(
                entity_id(EntityType.CAPABILITY, cap),
                EntityType.CAPABILITY,
                cap,
                Provenance.OBSERVED,
            )
            g._edges.append(
                NetworkEdge(
                    entity_id(EntityType.CAPABILITY, cap),
                    entity_id(EntityType.AGENT, agent),
                    RelationType.ISSUED,
                    Provenance.OBSERVED,
                )
            )
    return g


def benchmark_attack_graph(agents: int = 60) -> dict[str, Any]:
    network = _large_network(agents)

    def build() -> AttackGraph:
        return AttackGraph.from_network(network)

    graph, build_elapsed = _timed(build)

    def paths() -> int:
        return len(graph.paths_to("cap-0-0"))

    _, paths_elapsed = _timed(paths)

    return {
        "name": "attack_graph",
        "agents": agents,
        "nodes": len(graph.nodes()),
        "edges": len(graph.edges()),
        "build_seconds": round(build_elapsed, 4),
        "paths_seconds": round(paths_elapsed, 4),
    }


def benchmark_twin(agents: int = 40) -> dict[str, Any]:
    network = _large_network(agents)
    twin = SecurityTwin.from_network(network)
    twin.snapshot()

    def run() -> str:
        report = twin.compromise("agent-0")
        return report.kind

    result, elapsed = _timed(run)
    return {
        "name": "twin_compromise",
        "agents": agents,
        "seconds": round(elapsed, 4),
        "result": result,
    }


def benchmark_mesh_population(agents: int = 100) -> dict[str, Any]:
    reg = IdentityRegistry()
    for i in range(agents):
        reg.create(f"agent-{i}")
    mesh = DefenseMesh(reg)

    def run() -> int:
        for i in range(agents):
            mesh.evaluate(f"agent-{i}")
        return agents

    result, elapsed = _timed(run)
    return {
        "name": "mesh_evaluate_population",
        "agents": result,
        "seconds": round(elapsed, 4),
        "evaluations_per_second": round(result / elapsed, 1) if elapsed else None,
    }


def benchmark_a2a_chain(depth: int = 30) -> dict[str, Any]:
    reg = IdentityRegistry()
    for i in range(depth + 1):
        reg.create(f"n{i}")
    a2a = AgentToAgent(reg)
    root = a2a.establish(
        initiator="n0", responder="n1",
        permissions={"allowed_actions": ["read"]},
    )
    current = root
    for i in range(2, depth + 1):
        current = a2a.delegate(
            current, responder=f"n{i}",
            permissions={"allowed_actions": ["read"]},
        )

    def run() -> bool:
        return a2a.authorize(
            actor="n0", target=f"n{depth}", action="read"
        ).allowed

    result, elapsed = _timed(run)
    return {
        "name": "a2a_authorize_chain",
        "depth": depth,
        "allowed": result,
        "seconds": round(elapsed, 4),
    }


def benchmark_capability2(iterations: int = 1000) -> dict[str, Any]:
    cap = Capability2(
        "payments.send",
        constraints={
            "resource": "payments",
            "scope": "/prod",
            "action": ["send", "refund"],
            "identity": {"agent_id": "alice"},
            "lineage": {"max_depth": 2},
            "environment": {"env": "prod"},
        },
    )
    request = {
        "resource": "payments",
        "path": "/prod/invoice",
        "action": "send",
        "agent_id": "alice",
        "delegation_depth": 1,
        "env": "prod",
    }

    def run() -> int:
        allowed = 0
        for _ in range(iterations):
            if cap.evaluate(request)[0]:
                allowed += 1
        return allowed

    result, elapsed = _timed(run)
    return {
        "name": "capability2_evaluate",
        "iterations": iterations,
        "allowed": result,
        "seconds": round(elapsed, 4),
        "evaluations_per_second": round(iterations / elapsed, 1) if elapsed else None,
    }


BENCHMARKS: dict[str, Callable[..., dict[str, Any]]] = {
    "evidence_append": benchmark_evidence_append,
    "evidence_verify": benchmark_evidence_verify,
    "attack_graph": benchmark_attack_graph,
    "twin": benchmark_twin,
    "mesh": benchmark_mesh_population,
    "a2a_chain": benchmark_a2a_chain,
    "capability2": benchmark_capability2,
}


def run_benchmarks(
    names: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Run the requested benchmarks (all by default)."""

    selected = names or sorted(BENCHMARKS)
    results: dict[str, Any] = {}
    for name in selected:
        fn = BENCHMARKS.get(name)
        if fn is None:
            results[name] = {"error": f"unknown benchmark: {name}"}
            continue
        try:
            results[name] = fn()
        except Exception as exc:
            results[name] = {"error": f"{type(exc).__name__}: {exc}"}
    return {
        "benchmarks": results,
        "generated_at": time.time(),
    }


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entry: ``python -m firewall.benchmarks [name ...]``."""

    import sys

    names = list(argv or sys.argv[1:]) or None
    report = run_benchmarks(names)
    print(json.dumps(report, indent=2, sort_keys=True, default=str))
    failed = [
        name
        for name, result in report["benchmarks"].items()
        if "error" in result
    ]
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
