"""v1.9 CLI: Agent Security Network commands (clean rewrite).

Adds ``network`` (init/ingest/graph/correlate/simulate), ``detect``,
``attack-path``, and ``respond`` commands on top of the v1.8 CLI. All
security logic lives in :mod:`firewall.network`; these handlers are thin
argument translators with predictable exit codes:

0 success / meaningful positive result
1 meaningful negative result (no detections, no paths, unsafe simulation)
2 inputs could not be used
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Optional


def _fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 2


def _print_json(payload: Any) -> None:
    print(
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
            default=str,
        )
    )


def _load_network_state(state_path: str):
    from firewall.network.state import (
        NetworkStateError,
        build_index,
        load_state,
    )

    try:
        state = load_state(state_path)
        index, path_by_id = build_index(state)
    except NetworkStateError as exc:
        raise SystemExit(_fail(str(exc))) from exc

    return index, path_by_id


# ======================================================================
# network
# ======================================================================


def command_network_init(
    out: str,
    note: str,
) -> int:
    from firewall.network.state import (
        build_state,
        save_state,
    )

    state = build_state([])

    if note:
        state["note"] = note

    save_state(state, out)
    print(f"created network state {out}")

    return 0


def command_network_ingest(
    state_path: str,
    paths: list[str],
    *,
    out: Optional[str],
    allow_failed: bool,
    as_json: bool,
) -> int:
    """Verify + ingest artifacts and record them in the network state."""

    from firewall.network.correlation import CorrelationIndex
    from firewall.network.state import (
        build_state,
        load_state,
        save_state,
    )

    try:
        existing = (
            load_state(state_path)
            if Path(state_path).exists()
            else {
                "format": "agent-firewall-network-state",
                "version": 1,
                "artifacts": [],
            }
        )
    except Exception as exc:
        return _fail(f"cannot read state: {exc}")

    entries = list(existing.get("artifacts", []))
    known_paths = {
        entry.get("path") for entry in entries
    }

    index = CorrelationIndex(allow_failed=allow_failed)
    ingested: list[dict[str, Any]] = []

    for path in paths:
        if path in known_paths:
            continue

        target = Path(path)

        if not target.exists():
            print(
                f"warning: artifact not found: {target}",
                file=sys.stderr,
            )
            continue

        try:
            record = index.ingest_path(target)
        except Exception as exc:
            print(
                f"warning: could not ingest {target}: {exc}",
                file=sys.stderr,
            )
            continue

        entries.append(
            {
                "path": str(target),
                "artifact_id": record.artifact_id,
                "verification": record.verification,
                "agents": list(record.agents),
            }
        )

        ingested.append(
            {
                "path": str(target),
                "artifact_id": record.artifact_id,
                "verification": record.verification,
                "agents": list(record.agents),
            }
        )

    if not ingested and not entries:
        return _fail("nothing to ingest")

    save_state(
        build_state(entries),
        out if out is not None else state_path,
    )

    if as_json:
        _print_json(
            {
                "ingested": ingested,
                "total": len(entries),
            }
        )
        return 0

    for entry in ingested:
        print(
            f"  {entry['verification']:<11} "
            f"{entry['artifact_id']:<24} "
            f"{entry['path']}"
        )

    print(
        f"ingested {len(ingested)} artifact(s); "
        f"state has {len(entries)} total"
    )

    return 0


def command_network_graph(
    state_path: str,
    *,
    agent: Optional[str],
    why: Optional[str],
    reach: bool,
    who_can_reach: Optional[str],
    shared: Optional[str],
    agents: Optional[str],
    as_json: bool,
) -> int:
    index, _ = _load_network_state(state_path)
    graph = index.graph()

    if why is not None:
        if not agent:
            return _fail("--agent is required with --why")
        results = graph.why_can(agent, why)
        if as_json:
            _print_json(results)
            return 0
        if not results:
            print(f"{agent} has no recorded allow for {why}")
            return 1
        for result in results:
            print(
                f"{agent} could {why} "
                f"(reason: {result['reason']})"
            )
            for hop in result["authority_trail"]:
                print(
                    f"    {hop['relation']:<10} {hop['from_label']}"
                )
        return 0

    if reach:
        if not agent:
            return _fail("--agent is required with --reach")
        try:
            result = graph.reachable(agent)
        except Exception as exc:
            return _fail(str(exc))
        if as_json:
            _print_json(result.to_dict())
            return 0
        print(f"{agent} could reach:")
        for capability in result.capabilities:
            print(f"    capability: {capability}")
        for tool in result.tools:
            print(f"    tool: {tool}")
        for resource in result.resources:
            print(f"    resource: {resource}")
        for action in result.allowed_actions:
            print(f"    allowed action: {action}")
        return 0

    if who_can_reach is not None:
        results = graph.who_can_reach(who_can_reach)
        if as_json:
            _print_json(results)
            return 0
        if not results:
            print(f"no agent can reach {who_can_reach}")
            return 1
        print(f"agents that can reach {who_can_reach}:")
        for result in results:
            print(f"    {result['agent']}")
        return 0

    if shared is not None:
        if not agents:
            return _fail("--agents is required with --shared")
        agent_list = [
            name.strip()
            for name in agents.split(",")
            if name.strip()
        ]
        results = graph.shared_paths(agent_list, shared)
        if as_json:
            _print_json(results)
            return 0
        shared_agents = results[0]["agents"] if results else []
        if not shared_agents:
            print(
                f"no shared path to {shared} among the given agents"
            )
            return 1
        print(
            f"shared path to {shared}: "
            + ", ".join(shared_agents)
        )
        return 0

    if as_json:
        _print_json(graph.to_dict())
        return 0

    print(
        f"{len(graph.nodes())} nodes, "
        f"{len(graph.edges())} edges across "
        f"{len(index.verified_ids())} verified artifact(s)"
    )
    print("hint: --agent, --why <action>, --reach, "
          "--who-can-reach <resource>, --shared <resource> --agents a,b")

    return 0


def command_network_correlate(
    state_path: str,
    *,
    as_json: bool,
) -> int:
    index, _ = _load_network_state(state_path)
    bundles = index.bundles()

    if as_json:
        _print_json([bundle.to_dict() for bundle in bundles])
        return 0

    if not bundles:
        print("no correlation bundles found")
        return 1

    for bundle in bundles:
        print(
            f"{bundle.bundle_id}: {bundle.reason} "
            f"({len(bundle.artifact_ids)} artifacts, "
            f"statuses {', '.join(bundle.verification_statuses)})"
        )

    return 0


# ======================================================================
# detect
# ======================================================================


def command_detect(
    state_path: str,
    *,
    min_severity: str,
    as_json: bool,
) -> int:
    from firewall.network.behavior import analyze_index

    index, _ = _load_network_state(state_path)
    detections = analyze_index(index)

    rank = {
        "low": 0,
        "medium": 1,
        "high": 2,
        "critical": 3,
    }
    minimum = rank.get(min_severity, 0)

    selected = [
        detection
        for detection in detections
        if rank.get(detection.severity, 0) >= minimum
    ]

    if as_json:
        _print_json(
            [detection.to_dict() for detection in selected]
        )
        return 0

    if not selected:
        print("no detections")
        return 1

    for detection in selected:
        print(
            f"[{detection.severity}] {detection.title} "
            f"({detection.rule_id})"
        )
        print(f"    {detection.explanation}")
        print(
            "    agents: "
            + ", ".join(detection.agents or ("?",))
        )
        print(
            "    evidence: "
            + ", ".join(
                f"{entry.get('artifact')}#{entry.get('event_seq')}"
                for entry in detection.evidence[:5]
            )
        )
        print(f"    response: {detection.response}")

    return 0


# ======================================================================
# attack-path
# ======================================================================


def command_attack_path(
    state_path: str,
    *,
    agent: Optional[str],
    to: Optional[str],
    summary: bool,
    as_json: bool,
) -> int:
    from firewall.network.attack_path import AttackPathAnalyzer

    index, _ = _load_network_state(state_path)
    graph = index.graph()
    analyzer = AttackPathAnalyzer(graph)

    if summary:
        result = analyzer.summarize()
        if as_json:
            _print_json(result)
            return 0
        resources = result["sensitive_resources"]
        if not resources:
            print("no sensitive resources recorded")
            return 1
        for entry in resources:
            print(
                f"  {entry['resource']} "
                f"({entry['basis']}, {len(entry['evidence'])} evidence)"
            )
        return 0

    if to is None:
        return _fail("--to <target> (or --summary) is required")

    if agent is not None:
        path = analyzer.shortest_path_to(agent, to)
        if as_json:
            _print_json(
                path.to_dict() if path is not None else {"path": None}
            )
            return 0
        if path is None:
            print(f"no path from {agent} to {to}")
            return 1
        print(
            f"shortest path {agent} -> {to} "
            f"({path.status}, "
            f"dangerous={path.potentially_dangerous})"
        )
        for hop in path.hops:
            print(
                f"    {hop.edge:<10} {hop.target} "
                f"[{hop.status}]"
            )
        print("enabling capabilities: " + ", ".join(
            path.enabling_capabilities or ("none",)
        ))
        for suggestion in analyzer.break_path(path):
            print(
                f"    break: {suggestion['action']} "
                f"{suggestion['capability']} -- "
                f"{suggestion['effect']}"
            )
        return 0

    paths = analyzer.paths_to(to)
    if as_json:
        _print_json([path.to_dict() for path in paths])
        return 0
    if not paths:
        print(f"no recorded paths to {to}")
        return 1
    print(f"{len(paths)} path(s) to {to}:")
    for path in paths[:10]:
        print(
            f"  {path.source} -> {to} "
            f"({len(path.hops)} hops, {path.status}, "
            f"dangerous={path.potentially_dangerous})"
        )
    return 0


# ======================================================================
# simulate
# ======================================================================


def command_simulate_network(
    state_path: str,
    scenario_path: str,
    *,
    as_json: bool,
) -> int:
    from firewall.network import (
        Scenario,
        Simulator,
        SimulatorError,
    )

    index, _ = _load_network_state(state_path)
    graph = index.graph()

    try:
        scenario_data = json.loads(
            Path(scenario_path).read_text(encoding="utf-8")
        )
        scenario = Scenario(
            scenario_id=(
                scenario_data.get("scenario_id") or scenario_path
            ),
            kind=scenario_data.get("kind", "compromised_agent"),
            title=scenario_data.get("title") or scenario_path,
            agent=scenario_data.get("agent"),
            added_capabilities=tuple(
                scenario_data.get("added_capabilities") or ()
            ),
            removed_capabilities=tuple(
                scenario_data.get("removed_capabilities") or ()
            ),
            policy=dict(scenario_data.get("policy") or {}),
            containment=scenario_data.get("containment", "none"),
            added_tools=tuple(
                scenario_data.get("added_tools") or ()
            ),
        )
    except OSError as exc:
        return _fail(f"cannot read scenario: {exc}")
    except (SimulatorError, ValueError) as exc:
        return _fail(f"invalid scenario: {exc}")

    simulator = Simulator(graph)
    report = simulator.simulate(scenario)

    if as_json:
        print(report.to_json())
        return 0

    print(report.text())
    return 0


# ======================================================================
# respond
# ======================================================================


def command_respond(
    state_path: str,
    *,
    rule: Optional[str],
    severity: Optional[str],
    policy_path: Optional[str],
    as_json: bool,
) -> int:
    """Evaluate the current detections against a response policy and
    apply the resulting responses through the containment controller."""

    from firewall.containment import ContainmentController
    from firewall.network import (
        ResponseController,
        ResponseRule,
    )
    from firewall.network.behavior import analyze_index
    from firewall.risk_context import RiskContext
    from firewall.sdk import FirewallSDK

    index, _ = _load_network_state(state_path)

    if policy_path is not None:
        try:
            policy_data = json.loads(
                Path(policy_path).read_text(encoding="utf-8")
            )
            rules = [
                ResponseRule(
                    rule_id=entry["rule_id"],
                    min_severity=entry.get(
                        "min_severity", "medium"
                    ),
                    stage=entry.get("stage", "observe"),
                    auto_approve=bool(
                        entry.get("auto_approve", False)
                    ),
                )
                for entry in policy_data.get("rules", [])
                if isinstance(entry, dict)
                and entry.get("rule_id")
            ]
        except (OSError, ValueError) as exc:
            return _fail(f"cannot read policy: {exc}")
    else:
        rules = [
            ResponseRule(
                rule_id="repeated_denials",
                min_severity="medium",
                stage="restrict",
            ),
            ResponseRule(
                rule_id="credential_shaped_access",
                min_severity="high",
                stage="quarantine",
            ),
        ]

    # The response controller needs a live SDK + containment controller.
    # The CLI uses a fresh in-memory workspace: containment actions
    # against it demonstrate the response pipeline without touching any
    # real agent state.
    workspace = FirewallSDK(risk_context=RiskContext())
    workspace.generate_key("response-cli")
    containment = ContainmentController(
        workspace,
        authorizer=lambda: True,
    )
    controller = ResponseController(containment)

    for response_rule in rules:
        controller.add_rule(response_rule)

    detections = analyze_index(index)

    if rule is not None:
        detections = [
            detection
            for detection in detections
            if detection.rule_id == rule
        ]

    if severity is not None:
        rank = {
            "low": 0,
            "medium": 1,
            "high": 2,
            "critical": 3,
        }
        minimum = rank.get(severity, 0)
        detections = [
            detection
            for detection in detections
            if rank.get(detection.severity, 0) >= minimum
        ]

    records = []

    for detection in detections:
        try:
            records.append(
                controller.respond(detection, actor="cli")
            )
        except Exception as exc:
            records.append(
                {
                    "rule_id": detection.rule_id,
                    "error": str(exc),
                }
            )

    if as_json:
        _print_json(
            {
                "records": [
                    record.to_dict()
                    if hasattr(record, "to_dict")
                    else record
                    for record in records
                ],
                "snapshot": controller.snapshot(),
            }
        )
        return 0

    if not records:
        print("no detections matched the policy")
        return 1

    for record in records:
        if isinstance(record, dict) and "error" in record:
            print(
                f"  [error] {record['rule_id']}: {record['error']}"
            )
        else:
            print(
                f"  {record.stage:<10} {record.agent or '?'} "
                f"({record.rule_id}) -- {record.reason}"
            )

    return 0
