"""v2.1 CLI commands (firewall.cli_v21).

Adds defense, delegate (a2a zero trust), capability (capability
firewall 2.0), attack-graph, twin, evidence, immune, research, and
recover commands on top of the v2.0 CLI. All logic lives in the v2.1
modules; these handlers are thin translators with the established exit
codes (0 / 1 / 2).
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


def _load_json(path: str) -> dict[str, Any]:
    try:
        payload = json.loads(
            Path(path).read_text(encoding="utf-8")
        )
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def _write_json(path: str, payload: Any) -> None:
    target = Path(path)
    if target.parent and str(target.parent) != ".":
        target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(payload, indent=2, sort_keys=True, default=str)
        + "\n",
        encoding="utf-8",
    )


def _registry(registry_path: str, passphrase: Optional[str]):
    from firewall.ident import IdentityRegistry

    return IdentityRegistry(
        state_path=registry_path,
        passphrase=(
            passphrase.encode("utf-8")
            if passphrase is not None
            else None
        ),
    )


def _load_network_state(state_path: str):
    from firewall.network.state import (
        NetworkStateError,
        build_index,
        load_state,
    )

    try:
        state = load_state(state_path)
        index, _ = build_index(state)
    except NetworkStateError as exc:
        raise SystemExit(_fail(str(exc))) from exc
    return index.graph()


# ======================================================================
# defense (real-time defense mesh)
# ======================================================================


def _mesh(
    registry_path: str,
    passphrase: Optional[str],
    state_path: Optional[str] = None,
):
    """Build a defense mesh over the identity registry.

    The CLI attaches a real SDK so capability evaluation and
    quarantine actually exercise the v2.0 pipeline: every registered
    identity receives a scoped operating capability from the SDK's own
    key. Identity and capability stay separate - the capability is a
    live-authority fact the mesh reports, never an identity-derived
    right.
    """

    from firewall.defense import DefenseMesh
    from firewall.posture import PostureEngine
    from firewall.sdk import FirewallSDK

    reg = _registry(registry_path, passphrase)
    sdk = FirewallSDK()
    sdk.generate_key("defense-cli-key")
    for identity in reg.all():
        if identity.status == "active":
            try:
                sdk.issue(
                    agent=identity.agent_id,
                    capability=f"{identity.agent_id}.operate",
                    constraints={"scope": "cli-demo"},
                )
            except Exception:
                pass
    mesh = DefenseMesh(
        reg,
        posture=PostureEngine(),
        state_path=state_path,
    )
    mesh.attach_sdk(sdk)
    return reg, mesh


def command_defense_evaluate(
    registry_path: str,
    agent: str,
    *,
    state_path: Optional[str] = None,
    passphrase: Optional[str],
    as_json: bool,
) -> int:
    reg, mesh = _mesh(registry_path, passphrase, state_path)
    try:
        state = mesh.evaluate(agent)
    except Exception as exc:
        return _fail(str(exc))
    finally:
        reg.close()

    if as_json:
        _print_json(state.to_dict())
        return 0

    print(
        f"{state.agent}: state={state.state} "
        f"identity_verified={state.identity_verified} "
        f"trust={state.trust_score:.2f} posture={state.posture} "
        f"capability_ok={state.capability_ok}"
    )
    print(f"  reason: {state.reason}")
    return 0 if state.state != "retired" else 1


def command_defense_quarantine(
    registry_path: str,
    agent: str,
    *,
    state_path: Optional[str] = None,
    reason: str,
    actor: str,
    passphrase: Optional[str],
    as_json: bool,
) -> int:
    reg, mesh = _mesh(registry_path, passphrase, state_path)
    try:
        transition = mesh.quarantine(agent, actor=actor, reason=reason)
    except Exception as exc:
        return _fail(str(exc))
    finally:
        reg.close()

    if as_json:
        _print_json(transition.to_dict())
        return 0

    print(
        f"quarantined {agent}: "
        f"{transition.from_state} -> {transition.to_state}"
    )
    return 0


def command_defense_recover(
    registry_path: str,
    agent: str,
    *,
    state_path: Optional[str] = None,
    reason: str,
    actor: str,
    passphrase: Optional[str],
    as_json: bool,
) -> int:
    reg, mesh = _mesh(registry_path, passphrase, state_path)
    try:
        transition = mesh.recover(agent, actor=actor, reason=reason)
    except Exception as exc:
        return _fail(str(exc))
    finally:
        reg.close()

    if as_json:
        _print_json(transition.to_dict())
        return 0

    print(
        f"recovery begun for {agent}: "
        f"{transition.from_state} -> {transition.to_state}"
    )
    return 0


def command_defense_reenter(
    registry_path: str,
    agent: str,
    *,
    state_path: Optional[str] = None,
    reason: str,
    actor: str,
    passphrase: Optional[str],
    as_json: bool,
) -> int:
    reg, mesh = _mesh(registry_path, passphrase, state_path)
    try:
        transition = mesh.reenter(agent, actor=actor, reason=reason)
    except Exception as exc:
        return _fail(str(exc))
    finally:
        reg.close()

    if as_json:
        _print_json(transition.to_dict())
        return 0

    print(
        f"re-entered {agent}: "
        f"{transition.from_state} -> {transition.to_state}"
    )
    return 0


def command_defense_state(
    registry_path: str,
    agent: Optional[str],
    *,
    state_path: Optional[str] = None,
    passphrase: Optional[str],
    as_json: bool,
) -> int:
    reg, mesh = _mesh(registry_path, passphrase, state_path)
    try:
        for candidate in reg.agent_ids():
            mesh.evaluate(candidate)
        if agent is not None:
            records = [mesh.state(agent)]
        else:
            records = list(mesh.all_states().values())
    finally:
        reg.close()

    if as_json:
        _print_json(records)
        return 0

    for record in records:
        print(f"{record['agent']:<20} {record['state']}")
        for transition in record["transitions"]:
            print(
                f"    {transition['from']} -> {transition['to']} "
                f"({transition['actor']}: {transition['reason'][:60]})"
            )
    return 0


# ======================================================================
# delegate (agent-to-agent zero trust)
# ======================================================================


def _a2a(
    registry_path: str,
    state_path: str,
    passphrase: Optional[str],
):
    from firewall.a2a import AgentToAgent

    reg = _registry(registry_path, passphrase)
    a2a = AgentToAgent(reg, state_path=state_path)
    return reg, a2a


def command_delegate_establish(
    registry_path: str,
    state_path: str,
    *,
    initiator: str,
    responder: str,
    permissions: Optional[str],
    ttl: Optional[float],
    passphrase: Optional[str],
    as_json: bool,
) -> int:
    reg, a2a = _a2a(registry_path, state_path, passphrase)
    try:
        perms = json.loads(permissions) if permissions else None
        rel = a2a.establish(
            initiator=initiator,
            responder=responder,
            permissions=perms,
            ttl=ttl,
        )
    except Exception as exc:
        return _fail(str(exc))
    finally:
        reg.close()
        a2a.close()

    if as_json:
        _print_json(rel.to_dict())
        return 0

    print(
        f"established {rel.relationship_id}: "
        f"{rel.initiator} -> {rel.responder}"
    )
    print(f"  permissions: {json.dumps(rel.permissions)}")
    return 0


def command_delegate_grant(
    registry_path: str,
    state_path: str,
    *,
    relationship: str,
    responder: str,
    permissions: Optional[str],
    passphrase: Optional[str],
    as_json: bool,
) -> int:
    reg, a2a = _a2a(registry_path, state_path, passphrase)
    try:
        parent = a2a.get(relationship)
        if parent is None:
            return _fail(f"unknown relationship: {relationship}")
        perms = json.loads(permissions) if permissions else None
        child = a2a.delegate(
            parent,
            responder=responder,
            permissions=perms,
        )
    except Exception as exc:
        return _fail(str(exc))
    finally:
        reg.close()
        a2a.close()

    if as_json:
        _print_json(child.to_dict())
        return 0

    print(
        f"delegated {relationship} -> {child.relationship_id} "
        f"for {responder}"
    )
    print(f"  effective: {json.dumps(child.permissions)}")
    return 0


def command_delegate_revoke(
    registry_path: str,
    state_path: str,
    *,
    relationship: str,
    reason: str,
    passphrase: Optional[str],
    as_json: bool,
) -> int:
    reg, a2a = _a2a(registry_path, state_path, passphrase)
    try:
        count = a2a.revoke(relationship, reason=reason)
    except Exception as exc:
        return _fail(str(exc))
    finally:
        reg.close()
        a2a.close()

    if as_json:
        _print_json({"relationship": relationship, "revoked": count})
        return 0

    print(f"revoked {relationship} (recursively revoked {count})")
    return 0


def command_delegate_teardown(
    registry_path: str,
    state_path: str,
    *,
    a: str,
    b: str,
    reason: str,
    passphrase: Optional[str],
    as_json: bool,
) -> int:
    reg, a2a = _a2a(registry_path, state_path, passphrase)
    try:
        count = a2a.teardown(a, b, reason=reason)
    except Exception as exc:
        return _fail(str(exc))
    finally:
        reg.close()
        a2a.close()

    if as_json:
        _print_json({"a": a, "b": b, "revoked": count})
        return 0

    print(f"tore down relationships between {a} and {b} ({count})")
    return 0


def command_delegate_authorize(
    registry_path: str,
    state_path: str,
    *,
    actor: str,
    target: str,
    action: str,
    request: Optional[str],
    passphrase: Optional[str],
    as_json: bool,
) -> int:
    reg, a2a = _a2a(registry_path, state_path, passphrase)
    try:
        req = json.loads(request) if request else None
        decision = a2a.authorize(
            actor=actor, target=target, action=action, request=req
        )
    finally:
        reg.close()
        a2a.close()

    if as_json:
        _print_json(decision.to_dict())
        return 0

    verdict = "ALLOWED" if decision.allowed else "DENIED"
    if decision.allowed and not decision.is_canonical:
        # The mesh this command builds has no ``sdk_provider``, so an
        # allow here established a relationship and nothing more. Saying
        # only "ALLOWED" would let a reader -- or a shell script reading
        # the exit code -- take it for an authorization. Exit status stays
        # 0 because the question asked was answered affirmatively; what
        # changes is that the answer no longer overstates itself.
        verdict = "ALLOWED (relationship only)"

    print(f"{actor} -> {target} {action}: {verdict}")
    print(f"  {decision.reason}")
    if decision.allowed and not decision.is_canonical:
        print(
            "  basis: relationship_only -- this is a relationship check, "
            "not an authorization."
        )
        print(
            "  No FirewallSDK.authorize() decision was made; do not "
            "enforce on this result."
        )
    return 0 if decision.allowed else 1


def command_delegate_graph(
    registry_path: str,
    state_path: str,
    passphrase: Optional[str],
    as_json: bool,
) -> int:
    reg, a2a = _a2a(registry_path, state_path, passphrase)
    try:
        graph = a2a.trust_graph()
    finally:
        reg.close()
        a2a.close()

    if as_json:
        _print_json(graph)
        return 0

    edges = graph["relationships"]
    if not edges:
        print("no active relationships")
        return 1
    for edge in edges:
        print(
            f"{edge['initiator']:<16} -> {edge['responder']:<16} "
            f"{edge['relationship_id']} "
            f"expires={edge.get('expires_at')}"
        )
    return 0


# ======================================================================
# capability (capability firewall 2.0)
# ======================================================================


def _capability_policy(policy_path: str):
    from firewall.capability2 import Capability2

    payload = _load_json(policy_path)
    return Capability2.from_dict(payload)


def command_capability_eval(
    policy_path: str,
    request: str,
    as_json: bool,
) -> int:
    try:
        cap = _capability_policy(policy_path)
        req = json.loads(request)
        if not isinstance(req, dict):
            raise ValueError("request must be a JSON object")
        allowed, reason = cap.evaluate(req)
    except Exception as exc:
        return _fail(str(exc))

    if as_json:
        _print_json({"allowed": allowed, "reason": reason})
        return 0

    print(f"{'ALLOWED' if allowed else 'DENIED'}: {reason}")
    return 0 if allowed else 1


def command_capability_attenuate(
    policy_path: str,
    *,
    out: str,
    narrowing: Optional[str],
    as_json: bool,
) -> int:
    try:
        cap = _capability_policy(policy_path)
        changes = json.loads(narrowing) if narrowing else {}
        if not isinstance(changes, dict):
            raise ValueError("--narrowing must be a JSON object")
        child = cap.attenuate(**changes)
        if not child.is_narrower_than(cap):
            raise ValueError("attenuation produced a widening capability")
        _write_json(out, child.to_dict())
    except Exception as exc:
        return _fail(str(exc))

    if as_json:
        _print_json(child.to_dict())
        return 0

    print(f"wrote attenuated capability to {out}")
    print(f"  constraints: {json.dumps(child.constraints)}")
    return 0


def command_capability_delegate(
    policy_path: str,
    *,
    out: str,
    narrowing: Optional[str],
    as_json: bool,
) -> int:
    try:
        cap = _capability_policy(policy_path)
        changes = json.loads(narrowing) if narrowing else {}
        if not isinstance(changes, dict):
            raise ValueError("--narrowing must be a JSON object")
        child = cap.delegate(**changes)
        if not child.is_narrower_than(cap):
            raise ValueError("delegation produced a widening capability")
        _write_json(out, child.to_dict())
    except Exception as exc:
        return _fail(str(exc))

    if as_json:
        _print_json(child.to_dict())
        return 0

    print(f"wrote delegated capability to {out} (parent={child.parent})")
    return 0


# ======================================================================
# attack-graph
# ======================================================================


def command_attackgraph_build(
    state_path: str,
    *,
    out: str,
    as_json: bool,
) -> int:
    from firewall.attackgraph import AttackGraph

    try:
        graph = AttackGraph.from_network(_load_network_state(state_path))
        _write_json(out, graph.to_dict())
    except Exception as exc:
        return _fail(str(exc))

    if as_json:
        _print_json(graph.to_dict())
        return 0

    print(f"wrote attack graph to {out}")
    print(
        f"  {len(graph.nodes())} nodes, {len(graph.edges())} edges"
    )
    return 0


def _attack_graph_from(path: str):
    from firewall.attackgraph import AttackGraph

    payload = _load_json(path)
    graph = AttackGraph()
    for node in payload.get("nodes", []):
        graph.add_node(
            node["id"],
            node["type"],
            node["label"],
            basis=node.get("basis", "observed"),
            evidence=node.get("evidence", []),
            attributes=node.get("attributes", {}),
        )
    for edge in payload.get("edges", []):
        graph.add_edge(
            edge["source"],
            edge["target"],
            edge["type"],
            basis=edge.get("basis", "observed"),
            evidence=edge.get("evidence", []),
            attributes=edge.get("attributes", {}),
        )
    return graph


def command_attackgraph_paths(
    graph_path: str,
    *,
    target: str,
    max_hops: int,
    as_json: bool,
) -> int:
    try:
        graph = _attack_graph_from(graph_path)
        paths = graph.paths_to(target, max_hops=max_hops)
    except Exception as exc:
        return _fail(str(exc))

    if as_json:
        _print_json([p.to_dict() for p in paths])
        return 0

    if not paths:
        print(f"no paths to {target}")
        return 1
    for path in paths:
        print(
            f"{path.source} -> {path.target} "
            f"[{path.basis}] {len(path.hops)} hops"
        )
        for hop in path.hops:
            print(
                f"    {hop['edge']:<12} {hop['from_label']} -> "
                f"{hop['to_label']} [{hop['basis']}]"
            )
    return 0


def command_attackgraph_findings(
    graph_path: str,
    as_json: bool,
) -> int:
    try:
        graph = _attack_graph_from(graph_path)
        findings = graph.escalation_paths()
        chokepoints = graph.chokepoints()
    except Exception as exc:
        return _fail(str(exc))

    if as_json:
        _print_json(
            {
                "escalation_paths": [f.to_dict() for f in findings],
                "chokepoints": chokepoints,
            }
        )
        return 0

    print(f"escalation paths: {len(findings)}")
    for finding in findings[:10]:
        print(f"  [{finding.basis}] {finding.description[:100]}")
    print(f"chokepoints: {len(chokepoints)}")
    for chokepoint in chokepoints[:5]:
        print(
            f"  {chokepoint['label']}: {chokepoint['paths']} paths"
        )
    return 0


def command_attackgraph_summarize(
    graph_path: str,
    as_json: bool,
) -> int:
    try:
        graph = _attack_graph_from(graph_path)
        summary = graph.summarize()
    except Exception as exc:
        return _fail(str(exc))

    if as_json:
        _print_json(summary)
        return 0

    print(
        f"{summary['nodes']} nodes, {summary['edges']} edges, "
        f"{len(summary['agents'])} agents"
    )
    print("sensitive resources:", ", ".join(summary["sensitive_resources"]))
    return 0


# ======================================================================
# twin (security digital twin)
# ======================================================================


def command_twin_counterfactual(
    state_path: str,
    *,
    kind: str,
    agent: Optional[str],
    capability: Optional[str],
    tool: Optional[str],
    grantor: Optional[str],
    grantee: Optional[str],
    credential: Optional[str],
    as_json: bool,
) -> int:
    from firewall.twin import SecurityTwin

    try:
        twin = SecurityTwin.from_network(_load_network_state(state_path))
        if kind == "compromised_agent":
            if not agent:
                return _fail("--agent is required for compromised_agent")
            report = twin.compromise(agent)
        elif kind == "revoked_capability":
            if not agent or not capability:
                return _fail(
                    "--agent and --capability are required for "
                    "revoked_capability"
                )
            report = twin.revoke_capability(agent, capability)
        elif kind == "untrusted_tool":
            if not tool:
                return _fail("--tool is required for untrusted_tool")
            report = twin.untrust_tool(tool)
        elif kind == "delegated_authority":
            if not grantor or not grantee:
                return _fail(
                    "--grantor and --grantee are required for "
                    "delegated_authority"
                )
            report = twin.delegate(grantor, grantee)
        elif kind == "exposed_credential":
            if not agent:
                return _fail("--agent is required for exposed_credential")
            report = twin.expose_credential(
                agent, credential=credential or "credential"
            )
        else:
            return _fail(
                f"unknown counterfactual kind: {kind} "
                "(compromised_agent, revoked_capability, untrusted_tool, "
                "delegated_authority, exposed_credential)"
            )
    except Exception as exc:
        return _fail(str(exc))

    if as_json:
        _print_json(report.to_dict())
        return 0

    print(f"{report.kind}: {report.title} [{report.basis}]")
    print(f"  {report.description}")
    for delta in report.reachability_deltas:
        print(
            f"  delta {delta.agent}: "
            f"+{len(delta.added_capabilities)} caps "
            f"-{len(delta.removed_capabilities)} caps "
            f"+{len(delta.added_resources)} resources "
            f"(risk delta {delta.risk_delta()})"
        )
    for opportunity in report.containment_opportunities:
        print(
            f"  contain {opportunity['contain']}: "
            f"{opportunity['effect'][:90]}"
        )
    return 0


# ======================================================================
# evidence (cryptographic evidence graph)
# ======================================================================


def _evidence(
    state_path: str,
    registry_path: Optional[str],
    signer_agent: Optional[str],
    passphrase: Optional[str],
):
    from firewall.evidence_graph import (
        EvidenceGraph,
        IdentityEvidenceSigner,
    )

    if registry_path and signer_agent:
        reg = _registry(registry_path, passphrase)
        signer = IdentityEvidenceSigner(reg, signer_agent)
        return reg, EvidenceGraph(signer=signer, state_path=state_path)
    return None, EvidenceGraph(state_path=state_path)


def command_evidence_append(
    state_path: str,
    *,
    kind: str,
    subject: str,
    event_type: str,
    payload: Optional[str],
    registry_path: Optional[str],
    signer_agent: Optional[str],
    passphrase: Optional[str],
    as_json: bool,
) -> int:
    reg, graph = _evidence(
        state_path, registry_path, signer_agent, passphrase
    )
    try:
        body = json.loads(payload) if payload else {}
        if not isinstance(body, dict):
            raise ValueError("--payload must be a JSON object")
        event = graph.append(
            kind, subject, event_type, body
        )
    except Exception as exc:
        return _fail(str(exc))
    finally:
        if reg is not None:
            reg.close()
        graph.close()

    if as_json:
        _print_json(event.to_dict())
        return 0

    print(
        f"appended #{event.seq} {event.kind} {event.subject} "
        f"{event.event_type}"
    )
    print(f"  event_id: {event.event_id}")
    return 0


def command_evidence_verify(
    state_path: str,
    *,
    registry_path: Optional[str],
    signer_agent: Optional[str],
    passphrase: Optional[str],
    as_json: bool,
) -> int:
    reg, graph = _evidence(
        state_path, registry_path, signer_agent, passphrase
    )
    try:
        result = graph.verify()
    finally:
        if reg is not None:
            reg.close()
        graph.close()

    if as_json:
        _print_json(result)
        return 0

    print(f"status: {result['status']} ({result['events']} events)")
    for problem in result["problems"][:10]:
        print(f"  - {problem['type']} at seq {problem.get('seq')}")
    return 0 if result["status"] == "verified" else 2


def command_evidence_timeline(
    state_path: str,
    *,
    subject: str,
    registry_path: Optional[str],
    signer_agent: Optional[str],
    passphrase: Optional[str],
    as_json: bool,
) -> int:
    reg, graph = _evidence(
        state_path, registry_path, signer_agent, passphrase
    )
    try:
        timeline = graph.timeline(subject)
    finally:
        if reg is not None:
            reg.close()
        graph.close()

    if as_json:
        _print_json(timeline)
        return 0

    if not timeline:
        print(f"no evidence for {subject}")
        return 1
    for entry in timeline:
        print(
            f"  #{entry['seq']:<4} {entry['kind']:<10} "
            f"{entry['event_type']:<20} {entry['event_id'][:16]}"
        )
    return 0


def command_evidence_promote(
    state_path: str,
    *,
    event_id: str,
    reason: str,
    registry_path: Optional[str],
    signer_agent: Optional[str],
    passphrase: Optional[str],
    as_json: bool,
) -> int:
    reg, graph = _evidence(
        state_path, registry_path, signer_agent, passphrase
    )
    try:
        event = graph.promote(event_id, reason=reason)
    except Exception as exc:
        return _fail(str(exc))
    finally:
        if reg is not None:
            reg.close()
        graph.close()

    if as_json:
        _print_json(event.to_dict())
        return 0

    print(
        f"promoted {event_id} to observed evidence as #{event.seq}"
    )
    return 0


# ======================================================================
# immune (agent immune system)
# ======================================================================


def _immune_workspace():
    """A self-contained demo workspace: fresh identities, SDK, mesh,
    containment, and evidence graph."""

    from firewall.containment import ContainmentController
    from firewall.defense import DefenseMesh
    from firewall.evidence_graph import KeyEvidenceSigner, EvidenceGraph
    from firewall.ident import IdentityRegistry
    from firewall.immune import ImmuneSystem
    from firewall.posture import PostureEngine
    from firewall.sdk import FirewallSDK

    reg = IdentityRegistry()
    sdk = FirewallSDK()
    posture = PostureEngine()
    recorder = None
    controller = ContainmentController(
        sdk, recorder=recorder, authorizer=lambda: True
    )
    mesh = DefenseMesh(reg, posture=posture, containment=controller)
    mesh.attach_sdk(sdk)
    evidence = EvidenceGraph(signer=KeyEvidenceSigner())
    immune = ImmuneSystem(
        mesh,
        posture=posture,
        containment=controller,
        evidence_graph=evidence,
        approver=lambda stage, agent: True,
    )
    return immune, reg, sdk


def command_immune_demo(
    policy_path: Optional[str],
    as_json: bool,
) -> int:
    from firewall.immune import ImmunePolicy, ImmuneRule

    immune, reg, sdk = _immune_workspace()

    try:
        reg.create("agent-demo")
        sdk.generate_key("demo-key")
        sdk.issue(
            agent="agent-demo",
            capability="payments.send",
            constraints={"amount_max": 100},
        )

        if policy_path:
            payload = _load_json(policy_path)
            rules = tuple(
                ImmuneRule(
                    rule_id=entry["rule_id"],
                    stage=entry.get("stage", "observe"),
                    min_severity=entry.get("min_severity", "medium"),
                    auto_approve=bool(entry.get("auto_approve", False)),
                    description=entry.get("description", ""),
                )
                for entry in payload.get("rules", [])
            )
            immune.set_policy(ImmunePolicy(rules=rules))
        else:
            immune.set_policy(
                ImmunePolicy(
                    rules=(
                        ImmuneRule(
                            "compromised_posture",
                            stage="quarantine",
                            min_severity="high",
                            auto_approve=False,
                        ),
                    )
                )
            )

        from firewall.immune import ImmuneSignal

        immune.observe(
            ImmuneSignal(
                "agent-demo",
                "authorization_denial",
                "denied request 1",
                "medium",
            )
        )
        immune.observe(
            ImmuneSignal(
                "agent-demo",
                "authorization_denial",
                "denied request 2",
                "medium",
            )
        )
        immune.observe(
            ImmuneSignal(
                "agent-demo",
                "authorization_denial",
                "denied request 3",
                "medium",
            )
        )

        result = immune.run_cycle(agent="agent-demo")
    except Exception as exc:
        return _fail(str(exc))

    if as_json:
        _print_json(result)
        return 0

    transcript = result["cycle"]
    print(f"cycle: {len(transcript)} detection(s)")
    for entry in transcript:
        detection = entry["detection"]
        action = entry["action"]
        print(
            f"  {detection['rule_id']:<22} "
            f"{detection['severity']:<8} "
            f"action={action['action']}/{action['outcome']}"
        )
        print(f"    {detection['detail'][:90]}")
        print(f"    verification: {entry['verification']['reason'][:90]}")
    return 0


def command_immune_state(as_json: bool) -> int:
    """Show the immune system's policy shape and loop contract."""

    from firewall.immune import CONTAINMENT_STAGES

    payload = {
        "loop": [
            "observe",
            "detect",
            "reason",
            "simulate",
            "contain",
            "recover",
            "verify",
        ],
        "stages": list(CONTAINMENT_STAGES),
        "authorization_model": (
            "the reasoning system is advisory only; execution requires "
            "a deterministic immune policy rule and (for high-impact "
            "stages) human approval"
        ),
    }

    if as_json:
        _print_json(payload)
        return 0

    print("immune loop:", " -> ".join(payload["loop"]))
    print("stages:", ", ".join(payload["stages"]))
    print(payload["authorization_model"])
    return 0


# ======================================================================
# research (security research lab 3.0)
# ======================================================================


def command_research_run(
    scenario: Optional[str],
    as_json: bool,
) -> int:
    from firewall.research import SecurityResearchLab

    lab = SecurityResearchLab()
    try:
        if scenario is not None:
            finding = lab.run(scenario)
            findings = [finding]
        else:
            findings = list(lab.run_all().findings)
    except Exception as exc:
        return _fail(str(exc))

    if as_json:
        _print_json([f.to_dict() for f in findings])
        return 0

    violations = [f for f in findings if not f.defended]
    for finding in findings:
        marker = "OK " if finding.defended else "VIOLATION"
        print(
            f"  {marker} {finding.scenario}: {finding.detail[:90]}"
        )
    if violations:
        print(
            f"\n{len(violations)} violation(s) - copy each into "
            "test_v2_1_research_*.py as a regression test"
        )
        return 1
    print(f"\nall {len(findings)} scenarios defended")
    return 0


def command_research_properties(as_json: bool) -> int:
    from firewall.research import SecurityResearchLab

    lab = SecurityResearchLab()
    try:
        results = lab.property_tests()
    except Exception as exc:
        return _fail(str(exc))

    if as_json:
        _print_json(results)
        return 0

    for name, result in results.items():
        print(
            f"  {'PASS' if result['passed'] else 'FAIL'} {name}: "
            f"{result['detail'][:80]}"
        )
    return 0 if all(r["passed"] for r in results.values()) else 1


def command_research_report(
    out: Optional[str],
    as_json: bool,
) -> int:
    from firewall.research import SecurityResearchLab

    lab = SecurityResearchLab()
    try:
        payload = lab.report()
        if out:
            _write_json(out, payload)
    except Exception as exc:
        return _fail(str(exc))

    if as_json:
        _print_json(payload)
        return 0

    violations = payload["violations"]
    print(
        f"scenarios: {len(payload['findings'])}, "
        f"violations: {len(violations)}"
    )
    if out:
        print(f"wrote report to {out}")
    return 1 if violations else 0


# ======================================================================
# recover
# ======================================================================


def command_recover_mesh(
    registry_path: str,
    agent: str,
    *,
    state_path: Optional[str] = None,
    reason: str,
    actor: str,
    passphrase: Optional[str],
    as_json: bool,
) -> int:
    """Full mesh recovery: begin recovery, then attempt re-entry."""

    reg, mesh = _mesh(registry_path, passphrase, state_path)
    try:
        transition = mesh.recover(agent, actor=actor, reason=reason)
        try:
            reentry = mesh.reenter(agent, actor=actor, reason=reason)
        except Exception as exc:
            reentry = None
            note = str(exc)
    except Exception as exc:
        return _fail(str(exc))
    finally:
        reg.close()

    payload = {
        "recovery": transition.to_dict(),
        "reentry": reentry.to_dict() if reentry else None,
        "note": note if reentry is None else "",
    }

    if as_json:
        _print_json(payload)
        return 0

    print(
        f"recovered {agent}: "
        f"{transition.from_state} -> {transition.to_state}"
    )
    if reentry is not None:
        print(
            f"re-entered {agent}: "
            f"{reentry.from_state} -> {reentry.to_state}"
        )
    else:
        print(f"re-entry pending: {note}")
    return 0 if reentry is not None else 1
