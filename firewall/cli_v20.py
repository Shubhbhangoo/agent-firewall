"""v2.0 CLI commands (firewall.cli_v20).

Adds identity, task, passport, provenance, posture, trust, lab, and
attestation commands on top of the v1.8/v1.9 CLI. All logic lives in
the v2.0 modules; these handlers are thin translators with predictable
exit codes (0 / 1 / 2).
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


def _registry(path: str, passphrase: Optional[str]):
    from firewall.ident import IdentityRegistry

    return IdentityRegistry(
        state_path=path,
        passphrase=(
            passphrase.encode("utf-8")
            if passphrase is not None
            else None
        ),
    )


# ======================================================================
# identity
# ======================================================================


def command_identity_create(
    registry_path: str,
    agent: str,
    *,
    owner: str,
    environment: str,
    issuer: str,
    parent: Optional[str],
    passphrase: Optional[str],
    as_json: bool,
) -> int:
    reg = _registry(registry_path, passphrase)
    try:
        identity = reg.create(
            agent,
            owner=owner,
            environment=environment,
            issuer=issuer,
            parent_agent=parent,
        )
    except Exception as exc:
        return _fail(str(exc))
    finally:
        reg.close()

    if as_json:
        _print_json(identity.to_dict())
        return 0

    print(
        f"created identity {identity.agent_id} "
        f"(version {identity.identity_version}, "
        f"status {identity.status})"
    )
    print(f"  key fingerprint: {identity.key_fingerprint}")
    return 0


def command_identity_show(
    registry_path: str,
    agent: Optional[str],
    passphrase: Optional[str],
    as_json: bool,
) -> int:
    reg = _registry(registry_path, passphrase)
    try:
        if agent is not None:
            identity = reg.get(agent)
            if identity is None:
                return _fail(f"unknown identity: {agent}")
            records = [identity]
        else:
            records = list(reg.all())
    finally:
        reg.close()

    if as_json:
        _print_json(
            [identity.to_dict() for identity in records]
        )
        return 0

    if not records:
        print("no identities")
        return 1

    for identity in records:
        print(
            f"{identity.agent_id:<20} {identity.status:<8} "
            f"v{identity.identity_version} "
            f"{identity.key_fingerprint[:12]}..."
        )
        if identity.parent_agent:
            print(f"  parent: {identity.parent_agent}")
    return 0


def command_identity_rotate(
    registry_path: str,
    agent: str,
    passphrase: Optional[str],
    as_json: bool,
) -> int:
    reg = _registry(registry_path, passphrase)
    try:
        identity = reg.rotate(agent)
    except Exception as exc:
        return _fail(str(exc))
    finally:
        reg.close()

    if as_json:
        _print_json(identity.to_dict())
        return 0

    print(
        f"rotated {identity.agent_id} to version "
        f"{identity.identity_version}"
    )
    print(f"  key fingerprint: {identity.key_fingerprint}")
    return 0


def command_identity_revoke(
    registry_path: str,
    agent: str,
    *,
    reason: str,
    passphrase: Optional[str],
    as_json: bool,
) -> int:
    reg = _registry(registry_path, passphrase)
    try:
        identity = reg.revoke(agent, reason=reason)
    except Exception as exc:
        return _fail(str(exc))
    finally:
        reg.close()

    if as_json:
        _print_json(identity.to_dict())
        return 0

    print(f"revoked {identity.agent_id}")
    return 0


# ======================================================================
# task
# ======================================================================


def command_task_create(
    registry_path: str,
    agent: str,
    *,
    state: str,
    permissions: Optional[str],
    passphrase: Optional[str],
    as_json: bool,
) -> int:
    from firewall.task import TaskRegistry

    reg = _registry(registry_path, passphrase)
    tasks = TaskRegistry(
        state_path=state,
        identity_registry=reg,
    )
    try:
        perms = (
            json.loads(permissions)
            if permissions
            else {}
        )
        task = tasks.create(agent_id=agent, permissions=perms)
    except Exception as exc:
        return _fail(str(exc))
    finally:
        reg.close()

    if as_json:
        _print_json(task.to_dict())
        return 0

    print(f"created task {task.task_id} for {task.agent_id}")
    return 0


def command_task_delegate(
    registry_path: str,
    task_id: str,
    agent: str,
    *,
    state: str,
    permissions: Optional[str],
    passphrase: Optional[str],
    as_json: bool,
) -> int:
    from firewall.task import TaskRegistry

    reg = _registry(registry_path, passphrase)
    tasks = TaskRegistry(
        state_path=state,
        identity_registry=reg,
    )
    try:
        parent = tasks.require(task_id)
        perms = (
            json.loads(permissions)
            if permissions
            else {}
        )
        child = tasks.delegate(parent, agent_id=agent, permissions=perms)
    except Exception as exc:
        return _fail(str(exc))
    finally:
        reg.close()

    if as_json:
        _print_json(child.to_dict())
        return 0

    print(f"delegated {task_id} -> {child.task_id} for {agent}")
    return 0


def command_task_show(
    registry_path: str,
    *,
    state: str,
    agent: Optional[str],
    passphrase: Optional[str],
    as_json: bool,
) -> int:
    from firewall.task import TaskRegistry

    reg = _registry(registry_path, passphrase)
    tasks = TaskRegistry(
        state_path=state,
        identity_registry=reg,
    )
    try:
        if agent is not None:
            records = list(tasks.tasks_for_agent(agent))
        else:
            records = list(tasks.all())
    finally:
        reg.close()

    if as_json:
        _print_json([task.to_dict() for task in records])
        return 0

    if not records:
        print("no tasks")
        return 1

    for task in records:
        print(
            f"{task.task_id:<22} {task.agent_id:<16} "
            f"{task.status:<8} active={tasks.is_active(task.task_id)}"
        )
    return 0


# ======================================================================
# passport
# ======================================================================


def command_passport_show(
    registry_path: str,
    agent: str,
    *,
    out: Optional[str],
    passphrase: Optional[str],
    as_json: bool,
) -> int:
    from firewall.passport import PassportBuilder

    reg = _registry(registry_path, passphrase)
    builder = PassportBuilder(reg)
    try:
        passport = builder.build(agent)
    except Exception as exc:
        return _fail(str(exc))
    finally:
        reg.close()

    if out is not None:
        path = Path(out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(passport.to_dict(), indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        print(f"wrote passport to {path}")
        return 0

    if as_json:
        _print_json(passport.to_dict())
        return 0

    print(
        f"passport for {passport.identity.get('agent_id')} "
        f"(status {passport.identity.get('status')})"
    )
    print(f"  posture: {passport.posture.get('posture')}")
    print(
        f"  tasks: {len(passport.tasks)}, "
        f"capabilities: {len(passport.capabilities)}, "
        f"delegated: {len(passport.delegated_authority)}"
    )
    print(
        f"  signature: "
        + ("present" if passport.signature else "MISSING")
    )
    return 0


def command_passport_verify(
    passport_path: str,
    registry_path: str,
    passphrase: Optional[str],
    as_json: bool,
) -> int:
    from firewall.passport import PassportBuilder

    reg = _registry(registry_path, passphrase)
    builder = PassportBuilder(reg)
    try:
        passport = builder.load(passport_path)
        result = builder.verify(passport)
    except Exception as exc:
        return _fail(str(exc))
    finally:
        reg.close()

    if as_json:
        _print_json(result)
        return 0

    print(f"status: {result['status']}")
    for finding in result.get("findings", []):
        print(f"  - {finding}")
    return 0 if result["status"] == "verified" else 1


# ======================================================================
# attestation
# ======================================================================


def command_attest_verify(
    attestation_path: str,
    registry_path: str,
    passphrase: Optional[str],
    as_json: bool,
) -> int:
    from firewall.attest import Attestation, AttestationAuthority

    reg = _registry(registry_path, passphrase)
    authority = AttestationAuthority(reg)
    try:
        payload = json.loads(
            Path(attestation_path).read_text(encoding="utf-8")
        )
        attestation = Attestation.from_dict(payload)
        result = authority.verify(attestation)
    except Exception as exc:
        return _fail(str(exc))
    finally:
        reg.close()

    if as_json:
        _print_json(result)
        return 0

    print(f"status: {result['status']}")
    for finding in result.get("findings", []):
        print(f"  - {finding}")
    return 0 if result["status"] == "verified" else 1


# ======================================================================
# provenance
# ======================================================================


def command_provenance_register(
    state_path: str,
    kind: str,
    name: str,
    *,
    version: str,
    source: str,
    integrity: str,
    dependencies: Optional[str],
    as_json: bool,
) -> int:
    from firewall.provenance import ProvenanceRegistry

    reg = ProvenanceRegistry(state_path=state_path)
    try:
        deps = (
            [item.strip() for item in dependencies.split(",") if item.strip()]
            if dependencies
            else []
        )
        component = reg.register(
            kind=kind,
            name=name,
            version=version,
            source=source,
            integrity=integrity,
            dependencies=deps,
        )
    except Exception as exc:
        return _fail(str(exc))
    finally:
        reg.close()

    if as_json:
        _print_json(component.to_dict())
        return 0

    print(
        f"registered {component.component_id} "
        f"(status {component.status})"
    )
    print(
        "  note: registration does not trust the component; "
        "trust it explicitly"
    )
    return 0


def command_provenance_trust(
    state_path: str,
    component_id: str,
    *,
    reason: str,
    action: str,
    as_json: bool,
) -> int:
    from firewall.provenance import ProvenanceRegistry

    reg = ProvenanceRegistry(state_path=state_path)
    try:
        if action == "trust":
            component = reg.trust(component_id, reason=reason)
        elif action == "suspect":
            component = reg.suspect(component_id, reason=reason)
        elif action == "revoke":
            component = reg.revoke(component_id, reason=reason)
        else:
            return _fail(f"unknown action: {action}")
    except Exception as exc:
        return _fail(str(exc))
    finally:
        reg.close()

    if as_json:
        _print_json(component.to_dict())
        return 0

    print(f"{action}: {component.component_id} -> {component.status}")
    return 0


def command_provenance_show(
    state_path: str,
    *,
    as_json: bool,
) -> int:
    from firewall.provenance import ProvenanceRegistry

    reg = ProvenanceRegistry(state_path=state_path)
    try:
        components = list(reg.all())
    finally:
        reg.close()

    if as_json:
        _print_json(
            [
                {
                    "component_id": c.component_id,
                    "kind": c.kind,
                    "name": c.name,
                    "version": c.version,
                    "status": c.status,
                    "integrity": c.integrity,
                }
                for c in components
            ]
        )
        return 0

    if not components:
        print("no components registered")
        return 1

    for component in components:
        print(
            f"{component.status:<10} {component.kind:<12} "
            f"{component.name} {component.version}"
        )
    return 0


def command_provenance_verify(
    state_path: str,
    component_id: str,
    file: str,
    as_json: bool,
) -> int:
    from firewall.provenance import (
        ProvenanceRegistry,
        digest_file,
    )

    reg = ProvenanceRegistry(state_path=state_path)
    try:
        digest = digest_file(file)
        component = reg.require(component_id)
        result = reg.verify_integrity(
            component_id,
            open(file, "rb").read(),
        )
    except Exception as exc:
        return _fail(str(exc))
    finally:
        reg.close()

    if as_json:
        _print_json(
            {
                "component": component.component_id,
                "file_digest": digest,
                "recorded_integrity": component.integrity,
                "result": result,
            }
        )
        return 0

    print(f"status: {result['status']}")
    for finding in result.get("findings", []):
        print(f"  - {finding}")
    return 0 if result["status"] == "verified" else 1


# ======================================================================
# posture
# ======================================================================


def command_posture_state(
    state_path: str,
    *,
    agent: Optional[str],
    as_json: bool,
) -> int:
    from firewall.posture import PostureEngine

    # Posture state is derived from a live engine; the CLI demonstrates
    # with an empty engine unless a state file with signals exists.
    engine = PostureEngine()
    # A simple JSON state file can carry per-agent signals.
    if Path(state_path).exists():
        try:
            data = json.loads(
                Path(state_path).read_text(encoding="utf-8")
            )
            for entry in data.get("signals", []):
                engine.ingest(
                    entry.get("agent", "?"),
                    __import__(
                        "firewall.posture",
                        fromlist=["PostureSignal"],
                    ).PostureSignal(
                        name=entry.get("name", "signal"),
                        severity=int(entry.get("severity", 1)),
                        description=entry.get("description", ""),
                        evidence=entry.get("evidence", []),
                    ),
                )
        except Exception:
            pass

    if agent is not None:
        states = [engine.state(agent)]
    else:
        states = list(engine.all_states())

    if as_json:
        _print_json([state.to_dict() for state in states])
        return 0

    if not states:
        print("no posture state")
        return 1

    for state in states:
        print(f"{state.agent}: {state.posture}")
        for transition in state.transitions:
            print(
                f"  {transition.from_posture} -> "
                f"{transition.to_posture} "
                f"({transition.signals[0]['name'] if transition.signals else '?'})"
            )
    return 0


# ======================================================================
# trust / lab
# ======================================================================


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


def command_trust_query(
    state_path: str,
    *,
    agent: Optional[str],
    who: Optional[str],
    delegated: Optional[str],
    changed: Optional[str],
    radius: Optional[str],
    as_json: bool,
) -> int:
    from firewall.trust import TrustGraph

    graph = _load_network_state(state_path)
    trust = TrustGraph(graph)

    if radius is not None:
        try:
            result = trust.blast_radius(radius)
        except Exception as exc:
            return _fail(str(exc))
        if as_json:
            _print_json(result)
            return 0
        print(f"blast radius for {radius}:")
        for capability in result["capabilities"]:
            print(f"    capability: {capability}")
        for resource in result["resources"]:
            print(
                f"    resource: {resource}"
                + (
                    "  (SENSITIVE)"
                    if resource in result["sensitive_resources"]
                    else ""
                )
            )
        return 0

    if changed is not None:
        changes = trust.what_changed(changed)
        if as_json:
            _print_json(changes)
            return 0
        if not changes:
            print(f"no recorded authority changes for {changed}")
            return 1
        for change in changes:
            print(
                f"  {change['relation']:<10} {change['other']:<20} "
                f"by {change['by']}"
            )
        return 0

    if delegated is not None:
        grantors = trust.who_delegated(delegated)
        if as_json:
            _print_json(grantors)
            return 0
        if not grantors:
            print(f"no recorded grants for {delegated}")
            return 1
        print(f"who delegated to {delegated}:")
        for grantor in grantors:
            print(f"    {grantor['grantor']} ({grantor['relation']})")
        return 0

    if who is not None:
        reachers = trust.who_can(who)
        if as_json:
            _print_json(reachers)
            return 0
        if not reachers:
            print(f"no agent can reach {who}")
            return 1
        print(f"agents that can reach {who}:")
        for entry in reachers:
            print(f"    {entry['agent']}")
        return 0

    if agent is not None:
        result = trust.what_can(agent)
        if as_json:
            _print_json(result)
            return 0
        print(f"{agent} can:")
        for capability in result["capabilities"]:
            print(f"    capability: {capability}")
        for resource in result["resources"]:
            print(f"    resource: {resource}")
        return 0

    return _fail("one of --agent, --who, --delegated, --changed, --radius is required")


def command_lab_sweep(
    state_path: str,
    as_json: bool,
) -> int:
    from firewall.lab import SecurityLab

    graph = _load_network_state(state_path)
    lab = SecurityLab(graph)
    sweep = lab.sweep()

    if as_json:
        _print_json(sweep)
        return 0

    dangers = sweep["dangers"]
    opportunities = sweep["containment_opportunities"]

    print(f"dangers: {len(dangers)}")
    for danger in dangers[:10]:
        print(f"  [{danger['type']}] {danger['description']}")

    print(f"containment opportunities: {len(opportunities)}")
    for opportunity in opportunities[:5]:
        print(
            f"  {opportunity['agent']}: {opportunity['effect']}"
        )

    sensitive = sweep["sensitive_resources"].get(
        "sensitive_resources", []
    )
    print(f"sensitive resources: {len(sensitive)}")

    return 0


def command_lab_counterfactual(
    state_path: str,
    *,
    agent: str,
    kind: str,
    title: str,
    added: Optional[str],
    removed: Optional[str],
    containment: str,
    as_json: bool,
) -> int:
    from firewall.lab import SecurityLab

    graph = _load_network_state(state_path)
    lab = SecurityLab(graph)

    try:
        result = lab.counterfactual(
            agent=agent,
            kind=kind,
            title=title,
            added_capabilities=(
                [item.strip() for item in added.split(",") if item.strip()]
                if added
                else ()
            ),
            removed_capabilities=(
                [item.strip() for item in removed.split(",") if item.strip()]
                if removed
                else ()
            ),
            containment=containment,
        )
    except Exception as exc:
        return _fail(str(exc))

    if as_json:
        _print_json(result)
        return 0

    print(result.get("scenario", {}).get("title", "scenario"))
    for path in result.get("available_paths", []):
        print(f"  path: {path['source']} -> {path['target']} [{path['status']}]")
    for decision in result.get("policy_decisions", []):
        print(
            f"  {decision['action']} -> "
            f"{'ALLOWED' if decision['allowed'] else 'DENIED'} "
            f"({decision['reason']}) [{decision['basis']}]"
        )
    return 0
