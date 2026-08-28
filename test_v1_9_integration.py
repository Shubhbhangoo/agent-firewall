"""v1.9 integration tests: CLI exit codes, SOC routes, adapters end to
end, state persistence."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import urllib.error
import urllib.request

import pytest

from firewall.artifact import write_artifact
from firewall.network.state import (
    build_index,
    build_state,
    load_state,
    save_state,
)
from firewall.recorder import FlightRecorder
from firewall.sdk import FirewallSDK
from firewall.ui.server import build_server

PY = sys.executable


def _session(session_id, agent, cap_name, *, deny=0, secret=None, delegate_to=None, correlation=None):
    recorder = FlightRecorder(session_id=session_id, agent=agent)
    if correlation:
        recorder.set_meta("correlation_id", correlation)
    sdk = FirewallSDK(recorder=recorder)
    sdk.generate_key("k")
    cap = sdk.issue(
        agent=agent,
        capability=cap_name,
        constraints={"amount_max": 100},
    )
    sdk.authorize(cap, cap_name, {"amount": 20, "path": "/tmp/data"})
    for _ in range(deny):
        sdk.authorize(cap, cap_name, {"amount": 99999})
    if secret:
        sdk.authorize(cap, cap_name, {"path": secret})
    if delegate_to:
        child = sdk.delegate(
            cap,
            sdk.active_key().private_key,
            delegatee=delegate_to,
        ).child
    recorder.finalize()
    return recorder.artifact()


def _cli(*args, cwd=None):
    return subprocess.run(
        [PY, "-m", "firewall.cli", *args],
        capture_output=True,
        text=True,
        cwd=cwd,
        timeout=120,
    )


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------


def test_cli_network_workflow(tmp_path):
    a1 = _session("s1", "agent-a", "payments.send", deny=6, secret="/etc/shadow", delegate_to="ghost", correlation="c1")
    a2 = _session("s2", "agent-b", "files.read", correlation="c1")
    p1 = tmp_path / "a1.afw"
    p2 = tmp_path / "a2.afw"
    write_artifact(a1, p1)
    write_artifact(a2, p2)

    state = tmp_path / "net.json"
    init = _cli("network", "init", "--out", str(state))
    assert init.returncode == 0

    ingest = _cli("network", "ingest", str(p1), str(p2), "--state", str(state))
    assert ingest.returncode == 0, ingest.stderr
    assert "ingested 2 artifact(s)" in ingest.stdout

    correlate = _cli("network", "correlate", str(state))
    assert correlate.returncode == 0
    assert "correlation:c1" in correlate.stdout

    graph = _cli("network", "graph", str(state), "--agent", "agent-a", "--reach")
    assert graph.returncode == 0
    assert "payments.send" in graph.stdout
    assert "/etc/shadow" in graph.stdout

    who = _cli("network", "graph", str(state), "--who-can-reach", "/etc/shadow")
    assert who.returncode == 0
    assert "agent-a" in who.stdout

    detect = _cli("detect", str(state))
    assert detect.returncode == 0
    assert "repeated_denials" in detect.stdout
    assert "credential_shaped_access" in detect.stdout

    attack = _cli("attack-path", str(state), "--summary")
    assert attack.returncode == 0
    assert "/etc/shadow" in attack.stdout


def test_cli_network_simulate_and_respond(tmp_path):
    artifact = _session("s1", "agent-a", "payments.send", secret="/etc/shadow")
    path = tmp_path / "a.afw"
    write_artifact(artifact, path)

    state = tmp_path / "net.json"
    _cli("network", "init", "--out", str(state))
    _cli("network", "ingest", str(path), "--state", str(state))

    scenario = tmp_path / "scenario.json"
    scenario.write_text(
        json.dumps(
            {
                "scenario_id": "sc1",
                "kind": "compromised_agent",
                "title": "compromised",
                "agent": "agent-a",
                "added_capabilities": ["admin.bypass"],
            }
        ),
        encoding="utf-8",
    )

    sim = _cli("network", "simulate", str(state), str(scenario))
    assert sim.returncode == 0, sim.stderr
    assert "admin.bypass" in sim.stdout

    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "rule_id": "credential_shaped_access",
                        "min_severity": "high",
                        "stage": "quarantine",
                        "auto_approve": True,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    respond = _cli(
        "respond",
        str(state),
        "--policy",
        str(policy),
        "--rule",
        "credential_shaped_access",
    )
    assert respond.returncode == 0, respond.stderr
    assert "quarantine" in respond.stdout


def test_cli_v18_commands_still_work(tmp_path):
    path = tmp_path / "s.afw"
    result = _cli("record", "--out", str(path), "--agent", "cli-agent")
    assert result.returncode == 0, result.stderr

    verify = _cli("verify", str(path))
    assert verify.returncode == 0
    assert "status: verified" in verify.stdout


def test_cli_help_lists_v19_commands():
    result = _cli("--help")
    assert result.returncode == 0
    for command in ("network", "detect", "attack-path", "respond"):
        assert command in result.stdout


# ----------------------------------------------------------------------
# State persistence
# ----------------------------------------------------------------------


def test_state_save_load_round_trip(tmp_path):
    state = build_state(
        [
            {
                "path": "/tmp/a.afw",
                "artifact_id": "s1",
                "verification": "verified",
                "agents": ["agent-a"],
            }
        ]
    )
    path = save_state(state, tmp_path / "net.json")
    loaded = load_state(path)
    assert loaded["artifacts"][0]["artifact_id"] == "s1"


def test_build_index_skips_missing_files(tmp_path):
    artifact = _session("s1", "agent-a", "payments.send")
    path = tmp_path / "a.afw"
    write_artifact(artifact, path)

    state = build_state(
        [
            {
                "path": str(path),
                "artifact_id": "s1",
                "verification": "verified",
                "agents": ["agent-a"],
            },
            {
                "path": str(tmp_path / "missing.afw"),
                "artifact_id": "s2",
                "verification": "verified",
                "agents": ["agent-b"],
            },
        ]
    )

    index, path_by_id = build_index(state)
    assert "s1" in index.verified_ids()
    assert "s2" not in index.verified_ids()


# ----------------------------------------------------------------------
# SOC UI routes
# ----------------------------------------------------------------------


@pytest.fixture()
def soc_server():
    server = build_server(
        host="127.0.0.1",
        port=0,
        quiet=True,
        control=True,
        token="test-token",
    )
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        server.shutdown()
        server.server_close()


def _get(port, path, token=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _post(port, path, payload, token=None):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def test_soc_overview_route(soc_server):
    soc = _get(soc_server, "/api/soc")
    assert "agents" in soc
    assert "detections" in soc
    assert "bundles" in soc
    assert "sensitive_resources" in soc
    assert soc["agents"]
    assert any(
        detection["rule_id"] == "credential_shaped_access"
        for detection in soc["detections"]
    )


def test_soc_attack_paths_and_simulate_read_only(soc_server):
    paths = _post(
        soc_server,
        "/api/soc/attack-paths",
        {"agent": "agent-alpha", "target": "/etc/shadow"},
    )
    assert "path" in paths

    sim = _post(
        soc_server,
        "/api/soc/simulate",
        {
            "agent": "agent-alpha",
            "kind": "compromised_agent",
            "title": "what-if",
            "added_capabilities": ["admin.bypass"],
        },
    )
    assert sim["scenario"]["kind"] == "compromised_agent"


def test_soc_respond_requires_token(soc_server):
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        _post(
            soc_server,
            "/api/control/respond",
            {"policy": {"rules": []}},
        )
    assert excinfo.value.code == 401


def test_soc_respond_with_token(soc_server):
    result = _post(
        soc_server,
        "/api/control/respond",
        {
            "policy": {
                "rules": [
                    {
                        "rule_id": "credential_shaped_access",
                        "min_severity": "high",
                        "stage": "quarantine",
                        "auto_approve": True,
                    }
                ]
            },
            "rule": "credential_shaped_access",
        },
        token="test-token",
    )
    records = result["result"]["records"]
    assert records
    assert records[0]["stage"] == "quarantine"
    assert records[0]["agent"] == "agent-alpha"


def test_soc_static_assets(soc_server):
    for asset in ("/assets/soc.js", "/assets/soc.css"):
        with urllib.request.urlopen(
            f"http://127.0.0.1:{soc_server}{asset}"
        ) as resp:
            assert resp.status == 200
            assert len(resp.read()) > 0


def test_soc_index_has_panel(soc_server):
    with urllib.request.urlopen(
        f"http://127.0.0.1:{soc_server}/"
    ) as resp:
        html = resp.read().decode("utf-8")
    assert 'data-bind="socPanel"' in html
    assert "/assets/soc.js" in html


# ----------------------------------------------------------------------
# Adapters end to end
# ----------------------------------------------------------------------


def test_adapters_protect_and_record():
    from firewall.agents import PythonAgentAdapter
    from firewall.recorder import FlightRecorder

    recorder = FlightRecorder(session_id="ad", agent="agent-ad")
    sdk = FirewallSDK(recorder=recorder)
    sdk.generate_key("k")
    capability = sdk.issue(
        agent="agent-ad",
        capability="payments.send",
        constraints={"amount_max": 100},
    )

    def request_builder(args):
        return {"amount": args.get("amount")}

    def handler(amount):
        return f"charged {amount}"

    adapter = PythonAgentAdapter(
        sdk=sdk,
        agent_id="agent-ad",
        recorder=recorder,
        correlation_id="c-1",
    )
    protected = adapter.protect(
        handler,
        name="payments.send",
        capability=capability,
        request_builder=request_builder,
    )

    assert protected.execute(
        {"name": "payments.send", "arguments": {"amount": 20}}
    ) == "charged 20"

    with pytest.raises(PermissionError):
        protected.execute(
            {"name": "payments.send", "arguments": {"amount": 99999}}
        )

    artifact = recorder.finalize()
    from firewall.verify import verify_artifact

    assert verify_artifact(artifact).status == "verified"
    types = {event["type"] for event in artifact["events"]}
    assert "tool_result" in types
    assert "authorization" in types
