"""v1.8 integration tests: SDK recording, CLI exit codes, UI routes,
replay lab, and incident packages."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import urllib.error
import urllib.request

import pytest

from firewall.incident import (
    create_incident_package,
    read_incident_package,
    redact_artifact,
    write_incident_package,
)
from firewall.recorder import EventType, FlightRecorder
from firewall.replaylab import Laboratory, extract_cases
from firewall.risk_context import RiskContext
from firewall.sdk import FirewallSDK
from firewall.simulation import RuleSet
from firewall.ui.server import build_server
from firewall.verify import verify_artifact


# ----------------------------------------------------------------------
# SDK recording
# ----------------------------------------------------------------------


def test_sdk_records_authorizations_post_decision():
    recorder = FlightRecorder(session_id="sdk-rec", agent="agent-a")
    sdk = FirewallSDK(recorder=recorder)
    sdk.generate_key("k")
    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints={"amount_max": 100},
    )

    allowed = sdk.authorize(capability, "payments.send", {"amount": 20})
    denied = sdk.authorize(capability, "payments.send", {"amount": 9999})

    artifact = recorder.finalize()

    authorization = [
        event
        for event in artifact["events"]
        if event["type"] == "authorization"
    ]

    assert len(authorization) == 2
    assert authorization[0]["payload"]["allowed"] is True
    assert authorization[0]["payload"]["action"] == "payments.send"
    assert authorization[1]["payload"]["allowed"] is False
    assert authorization[1]["payload"]["reason"] == "constraint_denied"
    # The chain facts the gates reasoned about are recorded.
    assert authorization[0]["payload"]["chain"][0]["agent"] == "agent-a"
    assert allowed.allowed and not denied.allowed


def test_sdk_records_delegation_and_revocation():
    recorder = FlightRecorder(session_id="sdk-del", agent="agent-a")
    sdk = FirewallSDK(recorder=recorder)
    sdk.generate_key("k")
    root = sdk.issue(agent="agent-a", capability="payments.send")
    child = sdk.delegate(
        root,
        sdk.active_key().private_key,
        delegatee="agent-b",
    ).child
    sdk.revoke(root, reason="compromise")

    artifact = recorder.finalize()
    types = [event["type"] for event in artifact["events"]]

    assert "authority_issued" in types
    assert "authority_delegated" in types
    assert "authority_revoked" in types

    revoked = [
        event
        for event in artifact["events"]
        if event["type"] == "authority_revoked"
    ][0]
    assert revoked["payload"]["capability"] == "payments.send"
    assert revoked["payload"]["reason"] == "compromise"


def test_sdk_without_recorder_has_zero_overhead_path():
    sdk = FirewallSDK()
    sdk.generate_key("k")
    capability = sdk.issue(agent="agent-a", capability="payments.send")
    result = sdk.authorize(capability, "payments.send", {"amount": 1})
    assert result.allowed
    assert sdk.flight_recorder is None


def test_sdk_recorder_failure_never_breaks_authorization():
    recorder = FlightRecorder(session_id="broken", agent="agent-a")
    original = recorder.record

    def boom(*args, **kwargs):
        raise RuntimeError("recorder exploded")

    recorder.record = boom  # type: ignore

    sdk = FirewallSDK(recorder=recorder)
    sdk.generate_key("k")
    capability = sdk.issue(agent="agent-a", capability="payments.send")
    result = sdk.authorize(capability, "payments.send", {"amount": 1})
    assert result.allowed

    recorder.record = original  # restore
    recorder.finalize()


# ----------------------------------------------------------------------
# CLI exit codes
# ----------------------------------------------------------------------


def _cli(*args, cwd=None):
    return subprocess.run(
        [sys.executable, "-m", "firewall.cli", *args],
        capture_output=True,
        text=True,
        cwd=cwd,
        timeout=120,
    )


def test_cli_record_verify_round_trip(tmp_path):
    artifact_path = tmp_path / "session.afw"
    result = _cli(
        "record",
        "--out",
        str(artifact_path),
        "--agent",
        "cli-agent",
    )
    assert result.returncode == 0, result.stderr
    assert artifact_path.exists()

    verify = _cli("verify", str(artifact_path))
    assert verify.returncode == 0, verify.stderr
    assert "status: verified" in verify.stdout

    verify_json = _cli("verify", str(artifact_path), "--json")
    payload = json.loads(verify_json.stdout)
    assert payload["status"] == "verified"


def test_cli_verify_exit_codes_distinguish_states(tmp_path):
    from firewall.artifact import write_artifact

    recorder = FlightRecorder(session_id="cli-exit", agent="a")
    recorder.record(EventType.NOTE, {"text": "x"})
    recorder.finalize()
    good = tmp_path / "good.afw"
    write_artifact(recorder.artifact(), good)

    # incomplete
    recorder2 = FlightRecorder(session_id="cli-incomplete", agent="a")
    recorder2.record(EventType.NOTE, {"text": "x"})
    incomplete = tmp_path / "incomplete.afw"
    write_artifact(recorder2.artifact(), incomplete)

    # garbage
    garbage = tmp_path / "garbage.afw"
    garbage.write_text("not json", encoding="utf-8")

    assert _cli("verify", str(good)).returncode == 0
    assert _cli("verify", str(incomplete)).returncode == 1
    assert _cli("verify", str(garbage)).returncode == 2
    assert _cli("verify", str(good), "--expect-recorder", "0" * 64).returncode == 2


def test_cli_timeline_trajectory_graph_commands(tmp_path):
    artifact_path = tmp_path / "s.afw"
    _cli("record", "--out", str(artifact_path), "--agent", "cli-agent")

    timeline = _cli("timeline", str(artifact_path))
    assert timeline.returncode == 0
    assert "Session started" in timeline.stdout

    trajectory = _cli("trajectory", str(artifact_path))
    assert trajectory.returncode == 0

    graph = _cli("graph", str(artifact_path), "--agent", "cli-agent", "--why", "payments.send")
    assert graph.returncode == 0
    assert "could payments.send" in graph.stdout


def test_cli_replay_counterfactual(tmp_path):
    artifact_path = tmp_path / "s.afw"
    _cli("record", "--out", str(artifact_path), "--agent", "cli-agent")

    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps({"trusted_issuers": [], "max_delegation_depth": None}), encoding="utf-8")

    replay = _cli("replay", str(artifact_path), "--rules", str(rules))
    assert replay.returncode == 0
    assert "counterfactual analysis" in replay.stdout

    replay_json = _cli("replay", str(artifact_path), "--rules", str(rules), "--json")
    payload = json.loads(replay_json.stdout)
    assert "summary" in payload
    assert payload["summary"]["newly_denied"] >= 1


def test_cli_incident_package(tmp_path):
    artifact_path = tmp_path / "s.afw"
    _cli("record", "--out", str(artifact_path), "--agent", "cli-agent")

    package_path = tmp_path / "incident.json"
    incident = _cli(
        "incident", "create", str(artifact_path),
        "--title", "test incident", "--summary", "integration",
        "--out", str(package_path),
    )
    assert incident.returncode == 0, incident.stderr
    assert package_path.exists()

    package = read_incident_package(package_path)
    assert package["verification"]["status"] == "verified"
    assert "timeline" in package
    assert "trajectory" in package
    assert "graph" in package
    assert "replay" in package


def test_cli_redact_produces_verifiable_derivation(tmp_path):
    artifact_path = tmp_path / "s.afw"
    _cli("record", "--out", str(artifact_path), "--agent", "cli-agent")

    redacted_path = tmp_path / "red.afw"
    redact = _cli("redact", str(artifact_path), "--out", str(redacted_path))
    assert redact.returncode == 0, redact.stderr

    verify = _cli("verify", str(redacted_path))
    assert verify.returncode == 0
    assert "status: verified" in verify.stdout


def test_cli_help_lists_v18_commands():
    result = _cli("--help")
    assert result.returncode == 0
    for command in ("record", "inspect", "verify", "replay", "timeline", "trajectory", "graph", "incident", "redact"):
        assert command in result.stdout


# ----------------------------------------------------------------------
# UI routes
# ----------------------------------------------------------------------


@pytest.fixture()
def console_server():
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


def _get(port, path):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}") as resp:
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


def test_ui_recorder_route(console_server):
    recorder = _get(console_server, "/api/recorder")
    assert recorder["available"] is True
    assert recorder["session"]["event_count"] > 0
    assert recorder["verification"]["status"] in {
        "verified",
        "redacted",
    }
    assert recorder["timeline"]
    assert "transitions" in recorder["trajectory"]
    assert recorder["graph"]["nodes"]
    assert "containment" in recorder


def test_ui_recorder_replay_route_is_read_only(console_server):
    replay = _post(console_server, "/api/replay", {"trusted_issuers": []})
    assert "summary" in replay
    assert replay["summary"]["decisions_recorded"] > 0


def test_ui_containment_requires_token(console_server):
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        _post(
            console_server,
            "/api/control/containment",
            {"action": "quarantine_agent", "agent": "agent-alpha", "reason": "test"},
        )
    assert excinfo.value.code == 401


def test_ui_containment_with_token_is_audited(console_server):
    result = _post(
        console_server,
        "/api/control/containment",
        {"action": "quarantine_agent", "agent": "agent-alpha", "reason": "test"},
        token="test-token",
    )
    event = result["result"]["event"]
    assert event["action"] == "quarantine_agent"
    assert event["from"] == "active"
    assert event["to"] == "quarantined"
    assert event["actor"] == "console"

    # The containment action is recorded in the audit stream, which is
    # appended to the *controller's* history (state["containment"]) and
    # the control plane's own audit log. Both are surfaced in the
    # control-plane state projection.
    req = urllib.request.Request(
        f"http://127.0.0.1:{console_server}/api/control/state"
    )
    req.add_header("Authorization", "Bearer test-token")
    with urllib.request.urlopen(req) as resp:
        control_state = json.loads(resp.read().decode("utf-8"))

    assert control_state["containment"]["states"].get(
        "agent-alpha"
    ) == "quarantined"

    containment_history = control_state["containment"]["history"]
    assert containment_history, "containment history is empty"
    assert containment_history[0]["action"] == "quarantine_agent"
    assert containment_history[0]["to"] == "quarantined"
    assert containment_history[0]["actor"] == "console"

    # The action is audited in the control plane's own audit list too.
    all_actions = [entry["action"] for entry in control_state["audit"]]
    assert "containment" in all_actions


def test_ui_static_assets_served(console_server):
    for asset in ("/assets/recorder.js", "/assets/recorder.css"):
        with urllib.request.urlopen(
            f"http://127.0.0.1:{console_server}{asset}"
        ) as resp:
            assert resp.status == 200
            assert len(resp.read()) > 0


def test_ui_index_has_recorder_panel(console_server):
    with urllib.request.urlopen(
        f"http://127.0.0.1:{console_server}/"
    ) as resp:
        html = resp.read().decode("utf-8")
    assert 'data-bind="recorderPanel"' in html
    assert "/assets/recorder.js" in html


# ----------------------------------------------------------------------
# Replay laboratory
# ----------------------------------------------------------------------


def _recorded_artifact():
    recorder = FlightRecorder(
        session_id="lab", agent="agent-l", clock=lambda: 1700000000.0
    )
    sdk = FirewallSDK(recorder=recorder)
    sdk.generate_key("k")
    capability = sdk.issue(
        agent="agent-l",
        capability="payments.send",
        constraints={"amount_max": 100},
    )
    sdk.authorize(capability, "payments.send", {"amount": 20})
    sdk.authorize(capability, "payments.send", {"amount": 5000})
    sdk.authorize(capability, "payments.send", {"amount": 30})
    return recorder.finalize()


def test_lab_extracts_cases_and_replays_baseline():
    artifact = _recorded_artifact()
    cases = extract_cases(artifact)
    assert len(cases) == 3

    laboratory = Laboratory(artifact)
    report = laboratory.replay()
    assert report.summary()["decisions_replayed"] == 3


def test_lab_counterfactual_newly_denied():
    artifact = _recorded_artifact()
    laboratory = Laboratory(artifact)
    proposed = RuleSet(trusted_issuers=set())
    report = laboratory.replay(proposed)

    assert report.summary()["newly_denied"] >= 1

    counterfactual = [
        row for row in report.rows
        if row.classification == "counterfactual"
    ]
    assert counterfactual
    row = counterfactual[0]
    assert row.observed_allowed is True
    assert row.counterfactual_allowed is False
    assert row.counterfactual_reason == "untrusted_issuer"


def test_lab_rows_distinguish_observed_replayed_counterfactual():
    artifact = _recorded_artifact()
    laboratory = Laboratory(artifact)
    report = laboratory.replay(
        RuleSet(trusted_issuers=set())
    )

    for row in report.rows:
        assert row.observed_allowed is not None
        assert row.counterfactual_allowed is not None
        assert row.classification in {
            "verified",
            "counterfactual",
            "unverifiable",
        }


# ----------------------------------------------------------------------
# Incident packages
# ----------------------------------------------------------------------


def test_incident_package_bundles_everything():
    artifact = _recorded_artifact()
    package = create_incident_package(
        artifact,
        title="incident",
        summary="test",
    )
    assert package["incident"] == 1
    assert package["verification"]["status"] == "verified"
    assert package["timeline"]
    assert package["trajectory"]
    assert package["graph"]["nodes"]
    assert package["replay"]["summary"]["decisions_replayed"] == 3


def test_incident_package_round_trip(tmp_path):
    artifact = _recorded_artifact()
    package = create_incident_package(
        artifact,
        title="round trip",
    )
    path = write_incident_package(package, tmp_path / "inc.json")
    loaded = read_incident_package(path)
    assert loaded["title"] == "round trip"
    assert loaded["artifact"]["session"]["id"] == "lab"


def test_incident_redaction_export_verifies():
    recorder = FlightRecorder(
        session_id="sec", agent="agent-s", clock=lambda: 1700000000.0
    )
    recorder.record(
        EventType.TOOL_RESULT,
        {"tool": "db", "password": "hunter2"},
    )
    recorder.finalize()

    redacted = redact_artifact(recorder.artifact())
    report = verify_artifact(redacted)
    assert report.status == "redacted"

    package = create_incident_package(
        recorder.artifact(),
        title="secret",
        redact=True,
    )
    assert package["verification"]["status"] in {
        "verified",
        "redacted",
    }


def test_incident_package_never_conflates_broken_evidence():
    recorder = FlightRecorder(session_id="broken", agent="a")
    recorder.record(EventType.NOTE, {"text": "original"})
    recorder.finalize()
    artifact = recorder.artifact()
    artifact["events"][1]["payload"]["text"] = "tampered"

    package = create_incident_package(
        artifact,
        title="broken",
    )
    assert package["verification"]["status"] == "failed"
    assert any(
        finding["severity"] == "error"
        for finding in package["verification"]["findings"]
    )
