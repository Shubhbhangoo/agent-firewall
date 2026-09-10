"""v2.0 integration tests: CLI exit codes and end-to-end flows."""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

PY = sys.executable


def _cli(*args, cwd=None):
    return subprocess.run(
        [PY, "-m", "firewall.cli", *args],
        capture_output=True,
        text=True,
        cwd=cwd,
        timeout=120,
    )


def test_cli_identity_lifecycle(tmp_path):
    reg = str(tmp_path / "idents.json")

    created = _cli(
        "identity", "create", "agent-a",
        "--registry", reg, "--owner", "me", "--passphrase", "pw",
    )
    assert created.returncode == 0, created.stderr
    assert "created identity agent-a" in created.stdout

    shown = _cli("identity", "show", "--registry", reg, "--passphrase", "pw")
    assert shown.returncode == 0
    assert "agent-a" in shown.stdout

    rotated = _cli(
        "identity", "rotate", "agent-a",
        "--registry", reg, "--passphrase", "pw",
    )
    assert rotated.returncode == 0
    assert "version 2" in rotated.stdout

    revoked = _cli(
        "identity", "revoke", "agent-a",
        "--registry", reg, "--reason", "test", "--passphrase", "pw",
    )
    assert revoked.returncode == 0
    assert "revoked agent-a" in revoked.stdout


def test_cli_passport_round_trip(tmp_path):
    reg = str(tmp_path / "idents.json")
    _cli("identity", "create", "agent-a", "--registry", reg, "--passphrase", "pw")

    passport_path = str(tmp_path / "passport.json")
    built = _cli(
        "passport", "show", "agent-a",
        "--registry", reg, "--out", passport_path, "--passphrase", "pw",
    )
    assert built.returncode == 0, built.stderr
    assert os.path.exists(passport_path)

    verified = _cli(
        "passport", "verify", passport_path,
        "--registry", reg, "--passphrase", "pw",
    )
    assert verified.returncode == 0
    assert "status: verified" in verified.stdout

    # Tamper the passport -> verification fails with exit 1.
    payload = json.loads(open(passport_path, encoding="utf-8").read())
    payload["capabilities"] = ["admin.bypass"]
    open(passport_path, "w", encoding="utf-8").write(
        json.dumps(payload, sort_keys=True)
    )
    failed = _cli(
        "passport", "verify", passport_path,
        "--registry", reg, "--passphrase", "pw",
    )
    assert failed.returncode == 1
    assert "failed" in failed.stdout


def test_cli_task_flow(tmp_path):
    reg = str(tmp_path / "idents.json")
    _cli("identity", "create", "agent-a", "--registry", reg, "--passphrase", "pw")
    _cli("identity", "create", "agent-b", "--registry", reg, "--passphrase", "pw")

    perms = json.dumps({"allowed_actions": ["read"]})
    created = _cli(
        "task", "create", "agent-a",
        "--registry", reg, "--permissions", perms, "--passphrase", "pw",
    )
    assert created.returncode == 0, created.stderr

    shown = _cli(
        "task", "show", "--registry", reg, "--passphrase", "pw", "--json"
    )
    assert shown.returncode == 0
    tasks = json.loads(shown.stdout)
    assert tasks
    task_id = tasks[0]["task_id"]

    delegated = _cli(
        "task", "delegate", task_id, "agent-b",
        "--registry", reg, "--permissions", perms, "--passphrase", "pw",
    )
    assert delegated.returncode == 0, delegated.stderr


def test_cli_provenance_flow(tmp_path):
    state = str(tmp_path / "prov.json")

    registered = _cli(
        "provenance", "register", "tool", "payments.send",
        "--state", state, "--version", "1.0", "--integrity", "abc",
    )
    assert registered.returncode == 0
    assert "does not trust" in registered.stdout

    trusted = _cli(
        "provenance", "trust", "trust", "tool:payments.send:1.0",
        "--state", state, "--reason", "reviewed",
    )
    assert trusted.returncode == 0
    assert "trusted" in trusted.stdout

    shown = _cli("provenance", "show", "--state", state)
    assert "trusted" in shown.stdout


def test_cli_trust_and_lab(tmp_path):
    from firewall.artifact import write_artifact
    from firewall.recorder import FlightRecorder
    from firewall.sdk import FirewallSDK

    def session(session_id, agent, cap_name, secret=None):
        recorder = FlightRecorder(session_id=session_id, agent=agent)
        sdk = FirewallSDK(recorder=recorder)
        sdk.generate_key("k")
        cap = sdk.issue(
            agent=agent,
            capability=cap_name,
            constraints={"amount_max": 100},
        )
        sdk.authorize(cap, cap_name, {"amount": 20, "path": "/tmp/data"})
        if secret:
            sdk.authorize(cap, cap_name, {"path": secret})
        recorder.finalize()
        return recorder.artifact()

    a1 = tmp_path / "a1.afw"
    a2 = tmp_path / "a2.afw"
    write_artifact(
        session("s1", "agent-a", "payments.send", secret="/etc/shadow"), a1
    )
    write_artifact(session("s2", "agent-b", "files.read"), a2)

    net = str(tmp_path / "net.json")
    _cli("network", "init", "--out", net)
    ingested = _cli("network", "ingest", str(a1), str(a2), "--state", net)
    assert ingested.returncode == 0, ingested.stderr

    radius = _cli("trust", net, "--radius", "agent-a")
    assert radius.returncode == 0
    assert "SENSITIVE" in radius.stdout

    sweep = _cli("lab", "sweep", net)
    assert sweep.returncode == 0
    assert "containment opportunities" in sweep.stdout

    counter = _cli(
        "lab", "counterfactual", net,
        "--agent", "agent-a", "--kind", "compromised_agent",
        "--added", "admin.bypass",
    )
    assert counter.returncode == 0, counter.stderr
    assert "admin.bypass" in counter.stdout


def test_cli_help_lists_v20_commands():
    result = _cli("--help")
    assert result.returncode == 0
    for command in (
        "identity", "task", "passport", "attestation",
        "provenance", "posture", "trust", "lab",
    ):
        assert command in result.stdout


def test_cli_v18_v19_still_work(tmp_path):
    artifact = str(tmp_path / "s.afw")
    recorded = _cli("record", "--out", artifact, "--agent", "cli-agent")
    assert recorded.returncode == 0, recorded.stderr

    verified = _cli("verify", artifact)
    assert verified.returncode == 0
    assert "status: verified" in verified.stdout

    net = str(tmp_path / "net.json")
    _cli("network", "init", "--out", net)
    ingested = _cli("network", "ingest", artifact, "--state", net)
    assert ingested.returncode == 0, ingested.stderr
