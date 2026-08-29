"""v2.1 CLI integration tests: every v2.1 command, end to end."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

PY = sys.executable


def _cli(*args, cwd=None):
    result = subprocess.run(
        [PY, "-m", "firewall.cli", *args],
        capture_output=True,
        text=True,
        cwd=cwd,
    )
    return result


def _write(path: Path, payload) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )


@pytest.fixture()
def session(tmp_path):
    """A scratch directory with identities for alice/bob/carol."""

    reg = str(tmp_path / "identities.json")
    assert _cli("identity", "create", "alice", "--registry", reg).returncode == 0
    assert _cli("identity", "create", "bob", "--registry", reg).returncode == 0
    assert _cli("identity", "create", "carol", "--registry", reg).returncode == 0
    return tmp_path


# ----------------------------------------------------------------------
# defense
# ----------------------------------------------------------------------


class TestDefenseCLI:
    def test_evaluate(self, session):
        result = _cli(
            "defense", "evaluate", "alice",
            "--registry", str(session / "identities.json"),
        )
        assert result.returncode == 0
        assert "identity_verified=True" in result.stdout

    def test_evaluate_unknown_agent_fails(self, session):
        result = _cli(
            "defense", "evaluate", "ghost",
            "--registry", str(session / "identities.json"),
        )
        assert result.returncode == 1

    def test_quarantine_recover_reenter_lifecycle(self, session):
        reg = str(session / "identities.json")
        quarantine = _cli(
            "defense", "quarantine", "alice", "--reason", "incident",
            "--registry", reg,
        )
        assert quarantine.returncode == 0
        assert "quarantined" in quarantine.stdout

        recover = _cli(
            "defense", "recover", "alice", "--reason", "clean",
            "--registry", reg,
        )
        assert recover.returncode == 0
        assert "recovering" in recover.stdout

        reenter = _cli(
            "defense", "reenter", "alice", "--reason", "verified",
            "--registry", reg,
        )
        assert reenter.returncode == 0
        assert "re-entered" in reenter.stdout

    def test_reenter_from_active_rejected(self, session):
        result = _cli(
            "defense", "reenter", "alice", "--reason", "x",
            "--registry", str(session / "identities.json"),
        )
        assert result.returncode == 2

    def test_state_json(self, session):
        result = _cli(
            "defense", "state",
            "--registry", str(session / "identities.json"),
            "--json",
        )
        assert result.returncode == 0
        payload = json.loads(result.stdout)
        assert isinstance(payload, list)


# ----------------------------------------------------------------------
# delegate
# ----------------------------------------------------------------------


class TestDelegateCLI:
    def test_establish_authorize_lifecycle(self, session):
        reg = str(session / "identities.json")
        state = str(session / "a2a.json")
        establish = _cli(
            "delegate", "establish",
            "--registry", reg, "--state", state,
            "--initiator", "alice", "--responder", "bob",
            "--permissions", json.dumps({"allowed_actions": ["read"]}),
        )
        assert establish.returncode == 0
        relationship_id = json.loads(
            _cli("delegate", "graph", "--registry", reg, "--state", state, "--json").stdout
        )["relationships"][0]["relationship_id"]

        allow = _cli(
            "delegate", "authorize",
            "--registry", reg, "--state", state,
            "--actor", "alice", "--target", "bob", "--action", "read",
        )
        assert allow.returncode == 0
        assert "ALLOWED" in allow.stdout

        deny = _cli(
            "delegate", "authorize",
            "--registry", reg, "--state", state,
            "--actor", "alice", "--target", "bob", "--action", "admin",
        )
        assert deny.returncode == 1

        revoke = _cli(
            "delegate", "revoke",
            "--registry", reg, "--state", state,
            "--relationship", relationship_id, "--reason", "incident",
        )
        assert revoke.returncode == 0

        after = _cli(
            "delegate", "authorize",
            "--registry", reg, "--state", state,
            "--actor", "alice", "--target", "bob", "--action", "read",
        )
        assert after.returncode == 1

    def test_grant_narrows(self, session):
        reg = str(session / "identities.json")
        state = str(session / "a2a.json")
        _cli(
            "delegate", "establish",
            "--registry", reg, "--state", state,
            "--initiator", "alice", "--responder", "bob",
            "--permissions", json.dumps({"allowed_actions": ["read", "write"]}),
        )
        relationship_id = json.loads(
            _cli("delegate", "graph", "--registry", reg, "--state", state, "--json").stdout
        )["relationships"][0]["relationship_id"]
        grant = _cli(
            "delegate", "grant",
            "--registry", reg, "--state", state,
            "--relationship", relationship_id,
            "--responder", "carol",
            "--permissions", json.dumps({"allowed_actions": ["read", "write", "admin"]}),
        )
        assert grant.returncode == 0
        assert '"allowed_actions": ["read", "write"]' in grant.stdout

    def test_teardown(self, session):
        reg = str(session / "identities.json")
        state = str(session / "a2a.json")
        _cli(
            "delegate", "establish",
            "--registry", reg, "--state", state,
            "--initiator", "alice", "--responder", "bob",
            "--permissions", json.dumps({"allowed_actions": ["read"]}),
        )
        teardown = _cli(
            "delegate", "teardown",
            "--registry", reg, "--state", state,
            "--a", "alice", "--b", "bob", "--reason", "done",
        )
        assert teardown.returncode == 0
        assert "1" in teardown.stdout


# ----------------------------------------------------------------------
# capability
# ----------------------------------------------------------------------


class TestCapabilityCLI:
    def test_eval_allow_deny(self, session):
        policy = session / "policy.json"
        _write(policy, {
            "capability": "payments.send",
            "constraints": {
                "resource": "payments",
                "action": ["send"],
            },
        })
        allow = _cli(
            "capability", "eval", str(policy),
            json.dumps({"resource": "payments", "action": "send"}),
        )
        assert allow.returncode == 0
        assert "ALLOWED" in allow.stdout

        deny = _cli(
            "capability", "eval", str(policy),
            json.dumps({"resource": "admin", "action": "send"}),
        )
        assert deny.returncode == 1
        assert "DENIED" in deny.stdout

    def test_attenuate_narrows(self, session):
        policy = session / "policy.json"
        _write(policy, {
            "capability": "fs.read",
            "constraints": {"scope": "/data", "action": ["read", "write"]},
        })
        out = session / "narrowed.json"
        result = _cli(
            "capability", "attenuate", str(policy),
            "--out", str(out),
            "--narrowing", json.dumps({"action": ["read"]}),
        )
        assert result.returncode == 0
        child = json.loads(out.read_text(encoding="utf-8"))
        assert child["constraints"]["action"] == "read"

    def test_delegate_records_parent(self, session):
        policy = session / "policy.json"
        _write(policy, {
            "capability": "run",
            "constraints": {"action": ["a", "b"]},
        })
        out = session / "delegated.json"
        result = _cli(
            "capability", "delegate", str(policy),
            "--out", str(out),
            "--narrowing", json.dumps({"action": ["a"]}),
        )
        assert result.returncode == 0
        child = json.loads(out.read_text(encoding="utf-8"))
        assert child["parent"] == "run"

    def test_widening_attenuation_rejected(self, session):
        policy = session / "policy.json"
        _write(policy, {
            "capability": "fs.read",
            "constraints": {"scope": "/data"},
        })
        result = _cli(
            "capability", "attenuate", str(policy),
            "--out", str(session / "bad.json"),
            "--narrowing", json.dumps({"scope": "/etc"}),
        )
        assert result.returncode == 2


# ----------------------------------------------------------------------
# attack-graph / twin
# ----------------------------------------------------------------------


class TestAttackGraphTwinCLI:
    def _network(self, session):
        artifact = session / "demo.afw"
        net = session / "network.json"
        assert _cli("record", "--out", str(artifact)).returncode == 0
        assert _cli("network", "init", "--out", str(net)).returncode == 0
        assert _cli("network", "ingest", str(artifact), "--state", str(net)).returncode == 0
        return net

    def test_build_summarize_paths(self, session):
        net = self._network(session)
        graph = session / "attack-graph.json"
        build = _cli("attack-graph", "build", str(net), "--out", str(graph))
        assert build.returncode == 0
        summary = _cli("attack-graph", "summarize", str(graph))
        assert summary.returncode == 0
        assert "agents" in summary.stdout
        paths = _cli(
            "attack-graph", "paths", str(graph),
            "--target", "payments.send",
        )
        assert paths.returncode == 0
        assert "hops" in paths.stdout

    def test_findings(self, session):
        net = self._network(session)
        graph = session / "attack-graph.json"
        _cli("attack-graph", "build", str(net), "--out", str(graph))
        findings = _cli("attack-graph", "findings", str(graph))
        assert findings.returncode == 0

    def test_twin_compromise(self, session):
        net = self._network(session)
        twin = _cli(
            "twin", str(net),
            "--kind", "compromised_agent", "--agent", "agent-demo",
        )
        assert twin.returncode == 0
        assert "simulated" in twin.stdout

    def test_twin_unknown_agent_fails(self, session):
        net = self._network(session)
        twin = _cli(
            "twin", str(net),
            "--kind", "compromised_agent", "--agent", "ghost",
        )
        assert twin.returncode == 2


# ----------------------------------------------------------------------
# evidence
# ----------------------------------------------------------------------


class TestEvidenceCLI:
    def test_append_verify_timeline_promote(self, session):
        state = str(session / "evidence.json")
        append = _cli(
            "evidence", "append", "--state", state,
            "--kind", "inference", "--subject", "agent-a",
            "--type", "behavior", "--payload", json.dumps({"score": 0.9}),
            "--json",
        )
        assert append.returncode == 0
        event_id = json.loads(append.stdout)["event_id"]

        verify = _cli("evidence", "verify", "--state", state)
        assert verify.returncode == 2  # unsigned -> unverifiable

        promote = _cli(
            "evidence", "promote", "--state", state,
            "--event-id", event_id, "--reason", "confirmed",
        )
        assert promote.returncode == 0

        timeline = _cli(
            "evidence", "timeline", "--state", state, "--subject", "agent-a",
        )
        assert timeline.returncode == 0
        assert "observed" in timeline.stdout

    def test_signed_evidence_verifies(self, session):
        reg = str(session / "identities.json")
        state = str(session / "evidence.json")
        append = _cli(
            "evidence", "append", "--state", state,
            "--registry", reg, "--signer-agent", "alice",
            "--kind", "observed", "--subject", "agent-a",
            "--type", "decision", "--payload", json.dumps({"allowed": True}),
        )
        assert append.returncode == 0
        verify = _cli(
            "evidence", "verify", "--state", state,
            "--registry", reg, "--signer-agent", "alice",
        )
        assert verify.returncode == 0
        assert "verified" in verify.stdout

    def test_malformed_kind_rejected(self, session):
        state = str(session / "evidence.json")
        result = _cli(
            "evidence", "append", "--state", state,
            "--kind", "bogus", "--subject", "x", "--type", "y",
        )
        assert result.returncode == 2


# ----------------------------------------------------------------------
# immune / research / recover
# ----------------------------------------------------------------------


class TestImmuneResearchRecoverCLI:
    def test_immune_state(self):
        result = _cli("immune", "state")
        assert result.returncode == 0
        assert "observe" in result.stdout
        assert "advisory only" in result.stdout

    def test_immune_demo(self, session):
        result = _cli("immune", "demo")
        assert result.returncode == 0

    def test_research_run(self):
        result = _cli("research", "run")
        assert result.returncode == 0
        assert "defended" in result.stdout

    def test_research_properties(self):
        result = _cli("research", "properties")
        assert result.returncode == 0

    def test_research_report_json(self, session):
        out = session / "report.json"
        result = _cli("research", "report", "--out", str(out))
        assert result.returncode == 0
        payload = json.loads(out.read_text(encoding="utf-8"))
        assert payload["violations"] == []

    def test_recover(self, session):
        reg = str(session / "identities.json")
        _cli("defense", "quarantine", "alice", "--reason", "r", "--registry", reg)
        recover = _cli(
            "recover", "alice", "--reason", "clean", "--registry", reg,
        )
        assert recover.returncode == 0
        assert "recovered" in recover.stdout

    def test_help_lists_v21_commands(self):
        result = _cli("--help")
        assert result.returncode == 0
        for command in (
            "defense",
            "delegate",
            "capability",
            "attack-graph",
            "twin",
            "evidence",
            "immune",
            "research",
            "recover",
        ):
            assert command in result.stdout
