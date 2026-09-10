import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from firewall.engine import Firewall
from firewall.identity import (
    IdentityVerifier,
    sign_identity,
)


def make_identity(agent_id):
    private_key = Ed25519PrivateKey.generate()

    return sign_identity(
        private_key,
        agent_id,
        "trusted-issuer",
    )


def make_firewall(tmp_path, monkeypatch):
    policy_file = tmp_path / "policies.yaml"

    policy_file.write_text(
        """
rules:
  - tool: payments.send
    agent: finance-agent
    action: allow

  - tool: payments.send
    agent: attacker-agent
    action: deny
""",
        encoding="utf-8",
    )

    monkeypatch.chdir(tmp_path)

    return Firewall(
        str(policy_file),
        identity_verifier=IdentityVerifier(
            {"trusted-issuer"}
        ),
    )


def read_audit(tmp_path):
    audit_file = tmp_path / "audit.log"

    lines = audit_file.read_text(
        encoding="utf-8"
    ).splitlines()

    return [
        json.loads(line)
        for line in lines
    ]


def test_audit_records_verified_agent(
    tmp_path,
    monkeypatch,
):
    fw = make_firewall(
        tmp_path,
        monkeypatch,
    )

    identity = make_identity(
        "finance-agent"
    )

    fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    entries = read_audit(tmp_path)

    assert entries[-1]["agent"] == "finance-agent"


def test_audit_records_public_key(
    tmp_path,
    monkeypatch,
):
    fw = make_firewall(
        tmp_path,
        monkeypatch,
    )

    identity = make_identity(
        "finance-agent"
    )

    fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    entries = read_audit(tmp_path)

    assert (
        entries[-1]["public_key"]
        == identity.public_key
    )


def test_audit_records_issuer(
    tmp_path,
    monkeypatch,
):
    fw = make_firewall(
        tmp_path,
        monkeypatch,
    )

    identity = make_identity(
        "finance-agent"
    )

    fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    entries = read_audit(tmp_path)

    assert (
        entries[-1]["issuer"]
        == "trusted-issuer"
    )


def test_audit_records_decision(
    tmp_path,
    monkeypatch,
):
    fw = make_firewall(
        tmp_path,
        monkeypatch,
    )

    identity = make_identity(
        "finance-agent"
    )

    result = fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    entries = read_audit(tmp_path)

    assert entries[-1]["decision"] == result.action


def test_audit_records_tool(
    tmp_path,
    monkeypatch,
):
    fw = make_firewall(
        tmp_path,
        monkeypatch,
    )

    identity = make_identity(
        "finance-agent"
    )

    fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    entries = read_audit(tmp_path)

    assert (
        entries[-1]["tool"]
        == "payments.send"
    )


def test_audit_records_request_arguments(
    tmp_path,
    monkeypatch,
):
    fw = make_firewall(
        tmp_path,
        monkeypatch,
    )

    identity = make_identity(
        "finance-agent"
    )

    arguments = {
        "amount": 42
    }

    fw.check(
        identity,
        "payments.send",
        arguments,
    )

    entries = read_audit(tmp_path)

    assert (
        entries[-1]["arguments"]
        == arguments
    )


def test_denied_identity_is_audited(
    tmp_path,
    monkeypatch,
):
    fw = make_firewall(
        tmp_path,
        monkeypatch,
    )

    identity = make_identity(
        "attacker-agent"
    )

    result = fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    entries = read_audit(tmp_path)

    assert result.action == "deny"
    assert entries[-1]["agent"] == "attacker-agent"
    assert entries[-1]["decision"] == "deny"