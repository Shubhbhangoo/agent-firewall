import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from firewall.engine import Firewall
from firewall.identity import (
    IdentityVerifier,
    sign_identity,
)


def make_identity():
    private_key = Ed25519PrivateKey.generate()

    return sign_identity(
        private_key,
        "finance-agent",
        "trusted-issuer",
    )


def make_policy(tmp_path):
    policy_file = tmp_path / "policies.yaml"

    policy_file.write_text(
        """
rules:
  - tool: payments.send
    agent: finance-agent
    action: allow
""",
        encoding="utf-8",
    )

    return policy_file


def make_firewall(tmp_path):
    return Firewall(
        str(make_policy(tmp_path)),
        identity_verifier=IdentityVerifier(
            {"trusted-issuer"}
        ),
    )


def read_entries(tmp_path):
    audit_file = tmp_path / "audit.log"

    return [
        json.loads(line)
        for line in audit_file.read_text(
            encoding="utf-8"
        ).splitlines()
    ]


def test_chain_continues_after_firewall_restart(
    tmp_path,
    monkeypatch,
):
    monkeypatch.chdir(tmp_path)

    identity = make_identity()

    fw1 = make_firewall(tmp_path)

    fw1.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    first = read_entries(tmp_path)[-1]

    fw2 = make_firewall(tmp_path)

    fw2.check(
        identity,
        "payments.send",
        {"amount": 20},
    )

    entries = read_entries(tmp_path)

    assert len(entries) == 2

    assert (
        entries[1]["previous_hash"]
        == first["integrity_hash"]
    )


def test_chain_remains_valid_after_restart(
    tmp_path,
    monkeypatch,
):
    monkeypatch.chdir(tmp_path)

    identity = make_identity()

    fw1 = make_firewall(tmp_path)

    fw1.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    fw2 = make_firewall(tmp_path)

    fw2.check(
        identity,
        "payments.send",
        {"amount": 20},
    )

    assert fw2.verify_audit_chain() is True


def test_multiple_restarts_preserve_chain(
    tmp_path,
    monkeypatch,
):
    monkeypatch.chdir(tmp_path)

    identity = make_identity()

    for amount in (10, 20, 30, 40):

        fw = make_firewall(tmp_path)

        fw.check(
            identity,
            "payments.send",
            {"amount": amount},
        )

    entries = read_entries(tmp_path)

    assert len(entries) == 4

    for index in range(1, 4):
        assert (
            entries[index]["previous_hash"]
            == entries[index - 1]["integrity_hash"]
        )

    assert fw.verify_audit_chain() is True


def test_restart_after_denial_preserves_chain(
    tmp_path,
    monkeypatch,
):
    monkeypatch.chdir(tmp_path)

    identity = make_identity()

    fw1 = make_firewall(tmp_path)

    fw1.check(
        identity,
        "unknown.tool",
        {},
    )

    fw2 = make_firewall(tmp_path)

    fw2.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    entries = read_entries(tmp_path)

    assert entries[0]["decision"] == "deny"
    assert entries[1]["decision"] == "allow"

    assert (
        entries[1]["previous_hash"]
        == entries[0]["integrity_hash"]
    )


def test_restart_does_not_reset_chain_to_empty_hash(
    tmp_path,
    monkeypatch,
):
    monkeypatch.chdir(tmp_path)

    identity = make_identity()

    fw1 = make_firewall(tmp_path)

    fw1.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    first = read_entries(tmp_path)[0]

    fw2 = make_firewall(tmp_path)

    fw2.check(
        identity,
        "payments.send",
        {"amount": 20},
    )

    second = read_entries(tmp_path)[1]

    assert first["integrity_hash"] != ""
    assert second["previous_hash"] != ""
    assert (
        second["previous_hash"]
        == first["integrity_hash"]
    )


def test_missing_audit_log_starts_new_chain(
    tmp_path,
    monkeypatch,
):
    monkeypatch.chdir(tmp_path)

    identity = make_identity()

    fw = make_firewall(tmp_path)

    fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    entry = read_entries(tmp_path)[0]

    assert entry["previous_hash"] == ""
    assert fw.verify_audit_chain() is True