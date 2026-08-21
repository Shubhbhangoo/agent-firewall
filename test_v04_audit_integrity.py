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


def make_firewall(tmp_path, monkeypatch):
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

    monkeypatch.chdir(tmp_path)

    return Firewall(
        str(policy_file),
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


def test_audit_entry_has_integrity_hash(
    tmp_path,
    monkeypatch,
):
    fw = make_firewall(
        tmp_path,
        monkeypatch,
    )

    identity = make_identity()

    fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    entry = read_entries(tmp_path)[-1]

    assert "integrity_hash" in entry
    assert isinstance(
        entry["integrity_hash"],
        str,
    )
    assert entry["integrity_hash"]


def test_same_request_produces_valid_hash(
    tmp_path,
    monkeypatch,
):
    fw = make_firewall(
        tmp_path,
        monkeypatch,
    )

    identity = make_identity()

    fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    entry = read_entries(tmp_path)[-1]

    assert len(
        entry["integrity_hash"]
    ) == 64


def test_audit_entries_have_different_hashes(
    tmp_path,
    monkeypatch,
):
    fw = make_firewall(
        tmp_path,
        monkeypatch,
    )

    identity = make_identity()

    fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    fw.check(
        identity,
        "payments.send",
        {"amount": 20},
    )

    entries = read_entries(tmp_path)

    assert (
        entries[-1]["integrity_hash"]
        != entries[-2]["integrity_hash"]
    )


def test_integrity_hash_is_not_arguments_field(
    tmp_path,
    monkeypatch,
):
    fw = make_firewall(
        tmp_path,
        monkeypatch,
    )

    identity = make_identity()

    fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    entry = read_entries(tmp_path)[-1]

    assert (
        entry["integrity_hash"]
        != json.dumps(
            entry["arguments"],
            sort_keys=True,
        )
    )


def test_integrity_hash_is_recorded_for_denials(
    tmp_path,
    monkeypatch,
):
    fw = make_firewall(
        tmp_path,
        monkeypatch,
    )

    identity = make_identity()

    result = fw.check(
        identity,
        "unknown.tool",
        {},
    )

    assert result.action == "deny"

    entry = read_entries(tmp_path)[-1]

    assert "integrity_hash" in entry
    assert entry["decision"] == "deny"


def test_integrity_hash_is_recorded_for_identity_context(
    tmp_path,
    monkeypatch,
):
    fw = make_firewall(
        tmp_path,
        monkeypatch,
    )

    identity = make_identity()

    fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    entry = read_entries(tmp_path)[-1]

    assert entry["agent"] == "finance-agent"
    assert entry["issuer"] == "trusted-issuer"
    assert entry["public_key"] == identity.public_key
    assert "integrity_hash" in entry