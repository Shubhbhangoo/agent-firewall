import hashlib
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


def test_first_entry_has_previous_hash(
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

    assert "previous_hash" in entry
    assert entry["previous_hash"] == ""


def test_second_entry_references_first_hash(
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
        entries[1]["previous_hash"]
        == entries[0]["integrity_hash"]
    )


def test_chain_continues_across_multiple_entries(
    tmp_path,
    monkeypatch,
):
    fw = make_firewall(
        tmp_path,
        monkeypatch,
    )

    identity = make_identity()

    for amount in (10, 20, 30, 40):
        fw.check(
            identity,
            "payments.send",
            {"amount": amount},
        )

    entries = read_entries(tmp_path)

    for index in range(1, len(entries)):
        assert (
            entries[index]["previous_hash"]
            == entries[index - 1]["integrity_hash"]
        )


def test_each_entry_has_integrity_hash(
    tmp_path,
    monkeypatch,
):
    fw = make_firewall(
        tmp_path,
        monkeypatch,
    )

    identity = make_identity()

    for amount in (10, 20, 30):
        fw.check(
            identity,
            "payments.send",
            {"amount": amount},
        )

    entries = read_entries(tmp_path)

    for entry in entries:
        assert "integrity_hash" in entry
        assert len(
            entry["integrity_hash"]
        ) == 64


def test_chain_detects_modified_previous_entry(
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

    original_hash = entries[0]["integrity_hash"]

    entries[0]["arguments"]["amount"] = 999999

    assert (
        entries[1]["previous_hash"]
        == original_hash
    )

    modified_payload = dict(entries[0])
    modified_payload.pop("integrity_hash")

    recalculated = hashlib.sha256(
        json.dumps(
            modified_payload,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
    ).hexdigest()

    assert recalculated != original_hash


def test_denied_entries_continue_chain(
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
        "unknown.tool",
        {},
    )

    fw.check(
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


def test_chain_is_order_sensitive(
    tmp_path,
    monkeypatch,
):
    fw = make_firewall(
        tmp_path,
        monkeypatch,
    )

    identity = make_identity()

    for amount in (10, 20, 30):
        fw.check(
            identity,
            "payments.send",
            {"amount": amount},
        )

    entries = read_entries(tmp_path)

    original_chain = [
        entry["previous_hash"]
        for entry in entries
    ]

    reversed_entries = list(
        reversed(entries)
    )

    reversed_chain = [
        entry["previous_hash"]
        for entry in reversed_entries
    ]

    assert (
        original_chain
        != reversed_chain
    )