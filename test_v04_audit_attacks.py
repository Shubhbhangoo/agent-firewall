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
    monkeypatch.chdir(tmp_path)

    policy = tmp_path / "policies.yaml"

    policy.write_text(
        """
rules:
  - tool: payments.send
    agent: finance-agent
    action: allow
""",
        encoding="utf-8",
    )

    return Firewall(
        str(policy),
        identity_verifier=IdentityVerifier(
            {"trusted-issuer"}
        ),
    )


def read_entries(tmp_path):
    return [
        json.loads(line)
        for line in (
            tmp_path / "audit.log"
        ).read_text(
            encoding="utf-8"
        ).splitlines()
    ]


def write_entries(tmp_path, entries):
    (
        tmp_path / "audit.log"
    ).write_text(
        "\n".join(
            json.dumps(entry)
            for entry in entries
        )
        + "\n",
        encoding="utf-8",
    )


def test_forged_integrity_hash_is_detected(
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

    entries = read_entries(tmp_path)

    entries[0]["integrity_hash"] = "0" * 64

    write_entries(
        tmp_path,
        entries,
    )

    assert fw.verify_audit_chain() is False


def test_forged_previous_hash_is_detected(
    tmp_path,
    monkeypatch,
):
    fw = make_firewall(
        tmp_path,
        monkeypatch,
    )

    identity = make_identity()

    for amount in (10, 20):
        fw.check(
            identity,
            "payments.send",
            {"amount": amount},
        )

    entries = read_entries(tmp_path)

    entries[1]["previous_hash"] = "0" * 64

    write_entries(
        tmp_path,
        entries,
    )

    assert fw.verify_audit_chain() is False


def test_missing_integrity_hash_is_detected(
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

    entries = read_entries(tmp_path)

    del entries[0]["integrity_hash"]

    write_entries(
        tmp_path,
        entries,
    )

    assert fw.verify_audit_chain() is False


def test_missing_previous_hash_is_detected(
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

    entries = read_entries(tmp_path)

    del entries[0]["previous_hash"]

    write_entries(
        tmp_path,
        entries,
    )

    assert fw.verify_audit_chain() is False


def test_short_integrity_hash_is_detected(
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

    entries = read_entries(tmp_path)

    entries[0]["integrity_hash"] = "abc"

    write_entries(
        tmp_path,
        entries,
    )

    assert fw.verify_audit_chain() is False


def test_extra_field_tampering_is_detected(
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

    entries = read_entries(tmp_path)

    entries[0]["forged"] = True

    write_entries(
        tmp_path,
        entries,
    )

    assert fw.verify_audit_chain() is False


def test_duplicate_entry_is_detected(
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

    entries = read_entries(tmp_path)

    entries.append(
        dict(entries[0])
    )

    write_entries(
        tmp_path,
        entries,
    )

    assert fw.verify_audit_chain() is False


def test_tampering_after_restart_is_detected(
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

    fw = make_firewall(
        tmp_path,
        monkeypatch,
    )

    fw.check(
        identity,
        "payments.send",
        {"amount": 20},
    )

    entries = read_entries(tmp_path)

    entries[0]["arguments"]["amount"] = 999999

    write_entries(
        tmp_path,
        entries,
    )

    assert fw.verify_audit_chain() is False