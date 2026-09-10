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


def test_valid_chain_is_verified(
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

    assert fw.verify_audit_chain() is True


def test_empty_audit_log_is_valid(
    tmp_path,
    monkeypatch,
):
    fw = make_firewall(
        tmp_path,
        monkeypatch,
    )

    assert fw.verify_audit_chain() is True


def test_modified_entry_is_detected(
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

    entries[0]["arguments"]["amount"] = 999999

    audit_file = tmp_path / "audit.log"

    audit_file.write_text(
        "\n".join(
            json.dumps(entry)
            for entry in entries
        )
        + "\n",
        encoding="utf-8",
    )

    assert fw.verify_audit_chain() is False


def test_broken_previous_hash_is_detected(
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

    entries[1]["previous_hash"] = (
        "0" * 64
    )

    audit_file = tmp_path / "audit.log"

    audit_file.write_text(
        "\n".join(
            json.dumps(entry)
            for entry in entries
        )
        + "\n",
        encoding="utf-8",
    )

    assert fw.verify_audit_chain() is False


def test_reordered_entries_are_detected(
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

    entries.reverse()

    audit_file = tmp_path / "audit.log"

    audit_file.write_text(
        "\n".join(
            json.dumps(entry)
            for entry in entries
        )
        + "\n",
        encoding="utf-8",
    )

    assert fw.verify_audit_chain() is False


def test_deleted_middle_entry_is_detected(
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

    del entries[1]

    audit_file = tmp_path / "audit.log"

    audit_file.write_text(
        "\n".join(
            json.dumps(entry)
            for entry in entries
        )
        + "\n",
        encoding="utf-8",
    )

    assert fw.verify_audit_chain() is False


def test_truncated_audit_entry_is_detected(
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

    audit_file = tmp_path / "audit.log"

    audit_file.write_text(
        '{"request_id":"broken"}\n',
        encoding="utf-8",
    )

    assert fw.verify_audit_chain() is False


def test_invalid_json_is_detected(
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

    audit_file = tmp_path / "audit.log"

    with audit_file.open(
        "a",
        encoding="utf-8",
    ) as f:
        f.write(
            "this is not json\n"
        )

    assert fw.verify_audit_chain() is False