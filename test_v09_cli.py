from __future__ import annotations

import json

from firewall.capability import (
    generate_capability_key_pair,
)

from firewall.cli import main

from firewall.lifecycle import (
    LifecycleEventType,
)

from firewall.lifecycle_store import (
    SQLiteLifecycleStore,
)

from firewall.sdk import FirewallSDK


def make_capability():
    sdk = FirewallSDK()

    private_key, _ = (
        generate_capability_key_pair()
    )

    capability = sdk.issue(
        private_key=private_key,
        agent="agent-a",
        capability="payments.send",
    )

    return sdk, capability


def test_init_creates_configuration(
    tmp_path,
    capsys,
):
    path = tmp_path / "firewall.yaml"

    result = main(
        [
            "init",
            "--path",
            str(path),
        ]
    )

    assert result == 0
    assert path.exists()

    output = capsys.readouterr()

    assert "created" in output.out


def test_init_rejects_existing_file(
    tmp_path,
    capsys,
):
    path = tmp_path / "firewall.yaml"

    path.write_text(
        "existing",
        encoding="utf-8",
    )

    result = main(
        [
            "init",
            "--path",
            str(path),
        ]
    )

    assert result == 1

    output = capsys.readouterr()

    assert "already exists" in output.err


def test_validate_valid_configuration(
    tmp_path,
    capsys,
):
    path = tmp_path / "firewall.yaml"

    path.write_text(
        """
trusted_issuers:
  - trusted-issuer

rules: []
""",
        encoding="utf-8",
    )

    result = main(
        [
            "validate",
            str(path),
        ]
    )

    assert result == 0

    output = capsys.readouterr()

    assert "valid:" in output.out


def test_validate_missing_configuration(
    tmp_path,
    capsys,
):
    path = tmp_path / "missing.yaml"

    result = main(
        [
            "validate",
            str(path),
        ]
    )

    assert result == 1

    output = capsys.readouterr()

    assert "not found" in output.err


def test_validate_invalid_configuration(
    tmp_path,
    capsys,
):
    path = tmp_path / "firewall.yaml"

    path.write_text(
        """
rules:
  broken: true
""",
        encoding="utf-8",
    )

    result = main(
        [
            "validate",
            str(path),
        ]
    )

    assert result == 1

    output = capsys.readouterr()

    assert "'rules' must be a list" in output.err


def test_inspect_token(
    capsys,
):
    sdk, capability = (
        make_capability()
    )

    token = sdk.encode(
        capability
    )

    result = main(
        [
            "inspect-token",
            token,
        ]
    )

    assert result == 0

    output = capsys.readouterr()

    data = json.loads(
        output.out
    )

    assert data["agent_id"] == (
        capability.agent_id
    )

    assert data["capability"] == (
        capability.capability
    )

    sdk.close()


def test_inspect_invalid_token(
    capsys,
):
    result = main(
        [
            "inspect-token",
            "not-a-token",
        ]
    )

    assert result == 1

    output = capsys.readouterr()

    assert "error:" in output.err


def test_explain_empty_database(
    tmp_path,
    capsys,
):
    path = tmp_path / "lifecycle.db"

    store = SQLiteLifecycleStore(path)
    store.close()

    result = main(
        [
            "explain",
            str(path),
        ]
    )

    assert result == 0

    output = capsys.readouterr()

    assert "no lifecycle events" in output.out


def test_explain_database(
    tmp_path,
    capsys,
):
    path = tmp_path / "lifecycle.db"

    sdk = FirewallSDK(
        lifecycle_store_path=path
    )

    private_key, _ = (
        generate_capability_key_pair()
    )

    capability = sdk.issue(
        private_key=private_key,
        agent="agent-a",
        capability="payments.send",
    )

    sdk.authorize(
        capability,
        "payments.send",
        {},
    )

    sdk.close()

    result = main(
        [
            "explain",
            str(path),
        ]
    )

    assert result == 0

    output = capsys.readouterr()

    assert "issued" in output.out
    assert "used" in output.out


def test_explain_json(
    tmp_path,
    capsys,
):
    path = tmp_path / "lifecycle.db"

    sdk = FirewallSDK(
        lifecycle_store_path=path
    )

    private_key, _ = (
        generate_capability_key_pair()
    )

    capability = sdk.issue(
        private_key=private_key,
        agent="agent-a",
        capability="payments.send",
    )

    sdk.revoke(
        capability,
        reason="test",
    )

    sdk.close()

    result = main(
        [
            "explain",
            str(path),
            "--json",
        ]
    )

    assert result == 0

    output = capsys.readouterr()

    data = json.loads(
        output.out
    )

    assert len(data) == 2

    assert data[0]["event_type"] == (
        LifecycleEventType.ISSUED.value
    )

    assert data[1]["event_type"] == (
        LifecycleEventType.REVOKED.value
    )


def test_explain_by_fingerprint(
    tmp_path,
    capsys,
):
    path = tmp_path / "lifecycle.db"

    sdk = FirewallSDK(
        lifecycle_store_path=path
    )

    private_key, _ = (
        generate_capability_key_pair()
    )

    capability = sdk.issue(
        private_key=private_key,
        agent="agent-a",
        capability="payments.send",
    )

    fingerprint = sdk.fingerprint(
        capability
    )

    sdk.authorize(
        capability,
        "payments.send",
        {},
    )

    sdk.close()

    result = main(
        [
            "explain",
            str(path),
            "--fingerprint",
            fingerprint,
        ]
    )

    assert result == 0

    output = capsys.readouterr()

    assert fingerprint in output.out
    assert "issued" in output.out
    assert "used" in output.out


def test_explain_by_event_type(
    tmp_path,
    capsys,
):
    path = tmp_path / "lifecycle.db"

    sdk = FirewallSDK(
        lifecycle_store_path=path
    )

    private_key, _ = (
        generate_capability_key_pair()
    )

    capability = sdk.issue(
        private_key=private_key,
        agent="agent-a",
        capability="payments.send",
    )

    sdk.authorize(
        capability,
        "payments.send",
        {},
    )

    sdk.close()

    result = main(
        [
            "explain",
            str(path),
            "--event-type",
            "used",
        ]
    )

    assert result == 0

    output = capsys.readouterr()

    assert "used" in output.out
    assert "issued" not in output.out


def test_explain_missing_database(
    tmp_path,
    capsys,
):
    path = tmp_path / "missing.db"

    result = main(
        [
            "explain",
            str(path),
        ]
    )

    assert result == 1

    output = capsys.readouterr()

    assert "not found" in output.err