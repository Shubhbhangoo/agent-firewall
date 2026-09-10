import pytest

from firewall.capability import (
    generate_capability_key_pair,
)

from firewall.revocation import (
    RevocationRegistry,
)

from firewall.sdk import FirewallSDK


def make_capability(
    sdk,
    *,
    agent="agent-a",
    capability="payments.send",
):
    private_key, _ = (
        generate_capability_key_pair()
    )

    return sdk.issue(
        private_key=private_key,
        agent=agent,
        capability=capability,
    )


# ============================================================
# Persistent SDK initialization
# ============================================================


def test_sdk_accepts_revocation_store_path(
    tmp_path,
):
    path = (
        tmp_path
        / "revocations.db"
    )

    sdk = FirewallSDK(
        revocation_store_path=path
    )

    assert sdk._revocation_store is not None
    assert path.exists()

    sdk.close()


def test_sdk_persistent_registry_uses_backend(
    tmp_path,
):
    path = (
        tmp_path
        / "revocations.db"
    )

    sdk = FirewallSDK(
        revocation_store_path=path
    )

    assert isinstance(
        sdk.revocation,
        RevocationRegistry,
    )

    assert sdk.revocation.backend is not None

    sdk.close()


def test_sdk_default_remains_in_memory():
    sdk = FirewallSDK()

    assert sdk._revocation_store is None
    assert sdk.revocation.backend is None

    sdk.close()


def test_sdk_accepts_custom_registry(
    tmp_path,
):
    registry = RevocationRegistry()

    sdk = FirewallSDK(
        revocation_registry=registry
    )

    assert (
        sdk.revocation
        is registry
    )

    assert sdk._revocation_store is None

    sdk.close()


def test_sdk_rejects_registry_and_path_together(
    tmp_path,
):
    registry = RevocationRegistry()

    with pytest.raises(
        ValueError
    ):
        FirewallSDK(
            revocation_registry=registry,
            revocation_store_path=(
                tmp_path
                / "revocations.db"
            ),
        )


# ============================================================
# Persistent revocation
# ============================================================


def test_sdk_persistent_revocation(
    tmp_path,
):
    path = (
        tmp_path
        / "revocations.db"
    )

    sdk = FirewallSDK(
        revocation_store_path=path
    )

    capability = make_capability(
        sdk
    )

    record = sdk.revoke(
        capability,
        reason="compromised",
    )

    assert record.fingerprint == (
        sdk.fingerprint(
            capability
        )
    )

    assert record.reason == (
        "compromised"
    )

    assert sdk.is_revoked(
        capability
    )

    sdk.close()


def test_sdk_persistent_revocation_survives_restart(
    tmp_path,
):
    path = (
        tmp_path
        / "revocations.db"
    )

    sdk1 = FirewallSDK(
        revocation_store_path=path
    )

    capability = make_capability(
        sdk1
    )

    sdk1.revoke(
        capability,
        reason="compromised",
    )

    sdk1.close()

    sdk2 = FirewallSDK(
        revocation_store_path=path
    )

    assert sdk2.is_revoked(
        capability
    )

    record = sdk2.revocation.get(
        sdk2.fingerprint(
            capability
        )
    )

    assert record is not None
    assert record.reason == (
        "compromised"
    )

    sdk2.close()


def test_sdk_persistent_revocation_denies_authorization(
    tmp_path,
):
    path = (
        tmp_path
        / "revocations.db"
    )

    sdk = FirewallSDK(
        revocation_store_path=path
    )

    capability = make_capability(
        sdk
    )

    sdk.revoke(
        capability
    )

    result = sdk.authorize(
        capability,
        "payments.send",
        {},
    )

    assert result.allowed is False
    assert (
        result.reason
        == "capability_revoked"
    )

    sdk.close()


def test_sdk_persistent_revocation_denies_boolean_authorization(
    tmp_path,
):
    path = (
        tmp_path
        / "revocations.db"
    )

    sdk = FirewallSDK(
        revocation_store_path=path
    )

    capability = make_capability(
        sdk
    )

    sdk.revoke(
        capability
    )

    assert not sdk.is_authorized(
        capability,
        "payments.send",
        {},
    )

    sdk.close()


# ============================================================
# Persistent verification
# ============================================================


def test_sdk_persistent_revocation_blocks_verify(
    tmp_path,
):
    path = (
        tmp_path
        / "revocations.db"
    )

    sdk = FirewallSDK(
        revocation_store_path=path
    )

    capability = make_capability(
        sdk
    )

    assert sdk.verify(
        capability
    )

    sdk.revoke(
        capability
    )

    assert not sdk.verify(
        capability
    )

    sdk.close()


def test_sdk_persistent_revocation_blocks_decode_verified(
    tmp_path,
):
    path = (
        tmp_path
        / "revocations.db"
    )

    sdk = FirewallSDK(
        revocation_store_path=path
    )

    capability = make_capability(
        sdk
    )

    token = sdk.encode(
        capability
    )

    sdk.revoke(
        capability
    )

    with pytest.raises(Exception):
        sdk.decode_verified(
            token
        )

    sdk.close()


def test_existing_token_stays_revoked_after_restart(
    tmp_path,
):
    path = (
        tmp_path
        / "revocations.db"
    )

    sdk1 = FirewallSDK(
        revocation_store_path=path
    )

    capability = make_capability(
        sdk1
    )

    token = sdk1.encode(
        capability
    )

    sdk1.revoke(
        capability
    )

    sdk1.close()

    sdk2 = FirewallSDK(
        revocation_store_path=path
    )

    with pytest.raises(Exception):
        sdk2.decode_verified(
            token
        )

    assert not sdk2.is_authorized(
        capability,
        "payments.send",
        {},
    )

    sdk2.close()


# ============================================================
# Multiple capabilities
# ============================================================


def test_persistent_registry_isolates_capabilities(
    tmp_path,
):
    path = (
        tmp_path
        / "revocations.db"
    )

    sdk = FirewallSDK(
        revocation_store_path=path
    )

    first = make_capability(
        sdk,
        capability="payments.send",
    )

    second = make_capability(
        sdk,
        capability="payments.refund",
    )

    sdk.revoke(
        first
    )

    assert sdk.is_revoked(
        first
    )

    assert not sdk.is_revoked(
        second
    )

    assert not sdk.is_authorized(
        first,
        "payments.send",
        {},
    )

    assert sdk.is_authorized(
        second,
        "payments.refund",
        {},
    )

    sdk.close()


def test_persistent_registry_isolates_agents(
    tmp_path,
):
    path = (
        tmp_path
        / "revocations.db"
    )

    sdk = FirewallSDK(
        revocation_store_path=path
    )

    first = make_capability(
        sdk,
        agent="agent-a",
    )

    second = make_capability(
        sdk,
        agent="agent-b",
    )

    sdk.revoke(
        first
    )

    assert sdk.is_revoked(
        first
    )

    assert not sdk.is_revoked(
        second
    )

    sdk.close()


# ============================================================
# Revoke / duplicate behavior
# ============================================================


def test_persistent_duplicate_revoke_rejected(
    tmp_path,
):
    path = (
        tmp_path
        / "revocations.db"
    )

    sdk = FirewallSDK(
        revocation_store_path=path
    )

    capability = make_capability(
        sdk
    )

    sdk.revoke(
        capability
    )

    with pytest.raises(Exception):
        sdk.revoke(
            capability
        )

    sdk.close()


def test_persistent_registry_size(
    tmp_path,
):
    path = (
        tmp_path
        / "revocations.db"
    )

    sdk = FirewallSDK(
        revocation_store_path=path
    )

    first = make_capability(
        sdk,
        capability="payments.send",
    )

    second = make_capability(
        sdk,
        capability="payments.refund",
    )

    assert sdk.revocation.size() == 0

    sdk.revoke(first)
    assert sdk.revocation.size() == 1

    sdk.revoke(second)
    assert sdk.revocation.size() == 2

    sdk.close()


def test_persistent_records_survive_restart(
    tmp_path,
):
    path = (
        tmp_path
        / "revocations.db"
    )

    sdk1 = FirewallSDK(
        revocation_store_path=path
    )

    first = make_capability(
        sdk1
    )

    second = make_capability(
        sdk1,
        capability="payments.refund",
    )

    sdk1.revoke(
        first,
        reason="first",
    )

    sdk1.revoke(
        second,
        reason="second",
    )

    sdk1.close()

    sdk2 = FirewallSDK(
        revocation_store_path=path
    )

    records = sdk2.revocation.records()

    assert len(records) == 2

    reasons = {
        record.reason
        for record in records
    }

    assert reasons == {
        "first",
        "second",
    }

    sdk2.close()


# ============================================================
# Lifecycle
# ============================================================


def test_sdk_close_is_safe():
    sdk = FirewallSDK()

    sdk.close()
    sdk.close()


def test_sdk_persistent_close_is_safe(
    tmp_path,
):
    path = (
        tmp_path
        / "revocations.db"
    )

    sdk = FirewallSDK(
        revocation_store_path=path
    )

    sdk.close()
    sdk.close()


def test_sdk_context_manager_persists(
    tmp_path,
):
    path = (
        tmp_path
        / "revocations.db"
    )

    with FirewallSDK(
        revocation_store_path=path
    ) as sdk:
        capability = make_capability(
            sdk
        )

        sdk.revoke(
            capability
        )

    with FirewallSDK(
        revocation_store_path=path
    ) as reopened:

        assert reopened.is_revoked(
            capability
        )


# ============================================================
# Custom registry compatibility
# ============================================================


def test_custom_registry_still_has_priority(
    tmp_path,
):
    registry = RevocationRegistry()

    sdk = FirewallSDK(
        revocation_registry=registry
    )

    capability = make_capability(
        sdk
    )

    sdk.revoke(
        capability
    )

    assert (
        registry.is_revoked(
            sdk.fingerprint(
                capability
            )
        )
    )

    sdk.close()


def test_custom_registry_does_not_create_database(
    tmp_path,
):
    path = (
        tmp_path
        / "should-not-exist.db"
    )

    registry = RevocationRegistry()

    sdk = FirewallSDK(
        revocation_registry=registry
    )

    capability = make_capability(
        sdk
    )

    sdk.revoke(
        capability
    )

    assert not path.exists()

    sdk.close()