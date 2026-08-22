import threading

import pytest

from firewall.capability import (
    generate_capability_key_pair,
)

from firewall.http import (
    HTTPAuthorizationError,
    HTTPFirewall,
    HTTPRequest,
)

from firewall.mcp import (
    MCPAuthorizationError,
    MCPFirewall,
    MCPRequest,
)

from firewall.revocation import (
    RevocationRegistry,
)

from firewall.revocation_store import (
    SQLiteRevocationStore,
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


def make_engine(
    tmp_path,
    *,
    db_path,
):
    import yaml

    policy_path = (
        tmp_path / "policies.yaml"
    )

    policy_path.write_text(
        yaml.safe_dump(
            {
                "rules": [
                    {
                        "tool": "payments.send",
                        "agent": "agent-a",
                        "action": "allow",
                    }
                ]
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    from firewall.engine import Firewall

    return Firewall(
        str(policy_path),
        revocation_store_path=db_path,
    )


class AgentFixture:
    def __init__(
        self,
        agent_id,
        capabilities,
    ):
        self.agent_id = agent_id
        self.capabilities = list(
            capabilities
        )
        self.authenticated = True


# ============================================================
# Concurrent persistent revocation
# ============================================================


def test_concurrent_persistent_revoke_has_one_winner(
    tmp_path,
):
    path = (
        tmp_path
        / "revocations.db"
    )

    registry_a = RevocationRegistry(
        backend=SQLiteRevocationStore(path)
    )

    registry_b = RevocationRegistry(
        backend=SQLiteRevocationStore(path)
    )

    successes = []
    failures = []
    lock = threading.Lock()

    def revoke(registry):
        try:
            registry.revoke(
                "concurrent",
                reason="race",
            )

            with lock:
                successes.append(True)

        except Exception:
            with lock:
                failures.append(True)

    threads = [
        threading.Thread(
            target=revoke,
            args=(
                registry_a
                if index % 2 == 0
                else registry_b,
            ),
        )
        for index in range(20)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert len(successes) == 1
    assert len(failures) == 19

    assert registry_a.is_revoked(
        "concurrent"
    )

    assert registry_b.is_revoked(
        "concurrent"
    )


# ============================================================
# Two-instance visibility
# ============================================================


def test_second_registry_sees_new_revocation(
    tmp_path,
):
    path = (
        tmp_path
        / "revocations.db"
    )

    first = RevocationRegistry(
        backend=SQLiteRevocationStore(path)
    )

    second = RevocationRegistry(
        backend=SQLiteRevocationStore(path)
    )

    assert not second.is_revoked(
        "shared"
    )

    first.revoke(
        "shared"
    )

    assert second.is_revoked(
        "shared"
    )


def test_second_registry_sees_reason(
    tmp_path,
):
    path = (
        tmp_path
        / "revocations.db"
    )

    first = RevocationRegistry(
        backend=SQLiteRevocationStore(path)
    )

    second = RevocationRegistry(
        backend=SQLiteRevocationStore(path)
    )

    first.revoke(
        "shared",
        reason="compromised",
    )

    record = second.get(
        "shared"
    )

    assert record is not None
    assert (
        record.reason
        == "compromised"
    )


# ============================================================
# Restart persistence
# ============================================================


def test_registry_restart_preserves_revocation(
    tmp_path,
):
    path = (
        tmp_path
        / "revocations.db"
    )

    first = RevocationRegistry(
        backend=SQLiteRevocationStore(path)
    )

    first.revoke(
        "restart",
        reason="stolen",
    )

    first.backend.close()

    second = RevocationRegistry(
        backend=SQLiteRevocationStore(path)
    )

    assert second.is_revoked(
        "restart"
    )

    record = second.get(
        "restart"
    )

    assert record.reason == "stolen"

    second.backend.close()


def test_no_unrevoke_after_restart(
    tmp_path,
):
    path = (
        tmp_path
        / "revocations.db"
    )

    first = RevocationRegistry(
        backend=SQLiteRevocationStore(path)
    )

    first.revoke(
        "one-way"
    )

    first.backend.close()

    second = RevocationRegistry(
        backend=SQLiteRevocationStore(path)
    )

    assert second.is_revoked(
        "one-way"
    )

    assert not hasattr(
        second,
        "unrevoke",
    )

    second.backend.close()


# ============================================================
# SDK restart
# ============================================================


def test_sdk_restart_preserves_revocation(
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
        capability,
        reason="stolen",
    )

    sdk1.close()

    sdk2 = FirewallSDK(
        revocation_store_path=path
    )

    assert sdk2.is_revoked(
        capability
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


def test_existing_sdk_token_cannot_be_resurrected(
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

    for _ in range(3):
        with pytest.raises(Exception):
            sdk2.decode_verified(
                token
            )

    sdk2.close()


# ============================================================
# Engine restart
# ============================================================


def test_engine_restart_preserves_revocation(
    tmp_path,
):
    db_path = (
        tmp_path / "revocations.db"
    )

    sdk = FirewallSDK(
        revocation_store_path=db_path
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

    sdk.close()

    firewall = make_engine(
        tmp_path,
        db_path=db_path,
    )

    agent = AgentFixture(
        "agent-a",
        [capability],
    )

    decision = firewall.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert decision.action == "deny"

    # Existing token is also invalid through the SDK
    # backed by the same persistent store.
    sdk2 = FirewallSDK(
        revocation_store_path=db_path
    )

    with pytest.raises(Exception):
        sdk2.decode_verified(
            token
        )

    sdk2.close()


# ============================================================
# MCP restart
# ============================================================


def test_mcp_restart_preserves_revocation(
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

    firewall = MCPFirewall(sdk2)

    request = MCPRequest(
        agent="agent-a",
        tool="payments.send",
        arguments={},
        capability_token=token,
        nonce="restart-mcp",
    )

    decision = firewall.authorize(
        request
    )

    assert decision.allowed is False

    called = []

    def handler(arguments):
        called.append(True)

    with pytest.raises(
        MCPAuthorizationError
    ):
        firewall.execute(
            request,
            handler,
        )

    assert called == []

    sdk2.close()


# ============================================================
# HTTP restart
# ============================================================


def test_http_restart_preserves_revocation(
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

    firewall = HTTPFirewall(sdk2)

    request = HTTPRequest(
        agent="agent-a",
        method="POST",
        path="/payments",
        arguments={},
        capability_token=token,
        nonce="restart-http",
    )

    decision = firewall.authorize(
        request
    )

    assert decision.allowed is False

    called = []

    def handler(request):
        called.append(True)

    with pytest.raises(
        HTTPAuthorizationError
    ):
        firewall.execute(
            request,
            handler,
        )

    assert called == []

    sdk2.close()


# ============================================================
# Capability isolation
# ============================================================


def test_persistent_revocation_does_not_cross_capabilities(
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

    sdk.close()


def test_persistent_revocation_does_not_cross_agents(
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
# Cross-instance mutation
# ============================================================


def test_revoke_from_second_sdk_instance_visible_to_first(
    tmp_path,
):
    path = (
        tmp_path
        / "revocations.db"
    )

    sdk1 = FirewallSDK(
        revocation_store_path=path
    )

    sdk2 = FirewallSDK(
        revocation_store_path=path
    )

    capability = make_capability(
        sdk1
    )

    sdk2.revoke(
        capability,
        reason="second-instance",
    )

    assert sdk1.is_revoked(
        capability
    )

    result = sdk1.authorize(
        capability,
        "payments.send",
        {},
    )

    assert result.allowed is False

    sdk1.close()
    sdk2.close()


# ============================================================
# Close/reopen
# ============================================================


def test_close_then_reopen_does_not_clear_state(
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

    sdk.close()

    reopened = FirewallSDK(
        revocation_store_path=path
    )

    assert reopened.revocation.size() == 1
    assert reopened.is_revoked(
        capability
    )

    reopened.close()


# ============================================================
# Concurrent SDK access
# ============================================================


def test_concurrent_sdk_revoke_race(
    tmp_path,
):
    path = (
        tmp_path
        / "revocations.db"
    )

    clients = [
        FirewallSDK(
            revocation_store_path=path
        )
        for _ in range(8)
    ]

    capabilities = [
        make_capability(
            clients[0]
        )
        for _ in range(8)
    ]

    successes = []
    failures = []
    lock = threading.Lock()

    def worker(index):
        sdk = clients[index]
        capability = capabilities[index]

        try:
            sdk.revoke(
                capability
            )

            with lock:
                successes.append(index)

        except Exception as exc:
            with lock:
                failures.append(exc)

    threads = [
        threading.Thread(
            target=worker,
            args=(index,),
        )
        for index in range(8)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert len(successes) == 8
    assert failures == []

    verifier = FirewallSDK(
        revocation_store_path=path
    )

    for capability in capabilities:
        assert verifier.is_revoked(
            capability
        )

    for sdk in clients:
        sdk.close()

    verifier.close()


# ============================================================
# Persistent record integrity
# ============================================================


def test_reason_survives_all_restart_layers(
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
        reason="security incident",
    )

    sdk1.close()

    sdk2 = FirewallSDK(
        revocation_store_path=path
    )

    record = sdk2.revocation.get(
        sdk2.fingerprint(
            capability
        )
    )

    assert record is not None
    assert record.reason == (
        "security incident"
    )

    sdk2.close()


def test_persistent_records_are_not_duplicated(
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

    sdk.close()

    reopened = FirewallSDK(
        revocation_store_path=path
    )

    assert reopened.revocation.size() == 1
    assert len(
        reopened.revocation.records()
    ) == 1

    reopened.close()


# ============================================================
# Final invariant
# ============================================================


def test_persistent_revocation_is_final(
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
        capability
    )

    sdk1.close()

    sdk2 = FirewallSDK(
        revocation_store_path=path
    )

    sdk3 = FirewallSDK(
        revocation_store_path=path
    )

    assert sdk2.is_revoked(
        capability
    )

    assert sdk3.is_revoked(
        capability
    )

    assert not sdk2.is_authorized(
        capability,
        "payments.send",
        {},
    )

    assert not hasattr(
        sdk2.revocation,
        "unrevoke",
    )

    sdk2.close()
    sdk3.close()