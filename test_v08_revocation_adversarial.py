import threading

import pytest

from firewall.capability import (
    capability_fingerprint,
    generate_capability_key_pair,
    sign_capability,
)

from firewall.engine import Firewall
from firewall.http import HTTPFirewall, HTTPAuthorizationError, HTTPRequest
from firewall.mcp import MCPFirewall, MCPAuthorizationError, MCPRequest
from firewall.revocation import (
    AlreadyRevokedError,
    RevocationRegistry,
)


class AgentFixture:
    def __init__(self, agent_id, capabilities):
        self.agent_id = agent_id
        self.capabilities = list(capabilities)
        self.authenticated = True


def make_capability(
    *,
    agent="agent-a",
    capability="payments.send",
    constraints=None,
):
    private_key, _ = generate_capability_key_pair()

    return sign_capability(
        private_key=private_key,
        agent_id=agent,
        capability=capability,
        constraints=(
            {}
            if constraints is None
            else constraints
        ),
        issuer="trusted-issuer",
    )


def make_firewall(tmp_path):
    import yaml

    policy = tmp_path / "policies.yaml"

    policy.write_text(
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

    return Firewall(str(policy))


# ============================================================
# Registry attacks
# ============================================================


def test_revocation_is_one_way():
    registry = RevocationRegistry()

    registry.revoke(
        "fingerprint-1"
    )

    assert registry.is_revoked(
        "fingerprint-1"
    )

    assert not hasattr(
        registry,
        "unrevoke",
    )


def test_revocation_cannot_be_overwritten():
    registry = RevocationRegistry()

    first = registry.revoke(
        "fingerprint-1",
        reason="compromised",
    )

    with pytest.raises(
        AlreadyRevokedError
    ):
        registry.revoke(
            "fingerprint-1",
            reason="different",
        )

    current = registry.get(
        "fingerprint-1"
    )

    assert current == first


def test_revocation_fingerprint_is_exact():
    registry = RevocationRegistry()

    registry.revoke(
        "abc123"
    )

    assert registry.is_revoked("abc123")
    assert not registry.is_revoked("abc124")
    assert not registry.is_revoked("ABC123")


# ============================================================
# Capability isolation
# ============================================================


def test_revoking_one_capability_does_not_revoke_peer():
    registry = RevocationRegistry()

    first = make_capability(
        capability="payments.send"
    )

    second = make_capability(
        capability="payments.send"
    )

    registry.revoke(
        capability_fingerprint(first)
    )

    assert registry.is_revoked(
        capability_fingerprint(first)
    )

    assert not registry.is_revoked(
        capability_fingerprint(second)
    )


def test_same_scope_different_agent_isolated():
    registry = RevocationRegistry()

    first = make_capability(
        agent="agent-a"
    )

    second = make_capability(
        agent="agent-b"
    )

    registry.revoke(
        capability_fingerprint(first)
    )

    assert registry.is_revoked(
        capability_fingerprint(first)
    )

    assert not registry.is_revoked(
        capability_fingerprint(second)
    )


# ============================================================
# Engine attacks
# ============================================================


def test_revoked_capability_cannot_pass_engine(
    tmp_path,
):
    capability = make_capability()

    agent = AgentFixture(
        "agent-a",
        [capability],
    )

    firewall = make_firewall(tmp_path)

    firewall.revoke_capability(
        capability
    )

    decision = firewall.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert decision.action == "deny"


def test_revoked_capability_cannot_be_rescued_by_policy(
    tmp_path,
):
    capability = make_capability()

    agent = AgentFixture(
        "agent-a",
        [capability],
    )

    firewall = make_firewall(tmp_path)

    firewall.revoke_capability(
        capability
    )

    decision = firewall.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert decision.action == "deny"


def test_revoked_capability_cannot_bypass_with_wildcard(
    tmp_path,
):
    capability = make_capability(
        capability="payments.*"
    )

    agent = AgentFixture(
        "agent-a",
        [capability],
    )

    firewall = make_firewall(tmp_path)

    firewall.revoke_capability(
        capability
    )

    decision = firewall.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert decision.action == "deny"


def test_valid_peer_capability_still_works_after_revocation(
    tmp_path,
):
    revoked = make_capability(
        capability="payments.send"
    )

    valid = make_capability(
        capability="payments.send"
    )

    agent = AgentFixture(
        "agent-a",
        [revoked, valid],
    )

    firewall = make_firewall(tmp_path)

    firewall.revoke_capability(
        revoked
    )

    decision = firewall.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert decision.action == "allow"


def test_all_matching_capabilities_revoked_denies(
    tmp_path,
):
    first = make_capability(
        capability="payments.send"
    )

    second = make_capability(
        capability="payments.send"
    )

    agent = AgentFixture(
        "agent-a",
        [first, second],
    )

    firewall = make_firewall(tmp_path)

    firewall.revoke_capability(first)
    firewall.revoke_capability(second)

    decision = firewall.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert decision.action == "deny"


# ============================================================
# Replay + revocation
# ============================================================


def test_revoked_capability_cannot_use_replay_nonce(
    tmp_path,
):
    capability = make_capability()

    agent = AgentFixture(
        "agent-a",
        [capability],
    )

    firewall = make_firewall(tmp_path)

    firewall.revoke_capability(
        capability
    )

    decision = firewall.check(
        agent,
        "payments.send",
        {
            "amount": 10,
            "nonce": "nonce-1",
        },
    )

    assert decision.action == "deny"


def test_revocation_happens_before_replay_acceptance(
    tmp_path,
):
    capability = make_capability()

    agent = AgentFixture(
        "agent-a",
        [capability],
    )

    firewall = make_firewall(tmp_path)

    firewall.revoke_capability(
        capability
    )

    first = firewall.check(
        agent,
        "payments.send",
        {
            "amount": 10,
            "nonce": "same",
        },
    )

    second = firewall.check(
        agent,
        "payments.send",
        {
            "amount": 10,
            "nonce": "same",
        },
    )

    assert first.action == "deny"
    assert second.action == "deny"


# ============================================================
# MCP revocation attacks
# ============================================================


def test_revoked_capability_denied_by_mcp():
    from firewall.sdk import FirewallSDK

    sdk = FirewallSDK()

    capability = make_capability()

    sdk.revoke(
        capability
    )

    token = sdk.encode(
        capability
    )

    firewall = MCPFirewall(sdk)

    request = MCPRequest(
        agent="agent-a",
        tool="payments.send",
        arguments={},
        capability_token=token,
        nonce="mcp-1",
    )

    decision = firewall.authorize(
        request
    )

    assert decision.allowed is False


def test_revoked_mcp_capability_never_reaches_handler():
    from firewall.sdk import FirewallSDK

    sdk = FirewallSDK()

    capability = make_capability()

    sdk.revoke(
        capability
    )

    request = MCPRequest(
        agent="agent-a",
        tool="payments.send",
        arguments={},
        capability_token=sdk.encode(
            capability
        ),
        nonce="mcp-handler-1",
    )

    firewall = MCPFirewall(sdk)

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


# ============================================================
# HTTP revocation attacks
# ============================================================


def test_revoked_capability_denied_by_http():
    from firewall.sdk import FirewallSDK

    sdk = FirewallSDK()

    capability = make_capability()

    sdk.revoke(
        capability
    )

    firewall = HTTPFirewall(sdk)

    request = HTTPRequest(
        agent="agent-a",
        method="POST",
        path="/payments",
        arguments={},
        capability_token=sdk.encode(
            capability
        ),
        nonce="http-1",
    )

    decision = firewall.authorize(
        request
    )

    assert decision.allowed is False


def test_revoked_http_capability_never_reaches_handler():
    from firewall.sdk import FirewallSDK

    sdk = FirewallSDK()

    capability = make_capability()

    sdk.revoke(
        capability
    )

    firewall = HTTPFirewall(sdk)

    request = HTTPRequest(
        agent="agent-a",
        method="POST",
        path="/payments",
        arguments={},
        capability_token=sdk.encode(
            capability
        ),
        nonce="http-handler-1",
    )

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


# ============================================================
# Revocation after transport creation
# ============================================================


def test_revocation_invalidates_existing_transport_token():
    from firewall.sdk import FirewallSDK

    sdk = FirewallSDK()

    capability = make_capability()

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


def test_revocation_invalidates_existing_mcp_token():
    from firewall.sdk import FirewallSDK

    sdk = FirewallSDK()

    capability = make_capability()

    token = sdk.encode(
        capability
    )

    sdk.revoke(
        capability
    )

    firewall = MCPFirewall(sdk)

    request = MCPRequest(
        agent="agent-a",
        tool="payments.send",
        arguments={},
        capability_token=token,
        nonce="existing-mcp-token",
    )

    assert (
        firewall.authorize(
            request
        ).allowed
        is False
    )


def test_revocation_invalidates_existing_http_token():
    from firewall.sdk import FirewallSDK

    sdk = FirewallSDK()

    capability = make_capability()

    token = sdk.encode(
        capability
    )

    sdk.revoke(
        capability
    )

    firewall = HTTPFirewall(sdk)

    request = HTTPRequest(
        agent="agent-a",
        method="POST",
        path="/payments",
        arguments={},
        capability_token=token,
        nonce="existing-http-token",
    )

    assert (
        firewall.authorize(
            request
        ).allowed
        is False
    )


# ============================================================
# Concurrent revocation
# ============================================================


def test_concurrent_revocation_has_single_winner():
    registry = RevocationRegistry()

    successes = []
    failures = []
    lock = threading.Lock()

    def revoke():
        try:
            registry.revoke(
                "concurrent-fingerprint"
            )

            with lock:
                successes.append(True)

        except AlreadyRevokedError:
            with lock:
                failures.append(True)

    threads = [
        threading.Thread(
            target=revoke
        )
        for _ in range(32)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert len(successes) == 1
    assert len(failures) == 31

    assert registry.is_revoked(
        "concurrent-fingerprint"
    )


def test_concurrent_revocation_of_different_capabilities():
    registry = RevocationRegistry()

    capabilities = [
        make_capability(
            agent=f"agent-{index}"
        )
        for index in range(16)
    ]

    threads = []

    for capability in capabilities:
        fingerprint = capability_fingerprint(
            capability
        )

        thread = threading.Thread(
            target=registry.revoke,
            args=(fingerprint,),
        )

        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    assert registry.size() == 16


# ============================================================
# Capability immutability
# ============================================================


def test_revocation_does_not_modify_signature():
    capability = make_capability()

    before = capability.to_dict()

    registry = RevocationRegistry()

    registry.revoke(
        capability_fingerprint(
            capability
        )
    )

    after = capability.to_dict()

    assert after == before


def test_revocation_does_not_change_fingerprint():
    capability = make_capability()

    before = capability_fingerprint(
        capability
    )

    registry = RevocationRegistry()

    registry.revoke(before)

    after = capability_fingerprint(
        capability
    )

    assert after == before


# ============================================================
# Expiration + revocation interaction
# ============================================================


def test_expired_and_revoked_capability_remains_denied(
    tmp_path,
):
    from firewall.sdk import FirewallSDK

    now = [1000.0]

    sdk = FirewallSDK(
        clock=lambda: now[0]
    )

    private_key, _ = (
        generate_capability_key_pair()
    )

    capability = sdk.issue(
        private_key=private_key,
        agent="agent-a",
        capability="payments.send",
        issued_at=900,
        expires_at=1100,
    )

    sdk.revoke(
        capability
    )

    now[0] = 1200.0

    result = sdk.authorize(
        capability,
        "payments.send",
        {},
    )

    assert result.allowed is False


# ============================================================
# Final invariant
# ============================================================


def test_revocation_is_stronger_than_existing_valid_token():
    from firewall.sdk import FirewallSDK

    sdk = FirewallSDK()

    capability = make_capability()

    token = sdk.encode(
        capability
    )

    # Token is valid before revocation.
    assert (
        sdk.decode_verified(token)
        .to_dict()
        == capability.to_dict()
    )

    sdk.revoke(
        capability
    )

    # Same token must no longer authorize.
    with pytest.raises(Exception):
        sdk.decode_verified(
            token
        )

    assert not sdk.is_authorized(
        capability,
        "payments.send",
        {},
    )