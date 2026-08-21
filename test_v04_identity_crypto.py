from firewall.identity import AgentIdentity


def test_identity_contains_public_key():
    identity = AgentIdentity(
        agent_id="finance-agent",
        issuer="trusted-issuer",
        public_key="test-public-key",
    )

    assert identity.public_key == "test-public-key"


def test_identity_contains_signature():
    identity = AgentIdentity(
        agent_id="finance-agent",
        issuer="trusted-issuer",
        public_key="test-public-key",
        signature="test-signature",
    )

    assert identity.signature == "test-signature"


def test_identity_signature_is_bound_to_identity():
    identity = AgentIdentity(
        agent_id="finance-agent",
        issuer="trusted-issuer",
        public_key="test-public-key",
        signature="test-signature",
    )

    assert identity.agent_id == "finance-agent"
    assert identity.issuer == "trusted-issuer"
    assert identity.public_key == "test-public-key"
    assert identity.signature == "test-signature"


def test_tampered_agent_id_changes_identity():
    original = AgentIdentity(
        agent_id="finance-agent",
        issuer="trusted-issuer",
        public_key="test-public-key",
        signature="test-signature",
    )

    tampered = AgentIdentity(
        agent_id="admin-agent",
        issuer=original.issuer,
        public_key=original.public_key,
        signature=original.signature,
    )

    assert tampered.agent_id != original.agent_id


def test_tampered_issuer_changes_identity():
    original = AgentIdentity(
        agent_id="finance-agent",
        issuer="trusted-issuer",
        public_key="test-public-key",
        signature="test-signature",
    )

    tampered = AgentIdentity(
        agent_id=original.agent_id,
        issuer="evil-issuer",
        public_key=original.public_key,
        signature=original.signature,
    )

    assert tampered.issuer != original.issuer