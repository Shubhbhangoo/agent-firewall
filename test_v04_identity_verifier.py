from firewall.identity import AgentIdentity, IdentityVerifier


def test_trusted_issuer_verifies_identity():
    verifier = IdentityVerifier({"trusted-issuer"})

    identity = AgentIdentity(
        agent_id="finance-agent",
        issuer="trusted-issuer",
    )

    assert verifier.verify(identity) is True


def test_untrusted_issuer_rejects_identity():
    verifier = IdentityVerifier({"trusted-issuer"})

    identity = AgentIdentity(
        agent_id="finance-agent",
        issuer="evil-issuer",
    )

    assert verifier.verify(identity) is False


def test_unknown_identity_type_is_rejected():
    verifier = IdentityVerifier({"trusted-issuer"})

    assert verifier.verify("finance-agent") is False


def test_empty_issuer_is_rejected():
    verifier = IdentityVerifier({"trusted-issuer"})

    identity = AgentIdentity(
        agent_id="finance-agent",
        issuer="",
    )

    assert verifier.verify(identity) is False


def test_empty_agent_id_is_rejected():
    verifier = IdentityVerifier({"trusted-issuer"})

    identity = AgentIdentity(
        agent_id="",
        issuer="trusted-issuer",
    )

    assert verifier.verify(identity) is False


def test_verified_identity_uses_agent_id():
    verifier = IdentityVerifier({"trusted-issuer"})

    identity = AgentIdentity(
        agent_id="finance-agent",
        issuer="trusted-issuer",
    )

    assert verifier.verify(identity) is True
    assert identity.agent_id == "finance-agent"


def test_spoofed_issuer_is_rejected():
    verifier = IdentityVerifier({"trusted-issuer"})

    identity = AgentIdentity(
        agent_id="admin-agent",
        issuer="evil-issuer",
    )

    assert verifier.verify(identity) is False


def test_identity_is_immutable():
    identity = AgentIdentity(
        agent_id="finance-agent",
        issuer="trusted-issuer",
    )

    try:
        identity.agent_id = "admin-agent"
        assert False, "Identity should be immutable"
    except AttributeError:
        pass


def test_multiple_trusted_issuers_are_supported():
    verifier = IdentityVerifier({
        "issuer-a",
        "issuer-b",
    })

    identity_a = AgentIdentity(
        agent_id="agent-a",
        issuer="issuer-a",
    )

    identity_b = AgentIdentity(
        agent_id="agent-b",
        issuer="issuer-b",
    )

    assert verifier.verify(identity_a) is True
    assert verifier.verify(identity_b) is True


def test_untrusted_issuer_remains_rejected_with_multiple_trusted_issuers():
    verifier = IdentityVerifier({
        "issuer-a",
        "issuer-b",
    })

    identity = AgentIdentity(
        agent_id="attacker-agent",
        issuer="evil-issuer",
    )

    assert verifier.verify(identity) is False


def test_none_identity_is_rejected():
    verifier = IdentityVerifier({"trusted-issuer"})

    assert verifier.verify(None) is False


def test_identity_agent_id_is_not_trimmed_or_normalized():
    verifier = IdentityVerifier({"trusted-issuer"})

    identity = AgentIdentity(
        agent_id="finance-agent ",
        issuer="trusted-issuer",
    )

    assert verifier.verify(identity) is True
    assert identity.agent_id == "finance-agent "