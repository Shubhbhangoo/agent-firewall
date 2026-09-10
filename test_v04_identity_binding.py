from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from firewall.identity import (
    IdentityVerifier,
    sign_identity,
)


def make_identity(agent_id):
    private_key = Ed25519PrivateKey.generate()

    return sign_identity(
        private_key,
        agent_id,
        "trusted-issuer",
    )


def test_identity_key_is_bound_to_agent():
    identity = make_identity(
        "finance-agent"
    )

    verifier = IdentityVerifier(
        {"trusted-issuer"}
    )

    assert verifier.verify(identity) is True


def test_same_key_cannot_be_reassigned_to_another_agent():
    identity = make_identity(
        "finance-agent"
    )

    from firewall.identity import AgentIdentity

    forged = AgentIdentity(
        agent_id="admin-agent",
        issuer=identity.issuer,
        public_key=identity.public_key,
        signature=identity.signature,
    )

    verifier = IdentityVerifier(
        {"trusted-issuer"}
    )

    assert verifier.verify(forged) is False


def test_same_key_cannot_change_issuer():
    identity = make_identity(
        "finance-agent"
    )

    from firewall.identity import AgentIdentity

    forged = AgentIdentity(
        agent_id=identity.agent_id,
        issuer="another-issuer",
        public_key=identity.public_key,
        signature=identity.signature,
    )

    verifier = IdentityVerifier(
        {
            "trusted-issuer",
            "another-issuer",
        }
    )

    assert verifier.verify(forged) is False


def test_different_agents_get_different_keys():
    identity_a = make_identity(
        "finance-agent"
    )

    identity_b = make_identity(
        "admin-agent"
    )

    assert (
        identity_a.public_key
        != identity_b.public_key
    )


def test_rotated_key_stays_bound_to_same_agent():
    old_identity = make_identity(
        "finance-agent"
    )

    new_identity = make_identity(
        "finance-agent"
    )

    verifier = IdentityVerifier(
        {"trusted-issuer"}
    )

    verifier.rotate_key(
        old_identity.public_key
    )

    assert verifier.verify(
        old_identity
    ) is True

    assert verifier.verify(
        new_identity
    ) is True

    assert (
        old_identity.agent_id
        == new_identity.agent_id
    )


def test_revoked_key_cannot_be_reused_by_another_agent():
    identity = make_identity(
        "finance-agent"
    )

    verifier = IdentityVerifier(
        {"trusted-issuer"}
    )

    verifier.revoke_key(
        identity.public_key
    )

    from firewall.identity import AgentIdentity

    forged = AgentIdentity(
        agent_id="admin-agent",
        issuer=identity.issuer,
        public_key=identity.public_key,
        signature=identity.signature,
    )

    assert verifier.verify(
        forged
    ) is False


def test_retired_key_cannot_be_reused():
    identity = make_identity(
        "finance-agent"
    )

    verifier = IdentityVerifier(
        {"trusted-issuer"}
    )

    verifier.retire_key(
        identity.public_key
    )

    assert verifier.verify(
        identity
    ) is False
    