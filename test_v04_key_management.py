from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from firewall.identity import (
    IdentityVerifier,
    sign_identity,
)


def make_identity(agent_id, issuer):
    private_key = Ed25519PrivateKey.generate()

    identity = sign_identity(
        private_key,
        agent_id,
        issuer,
    )

    return identity, private_key


def test_active_key_is_accepted():
    identity, _ = make_identity(
        "finance-agent",
        "trusted-issuer",
    )

    verifier = IdentityVerifier(
        {"trusted-issuer"}
    )

    assert verifier.verify(identity) is True


def test_revoked_issuer_is_rejected():
    identity, _ = make_identity(
        "finance-agent",
        "revoked-issuer",
    )

    verifier = IdentityVerifier(
        {"trusted-issuer"}
    )

    assert verifier.verify(identity) is False


def test_rotated_key_can_replace_old_key():
    old_identity, _ = make_identity(
        "finance-agent",
        "trusted-issuer",
    )

    new_identity, _ = make_identity(
        "finance-agent",
        "trusted-issuer",
    )

    verifier = IdentityVerifier(
        {"trusted-issuer"}
    )

    assert verifier.verify(old_identity) is True
    assert verifier.verify(new_identity) is True

    assert (
        old_identity.public_key
        != new_identity.public_key
    )


def test_revoked_issuer_does_not_affect_other_trusted_issuer():
    active_identity, _ = make_identity(
        "finance-agent",
        "trusted-issuer",
    )

    revoked_identity, _ = make_identity(
        "old-finance-agent",
        "revoked-issuer",
    )

    verifier = IdentityVerifier(
        {
            "trusted-issuer",
        }
    )

    assert verifier.verify(active_identity) is True
    assert verifier.verify(revoked_identity) is False


def test_key_rotation_preserves_agent_id():
    old_identity, _ = make_identity(
        "finance-agent",
        "trusted-issuer",
    )

    new_identity, _ = make_identity(
        "finance-agent",
        "trusted-issuer",
    )

    assert old_identity.agent_id == new_identity.agent_id


def test_key_rotation_changes_public_key():
    old_identity, _ = make_identity(
        "finance-agent",
        "trusted-issuer",
    )

    new_identity, _ = make_identity(
        "finance-agent",
        "trusted-issuer",
    )

    assert (
        old_identity.public_key
        != new_identity.public_key
    )


def test_invalid_rotated_key_is_rejected():
    identity, _ = make_identity(
        "finance-agent",
        "trusted-issuer",
    )

    verifier = IdentityVerifier(
        {"trusted-issuer"}
    )

    assert verifier.verify(identity) is True

    assert verifier.verify(
        type(identity)(
            agent_id=identity.agent_id,
            issuer=identity.issuer,
            public_key=identity.public_key,
            signature="invalid-signature",
        )
    ) is False