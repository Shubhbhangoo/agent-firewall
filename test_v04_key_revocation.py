from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from firewall.identity import (
    IdentityVerifier,
    sign_identity,
)


def make_identity(agent_id="finance-agent"):
    private_key = Ed25519PrivateKey.generate()

    identity = sign_identity(
        private_key,
        agent_id,
        "trusted-issuer",
    )

    return identity


def test_active_key_is_accepted():
    identity = make_identity()

    verifier = IdentityVerifier(
        {"trusted-issuer"}
    )

    assert verifier.verify(identity) is True


def test_revoked_public_key_is_rejected():
    identity = make_identity()

    verifier = IdentityVerifier(
        {"trusted-issuer"}
    )

    assert verifier.verify(identity) is True

    verifier.revoke_key(
        identity.public_key
    )

    assert verifier.verify(identity) is False


def test_revoking_one_key_does_not_revoke_another():
    identity_a = make_identity(
        "finance-agent"
    )

    identity_b = make_identity(
        "admin-agent"
    )

    verifier = IdentityVerifier(
        {"trusted-issuer"}
    )

    verifier.revoke_key(
        identity_a.public_key
    )

    assert verifier.verify(identity_a) is False
    assert verifier.verify(identity_b) is True


def test_unrevoke_restores_key():
    identity = make_identity()

    verifier = IdentityVerifier(
        {"trusted-issuer"}
    )

    verifier.revoke_key(
        identity.public_key
    )

    assert verifier.verify(identity) is False

    verifier.unrevoke_key(
        identity.public_key
    )

    assert verifier.verify(identity) is True


def test_revoked_key_remains_rejected():
    identity = make_identity()

    verifier = IdentityVerifier(
        {"trusted-issuer"}
    )

    verifier.revoke_key(
        identity.public_key
    )

    assert verifier.verify(identity) is False
    assert verifier.verify(identity) is False


def test_revoking_unknown_key_is_safe():
    verifier = IdentityVerifier(
        {"trusted-issuer"}
    )

    verifier.revoke_key(
        "unknown-public-key"
    )


def test_revoked_key_does_not_affect_new_rotated_key():
    old_identity = make_identity(
        "finance-agent"
    )

    new_identity = make_identity(
        "finance-agent"
    )

    verifier = IdentityVerifier(
        {"trusted-issuer"}
    )

    verifier.revoke_key(
        old_identity.public_key
    )

    assert verifier.verify(old_identity) is False
    assert verifier.verify(new_identity) is True