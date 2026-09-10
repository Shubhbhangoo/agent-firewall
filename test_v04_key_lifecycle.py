from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

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


def test_new_key_is_active():
    identity = make_identity()

    verifier = IdentityVerifier(
        {"trusted-issuer"}
    )

    assert verifier.key_status(
        identity.public_key
    ) == "active"


def test_rotated_key_has_rotated_status():
    identity = make_identity()

    verifier = IdentityVerifier(
        {"trusted-issuer"}
    )

    verifier.rotate_key(
        identity.public_key
    )

    assert verifier.key_status(
        identity.public_key
    ) == "rotated"


def test_revoked_key_has_revoked_status():
    identity = make_identity()

    verifier = IdentityVerifier(
        {"trusted-issuer"}
    )

    verifier.revoke_key(
        identity.public_key
    )

    assert verifier.key_status(
        identity.public_key
    ) == "revoked"


def test_retired_key_has_retired_status():
    identity = make_identity()

    verifier = IdentityVerifier(
        {"trusted-issuer"}
    )

    verifier.retire_key(
        identity.public_key
    )

    assert verifier.key_status(
        identity.public_key
    ) == "retired"


def test_unknown_key_has_unknown_status():
    verifier = IdentityVerifier(
        {"trusted-issuer"}
    )

    assert verifier.key_status(
        "unknown-key"
    ) == "unknown"


def test_rotated_key_is_not_revoked():
    identity = make_identity()

    verifier = IdentityVerifier(
        {"trusted-issuer"}
    )

    verifier.rotate_key(
        identity.public_key
    )

    assert verifier.key_status(
        identity.public_key
    ) == "rotated"

    assert verifier.verify(
        identity
    ) is True


def test_revoked_key_is_not_accepted():
    identity = make_identity()

    verifier = IdentityVerifier(
        {"trusted-issuer"}
    )

    verifier.revoke_key(
        identity.public_key
    )

    assert verifier.key_status(
        identity.public_key
    ) == "revoked"

    assert verifier.verify(
        identity
    ) is False


def test_retired_key_is_not_accepted():
    identity = make_identity()

    verifier = IdentityVerifier(
        {"trusted-issuer"}
    )

    verifier.retire_key(
        identity.public_key
    )

    assert verifier.key_status(
        identity.public_key
    ) == "retired"

    assert verifier.verify(
        identity
    ) is False