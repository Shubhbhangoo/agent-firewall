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


def test_revocation_can_be_saved(tmp_path):
    identity = make_identity()

    store = tmp_path / "revoked_keys.json"

    verifier = IdentityVerifier(
        {"trusted-issuer"},
        revocation_file=str(store),
    )

    verifier.revoke_key(identity.public_key)

    assert identity.public_key in verifier.revoked_keys
    assert store.exists()


def test_revocation_survives_verifier_restart(tmp_path):
    identity = make_identity()

    store = tmp_path / "revoked_keys.json"

    verifier = IdentityVerifier(
        {"trusted-issuer"},
        revocation_file=str(store),
    )

    verifier.revoke_key(identity.public_key)

    verifier2 = IdentityVerifier(
        {"trusted-issuer"},
        revocation_file=str(store),
    )

    assert verifier2.verify(identity) is False


def test_unrevocation_persists(tmp_path):
    identity = make_identity()

    store = tmp_path / "revoked_keys.json"

    verifier = IdentityVerifier(
        {"trusted-issuer"},
        revocation_file=str(store),
    )

    verifier.revoke_key(identity.public_key)
    verifier.unrevoke_key(identity.public_key)

    verifier2 = IdentityVerifier(
        {"trusted-issuer"},
        revocation_file=str(store),
    )

    assert verifier2.verify(identity) is True


def test_multiple_revocations_persist(tmp_path):
    identity_a = make_identity()
    identity_b = make_identity()

    store = tmp_path / "revoked_keys.json"

    verifier = IdentityVerifier(
        {"trusted-issuer"},
        revocation_file=str(store),
    )

    verifier.revoke_key(identity_a.public_key)
    verifier.revoke_key(identity_b.public_key)

    verifier2 = IdentityVerifier(
        {"trusted-issuer"},
        revocation_file=str(store),
    )

    assert verifier2.verify(identity_a) is False
    assert verifier2.verify(identity_b) is False


def test_missing_revocation_file_starts_empty(tmp_path):
    store = tmp_path / "does_not_exist.json"

    verifier = IdentityVerifier(
        {"trusted-issuer"},
        revocation_file=str(store),
    )

    assert verifier.revoked_keys == set()