import threading

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


def test_concurrent_revocations_do_not_corrupt_store(tmp_path):
    store = tmp_path / "revoked_keys.json"

    identities = [
        make_identity()
        for _ in range(20)
    ]

    verifier = IdentityVerifier(
        {"trusted-issuer"},
        revocation_file=str(store),
    )

    threads = [
        threading.Thread(
            target=verifier.revoke_key,
            args=(identity.public_key,),
        )
        for identity in identities
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    verifier2 = IdentityVerifier(
        {"trusted-issuer"},
        revocation_file=str(store),
    )

    for identity in identities:
        assert verifier2.verify(identity) is False


def test_concurrent_revocation_and_unrevocation_is_safe(tmp_path):
    store = tmp_path / "revoked_keys.json"

    identity = make_identity()

    verifier = IdentityVerifier(
        {"trusted-issuer"},
        revocation_file=str(store),
    )

    def revoke():
        for _ in range(20):
            verifier.revoke_key(
                identity.public_key
            )

    def unrevoke():
        for _ in range(20):
            verifier.unrevoke_key(
                identity.public_key
            )

    threads = [
        threading.Thread(target=revoke),
        threading.Thread(target=unrevoke),
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    verifier2 = IdentityVerifier(
        {"trusted-issuer"},
        revocation_file=str(store),
    )

    assert isinstance(
        verifier2.revoked_keys,
        set,
    )


def test_concurrent_same_key_revocation_is_idempotent(tmp_path):
    store = tmp_path / "revoked_keys.json"

    identity = make_identity()

    verifier = IdentityVerifier(
        {"trusted-issuer"},
        revocation_file=str(store),
    )

    threads = [
        threading.Thread(
            target=verifier.revoke_key,
            args=(identity.public_key,),
        )
        for _ in range(50)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    verifier2 = IdentityVerifier(
        {"trusted-issuer"},
        revocation_file=str(store),
    )

    assert verifier2.verify(identity) is False
    assert len(verifier2.revoked_keys) == 1