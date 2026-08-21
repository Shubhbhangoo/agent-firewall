import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from firewall.identity import (
    AgentIdentity,
    IdentityVerifier,
    sign_identity,
)


def make_identity(
    agent_id="finance-agent",
    issuer="trusted-issuer",
):
    private_key = Ed25519PrivateKey.generate()

    identity = sign_identity(
        private_key,
        agent_id,
        issuer,
    )

    return identity, private_key


def test_trusted_issuer_verifies_signed_identity():
    identity, _ = make_identity()

    verifier = IdentityVerifier({"trusted-issuer"})

    assert verifier.verify(identity) is True


def test_untrusted_issuer_rejects_signed_identity():
    identity, _ = make_identity(
        issuer="evil-issuer",
    )

    verifier = IdentityVerifier({"trusted-issuer"})

    assert verifier.verify(identity) is False


def test_unknown_identity_type_is_rejected():
    verifier = IdentityVerifier({"trusted-issuer"})

    assert verifier.verify("finance-agent") is False


def test_empty_issuer_is_rejected():
    identity, _ = make_identity(
        issuer="trusted-issuer",
    )

    identity = AgentIdentity(
        agent_id=identity.agent_id,
        issuer="",
        public_key=identity.public_key,
        signature=identity.signature,
    )

    verifier = IdentityVerifier({"trusted-issuer"})

    assert verifier.verify(identity) is False


def test_empty_agent_id_is_rejected():
    identity, _ = make_identity()

    identity = AgentIdentity(
        agent_id="",
        issuer=identity.issuer,
        public_key=identity.public_key,
        signature=identity.signature,
    )

    verifier = IdentityVerifier({"trusted-issuer"})

    assert verifier.verify(identity) is False


def test_verified_identity_uses_agent_id():
    identity, _ = make_identity()

    verifier = IdentityVerifier({"trusted-issuer"})

    assert verifier.verify(identity) is True
    assert identity.agent_id == "finance-agent"


def test_spoofed_issuer_is_rejected():
    identity, _ = make_identity()

    tampered = AgentIdentity(
        agent_id=identity.agent_id,
        issuer="evil-issuer",
        public_key=identity.public_key,
        signature=identity.signature,
    )

    verifier = IdentityVerifier({"trusted-issuer"})

    assert verifier.verify(tampered) is False


def test_multiple_trusted_issuers_are_supported():
    identity_a, _ = make_identity(
        agent_id="agent-a",
        issuer="issuer-a",
    )

    identity_b, _ = make_identity(
        agent_id="agent-b",
        issuer="issuer-b",
    )

    verifier = IdentityVerifier({
        "issuer-a",
        "issuer-b",
    })

    assert verifier.verify(identity_a) is True
    assert verifier.verify(identity_b) is True


def test_untrusted_issuer_remains_rejected():
    identity, _ = make_identity(
        agent_id="attacker-agent",
        issuer="evil-issuer",
    )

    verifier = IdentityVerifier({
        "issuer-a",
        "issuer-b",
    })

    assert verifier.verify(identity) is False


def test_none_identity_is_rejected():
    verifier = IdentityVerifier({"trusted-issuer"})

    assert verifier.verify(None) is False


def test_identity_agent_id_is_not_normalized():
    identity, _ = make_identity(
        agent_id="finance-agent ",
    )

    verifier = IdentityVerifier({"trusted-issuer"})

    assert verifier.verify(identity) is True
    assert identity.agent_id == "finance-agent "


def test_tampered_signature_is_rejected():
    identity, _ = make_identity()

    tampered_signature = base64.b64encode(
        b"tampered"
    ).decode("ascii")

    tampered = AgentIdentity(
        agent_id=identity.agent_id,
        issuer=identity.issuer,
        public_key=identity.public_key,
        signature=tampered_signature,
    )

    verifier = IdentityVerifier({"trusted-issuer"})

    assert verifier.verify(tampered) is False


def test_tampered_public_key_is_rejected():
    identity, _ = make_identity()

    other_private_key = Ed25519PrivateKey.generate()

    other_public_key = base64.b64encode(
        other_private_key.public_key().public_bytes_raw()
    ).decode("ascii")

    tampered = AgentIdentity(
        agent_id=identity.agent_id,
        issuer=identity.issuer,
        public_key=other_public_key,
        signature=identity.signature,
    )

    verifier = IdentityVerifier({"trusted-issuer"})

    assert verifier.verify(tampered) is False