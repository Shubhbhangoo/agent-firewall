"""Cryptographic Attestation (v2.0).

Signed, versioned statements about security-relevant facts under agent
identity keys, with explicit algorithm metadata, key fingerprints, and
a three-state verifier (verified / failed / unverifiable).
"""

from firewall.attest.authority import (
    ATTESTATION_VERSION,
    SUPPORTED_ALGORITHMS,
    Attestation,
    AttestationAuthority,
    AttestationError,
)

__all__ = [
    "ATTESTATION_VERSION",
    "SUPPORTED_ALGORITHMS",
    "Attestation",
    "AttestationAuthority",
    "AttestationError",
]
