"""Agent Security Passport (v2.0).

A deterministic, versioned, signed summary of an agent's security
identity and posture. Never contains private keys; independently
verifiable against the recorded identity key.
"""

from firewall.passport.builder import (
    PASSPORT_VERSION,
    Passport,
    PassportBuilder,
    PassportError,
)

__all__ = [
    "PASSPORT_VERSION",
    "Passport",
    "PassportBuilder",
    "PassportError",
]
