"""Agent Identity (v2.0).

First-class, persistent, cryptographically bound agent identity with a
full lifecycle (create, rotate, revoke, retire), parent/child
relationships, atomic persistence, and honest verification. Identity
never implies authorization: it answers *who*, the authorization
pipeline alone answers *may*.
"""

from firewall.ident.registry import (
    IDENTITY_STATUSES,
    IDENTITY_VERSION,
    Identity,
    IdentityError,
    IdentityRegistry,
    generate_key_pair,
)

__all__ = [
    "IDENTITY_STATUSES",
    "IDENTITY_VERSION",
    "Identity",
    "IdentityError",
    "IdentityRegistry",
    "generate_key_pair",
]
