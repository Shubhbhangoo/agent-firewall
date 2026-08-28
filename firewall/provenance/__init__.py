"""Supply-Chain Provenance (v2.0).

Tracks integrity and trust for the components agents depend on
(models, tools, MCP servers, skills, plugins, packages, adapters,
configuration, policies). A name is never trust: trust requires an
explicit decision, and revoked dependencies make dependents untrusted.
"""

from firewall.provenance.registry import (
    COMPONENT_KINDS,
    COMPONENT_STATUSES,
    Component,
    ProvenanceError,
    ProvenanceRegistry,
    digest_file,
    sha256_digest,
)

__all__ = [
    "COMPONENT_KINDS",
    "COMPONENT_STATUSES",
    "Component",
    "ProvenanceError",
    "ProvenanceRegistry",
    "digest_file",
    "sha256_digest",
]
