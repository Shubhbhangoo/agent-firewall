"""Cross-Agent Trust Graph (v2.0).

Trust-centric queries over the verified network graph (who_delegated,
what_changed, blast_radius, path) plus heuristic danger detection
(excessive authority, dangerous delegation, privilege escalation
paths) that is always labeled inferred/derived -- never observation.
"""

from firewall.trust.graph import (
    TrustError,
    TrustGraph,
    _is_sensitive,
)

__all__ = [
    "TrustError",
    "TrustGraph",
    "_is_sensitive",
]
