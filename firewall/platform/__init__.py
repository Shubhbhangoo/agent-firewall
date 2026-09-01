"""v2.2 platform primitives shared by every analytical subsystem.

This package holds the vocabulary the v2.2 subsystems agree on. It holds
no authorization logic and cannot grant permission; everything here
describes *how strongly something is known*, which is an input to
analysis and reporting, never a decision.

The one rule worth stating up front: nothing in this package may define
a second copy of a concept that already exists elsewhere in the
codebase. :mod:`firewall.platform.provenance` re-exports
:class:`firewall.network.model.Provenance` rather than declaring a
parallel enum, precisely so that a finding's provenance and an attack
path's basis remain directly comparable.
"""

from firewall.platform.provenance import (
    PROVENANCE_RANK,
    Confidence,
    Provenance,
    coerce,
    combine,
    from_evidence_kind,
    is_factual,
    to_evidence_kind,
)

__all__ = [
    "PROVENANCE_RANK",
    "Confidence",
    "Provenance",
    "coerce",
    "combine",
    "from_evidence_kind",
    "is_factual",
    "to_evidence_kind",
]
