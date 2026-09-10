"""Canonical provenance and confidence primitives for the v2.2 platform.

There is exactly one provenance vocabulary in Agent Firewall. It already
existed in :mod:`firewall.network.model` as :class:`Provenance`, and the
v2.2 control plane re-exports that same class rather than defining a
competing enum. Every v2.2 subsystem imports it from here.

Two rules are enforced structurally, not by convention:

1. **Inference is never promoted to fact.** :func:`combine` takes the
   *weakest* provenance of its inputs. A conclusion drawn from one
   observed fact and one inferred fact is inferred.
2. **Simulation stays simulated.** Anything derived from a simulated
   input is simulated, regardless of how strong the other inputs are.
   :data:`Provenance.SIMULATED` therefore ranks below ``inferred`` and
   is additionally sticky: see :func:`combine`.

Evidence events use a different, deliberately separate vocabulary
(:class:`firewall.evidence_graph.EvidenceKind`) because evidence can be
a ``prediction`` while an analysis fact cannot. :func:`to_evidence_kind`
is the only sanctioned bridge between the two.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Optional

from firewall.evidence_graph import EvidenceKind

# Single canonical provenance vocabulary. Aliased, never redefined.
from firewall.network.model import Provenance

__all__ = [
    "Provenance",
    "PROVENANCE_RANK",
    "Confidence",
    "combine",
    "is_factual",
    "to_evidence_kind",
    "from_evidence_kind",
    "coerce",
]


#: Strength ordering, weakest first. Mirrors ``attackgraph._BASIS_RANK``
#: so a path basis and a finding provenance are directly comparable.
PROVENANCE_RANK: dict[str, int] = {
    Provenance.UNKNOWN.value: 0,
    Provenance.SIMULATED.value: 1,
    Provenance.INFERRED.value: 2,
    Provenance.DERIVED.value: 3,
    Provenance.OBSERVED.value: 4,
}


def coerce(value: Any) -> Provenance:
    """Normalize a string/enum into :class:`Provenance`.

    Unrecognized input becomes ``UNKNOWN`` rather than raising: a
    security conclusion built on an unparseable basis must degrade to
    the weakest claim, never to a strong one.
    """

    if isinstance(value, Provenance):
        return value
    if isinstance(value, str):
        try:
            return Provenance(value)
        except ValueError:
            return Provenance.UNKNOWN
    return Provenance.UNKNOWN


def combine(*values: Any) -> Provenance:
    """Weakest-wins combination, with ``SIMULATED`` sticky.

    ``combine()`` with no arguments is ``UNKNOWN`` -- a conclusion with
    no stated basis is not a fact.
    """

    levels = [coerce(v) for v in values]
    if not levels:
        return Provenance.UNKNOWN

    # Simulation isolation: a simulated input taints the conclusion even
    # when another input is merely UNKNOWN-ranked lower. Simulated
    # results must never be mistaken for production observations.
    if any(level is Provenance.SIMULATED for level in levels):
        return Provenance.SIMULATED

    return min(levels, key=lambda level: PROVENANCE_RANK[level.value])


def is_factual(value: Any) -> bool:
    """True only for ``observed`` and ``derived``.

    ``derived`` is factual because it is a deterministic consequence of
    recorded authority. ``inferred``, ``simulated`` and ``unknown`` are
    not facts and must never be presented as such.
    """

    return coerce(value) in (Provenance.OBSERVED, Provenance.DERIVED)


def to_evidence_kind(value: Any) -> EvidenceKind:
    """Map analysis provenance onto an evidence-event kind."""

    level = coerce(value)
    if level is Provenance.OBSERVED:
        return EvidenceKind.OBSERVED
    if level is Provenance.DERIVED:
        # A derived fact is a deterministic consequence of observed
        # authority, but the evidence graph has no `derived` kind and
        # recording it as `observed` would overstate it.
        return EvidenceKind.INFERENCE
    if level is Provenance.INFERRED:
        return EvidenceKind.INFERENCE
    if level is Provenance.SIMULATED:
        return EvidenceKind.SIMULATION
    return EvidenceKind.UNKNOWN


def from_evidence_kind(value: Any) -> Provenance:
    """Map an evidence-event kind back onto analysis provenance."""

    raw = value.value if isinstance(value, EvidenceKind) else str(value)
    if raw == EvidenceKind.OBSERVED.value:
        return Provenance.OBSERVED
    if raw == EvidenceKind.INFERENCE.value:
        return Provenance.INFERRED
    if raw == EvidenceKind.PREDICTION.value:
        # A prediction is a statement about the future; it can never be
        # stronger than an inference.
        return Provenance.INFERRED
    if raw == EvidenceKind.SIMULATION.value:
        return Provenance.SIMULATED
    return Provenance.UNKNOWN


@dataclass(frozen=True)
class Confidence:
    """A bounded confidence score paired with its provenance.

    Confidence alone is meaningless: 0.9 from an inference is a
    different kind of claim than 0.9 from an observation. The two
    always travel together, and :meth:`combine` degrades both.
    """

    score: float
    provenance: Provenance = Provenance.UNKNOWN
    basis: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if isinstance(self.score, bool) or not isinstance(
            self.score, (int, float)
        ):
            raise TypeError("score must be a number")
        if not 0.0 <= float(self.score) <= 1.0:
            raise ValueError("score must be within [0.0, 1.0]")
        object.__setattr__(self, "score", float(self.score))
        object.__setattr__(self, "provenance", coerce(self.provenance))
        object.__setattr__(self, "basis", tuple(str(b) for b in self.basis))

    @property
    def factual(self) -> bool:
        return is_factual(self.provenance)

    def combine(self, other: "Confidence") -> "Confidence":
        """Conservative combination: min score, weakest provenance."""

        return Confidence(
            score=min(self.score, other.score),
            provenance=combine(self.provenance, other.provenance),
            basis=tuple(dict.fromkeys(self.basis + other.basis)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "provenance": self.provenance.value,
            "basis": list(self.basis),
            "factual": self.factual,
        }
