"""v2.2 §13 evidence model: provenance and confidence primitives.

Three claims are load-bearing across the whole v2.2 analytical stack and
are asserted here rather than trusted:

* ``inferred != observed`` -- an inference never becomes a fact by being
  combined with one.
* ``simulated != observed`` -- simulated inputs taint every conclusion
  drawn from them, and the taint cannot be diluted.
* ``unknown != trusted`` -- an unreadable or unstated basis degrades to
  the weakest claim, never to a strong one.

There is deliberately one provenance vocabulary in the codebase.
``firewall.platform`` re-exports ``firewall.network.model.Provenance``
instead of declaring a parallel enum, so a finding's provenance and an
attack path's basis stay directly comparable. The identity test below
pins that.
"""

import pytest

from firewall.evidence_graph import EvidenceKind
from firewall.network.model import Provenance as NetworkProvenance
from firewall.platform import (
    PROVENANCE_RANK,
    Confidence,
    Provenance,
    coerce,
    combine,
    from_evidence_kind,
    is_factual,
    to_evidence_kind,
)


# --------------------------------------------------------------------------
# One vocabulary
# --------------------------------------------------------------------------


def test_platform_provenance_is_the_network_provenance():
    """Not a copy, not a subclass -- the same class object.

    Two enums with the same member names would compare unequal, so a
    finding's provenance and an attack path's basis would silently never
    match. Aliasing is the point of the module.
    """
    assert Provenance is NetworkProvenance


def test_every_provenance_member_has_a_rank():
    """A new member without a rank would raise a KeyError inside combine."""
    for member in Provenance:
        assert member.value in PROVENANCE_RANK


def test_rank_order_is_weakest_first():
    assert (
        PROVENANCE_RANK[Provenance.UNKNOWN.value]
        < PROVENANCE_RANK[Provenance.SIMULATED.value]
        < PROVENANCE_RANK[Provenance.INFERRED.value]
        < PROVENANCE_RANK[Provenance.DERIVED.value]
        < PROVENANCE_RANK[Provenance.OBSERVED.value]
    )


# --------------------------------------------------------------------------
# inferred != observed
# --------------------------------------------------------------------------


def test_an_inference_does_not_become_observed_by_combination():
    assert combine(Provenance.OBSERVED, Provenance.INFERRED) is (
        Provenance.INFERRED
    )


def test_many_observations_do_not_outvote_one_inference():
    """Weakest-wins, not majority-wins."""
    assert (
        combine(
            Provenance.OBSERVED,
            Provenance.OBSERVED,
            Provenance.OBSERVED,
            Provenance.INFERRED,
        )
        is Provenance.INFERRED
    )


def test_inferred_is_not_factual():
    assert is_factual(Provenance.OBSERVED)
    assert is_factual(Provenance.DERIVED)
    assert not is_factual(Provenance.INFERRED)
    assert not is_factual(Provenance.SIMULATED)
    assert not is_factual(Provenance.UNKNOWN)


# --------------------------------------------------------------------------
# simulated != observed
# --------------------------------------------------------------------------


def test_simulation_taints_every_conclusion_it_touches():
    assert combine(Provenance.OBSERVED, Provenance.SIMULATED) is (
        Provenance.SIMULATED
    )
    assert combine(Provenance.DERIVED, Provenance.SIMULATED) is (
        Provenance.SIMULATED
    )
    assert combine(Provenance.INFERRED, Provenance.SIMULATED) is (
        Provenance.SIMULATED
    )


def test_simulation_taint_is_not_diluted_by_volume():
    values = [Provenance.OBSERVED] * 50 + [Provenance.SIMULATED]
    assert combine(*values) is Provenance.SIMULATED


def test_simulated_outranks_unknown_when_both_are_present():
    """The sticky rule beats weakest-wins here, on purpose.

    UNKNOWN ranks below SIMULATED, so pure weakest-wins would report
    UNKNOWN and lose the simulation taint -- and losing that taint is how
    a simulated result gets mistaken for a production one. Neither value
    is factual, so nothing is over-claimed by keeping SIMULATED.
    """
    assert combine(Provenance.SIMULATED, Provenance.UNKNOWN) is (
        Provenance.SIMULATED
    )
    assert not is_factual(combine(Provenance.SIMULATED, Provenance.UNKNOWN))


# --------------------------------------------------------------------------
# unknown != trusted
# --------------------------------------------------------------------------


def test_no_stated_basis_is_unknown():
    assert combine() is Provenance.UNKNOWN


def test_unrecognized_input_degrades_to_unknown_instead_of_raising():
    """A conclusion built on an unparseable basis must not look strong."""
    assert coerce("observed!") is Provenance.UNKNOWN
    assert coerce(None) is Provenance.UNKNOWN
    assert coerce(42) is Provenance.UNKNOWN
    assert coerce(object()) is Provenance.UNKNOWN
    assert combine("not-a-provenance", Provenance.OBSERVED) is (
        Provenance.UNKNOWN
    )


def test_coerce_accepts_the_canonical_string_forms():
    for member in Provenance:
        assert coerce(member.value) is member
        assert coerce(member) is member


# --------------------------------------------------------------------------
# Bridging to the evidence-event vocabulary
# --------------------------------------------------------------------------


def test_derived_does_not_map_to_observed_evidence():
    """The evidence graph has no `derived` kind.

    Recording a derived fact as OBSERVED would promote a consequence of
    recorded authority into a direct observation of the world.
    """
    assert to_evidence_kind(Provenance.DERIVED) is EvidenceKind.INFERENCE
    assert to_evidence_kind(Provenance.OBSERVED) is EvidenceKind.OBSERVED


def test_simulated_maps_to_simulation_evidence():
    assert to_evidence_kind(Provenance.SIMULATED) is EvidenceKind.SIMULATION


def test_unknown_provenance_maps_to_unknown_evidence():
    assert to_evidence_kind(Provenance.UNKNOWN) is EvidenceKind.UNKNOWN
    assert to_evidence_kind("nonsense") is EvidenceKind.UNKNOWN


def test_a_prediction_is_never_stronger_than_an_inference():
    assert from_evidence_kind(EvidenceKind.PREDICTION) is Provenance.INFERRED
    assert not is_factual(from_evidence_kind(EvidenceKind.PREDICTION))


def test_evidence_kind_round_trip_never_strengthens():
    """Crossing the bridge must not upgrade a claim.

    Both directions are lossy by design; what matters is that a round
    trip lands on something no stronger than where it started.
    """
    for member in Provenance:
        landed = from_evidence_kind(to_evidence_kind(member))
        assert (
            PROVENANCE_RANK[landed.value] <= PROVENANCE_RANK[member.value]
        ), member


def test_every_evidence_kind_maps_back_to_a_provenance():
    for kind in EvidenceKind:
        assert isinstance(from_evidence_kind(kind), Provenance)


# --------------------------------------------------------------------------
# Confidence
# --------------------------------------------------------------------------


def test_confidence_defaults_to_unknown_provenance():
    """A bare score states nothing about how it was arrived at."""
    assert Confidence(0.9).provenance is Provenance.UNKNOWN
    assert not Confidence(0.9).factual


def test_confidence_rejects_out_of_range_and_non_numeric_scores():
    for bad in (-0.1, 1.1, 2.0):
        with pytest.raises(ValueError):
            Confidence(bad)

    for bad in ("0.5", None, True):
        with pytest.raises(TypeError):
            Confidence(bad)


def test_confidence_accepts_the_closed_unit_interval():
    assert Confidence(0.0).score == 0.0
    assert Confidence(1.0).score == 1.0
    assert Confidence(1).score == 1.0


def test_combining_confidence_takes_the_lower_score_and_weaker_basis():
    observed = Confidence(0.9, Provenance.OBSERVED, ("audit-log",))
    inferred = Confidence(0.4, Provenance.INFERRED, ("correlation",))

    merged = observed.combine(inferred)

    assert merged.score == 0.4
    assert merged.provenance is Provenance.INFERRED
    assert merged.basis == ("audit-log", "correlation")
    assert not merged.factual


def test_combining_confidence_cannot_launder_a_simulation():
    observed = Confidence(1.0, Provenance.OBSERVED, ("audit-log",))
    simulated = Confidence(1.0, Provenance.SIMULATED, ("twin-run",))

    merged = observed.combine(simulated)

    assert merged.score == 1.0
    assert merged.provenance is Provenance.SIMULATED
    assert not merged.factual
    assert "twin-run" in merged.basis


def test_confidence_basis_is_deduplicated_and_order_stable():
    left = Confidence(0.8, Provenance.OBSERVED, ("a", "b"))
    right = Confidence(0.8, Provenance.OBSERVED, ("b", "c"))

    assert left.combine(right).basis == ("a", "b", "c")


def test_confidence_is_immutable():
    confidence = Confidence(0.5, Provenance.OBSERVED)

    with pytest.raises(Exception):
        confidence.score = 1.0


def test_confidence_serialisation_carries_the_basis_and_factuality():
    payload = Confidence(0.75, "inferred", ("graph",)).to_dict()

    assert payload == {
        "score": 0.75,
        "provenance": "inferred",
        "basis": ["graph"],
        "factual": False,
    }


def test_a_high_score_does_not_make_a_claim_factual():
    """§13's point: confidence and provenance are different axes.

    0.99 from an inference is still not an observation, and nothing
    downstream may treat it as one.
    """
    assert not Confidence(0.99, Provenance.INFERRED).factual
    assert not Confidence(0.99, Provenance.SIMULATED).factual
    assert Confidence(0.01, Provenance.OBSERVED).factual
