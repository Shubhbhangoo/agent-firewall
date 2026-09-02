"""v2.3: two names for one concept, and one name for two concepts.

The mission forbids multiple competing representations of the same
security concept. Two pairs in v2.2 violated it in the more dangerous
direction -- one *name* covering two different claims, so a reader could
carry a guarantee across a boundary where it does not hold:

``IntegrityReport`` meant both "this hash-chained evidence log verifies
against its checkpoints and signers" (:mod:`firewall.evidence_integrity`)
and "eight subsystems were asked about this agent and mostly agreed"
(:mod:`firewall.deception`). The second is not a cryptographic result,
and nothing in its name said so.

``trust_score`` meant both "the trust provider scored this agent, and 0.0
when identity could not be verified" (:class:`MeshState`) and "1.0 until
something is found against the agent" (``AgentSecurityProfile``). The two
disagree about *absence*, in opposite directions, and the mesh compares
its version against a quarantine threshold.

``Checkpoint`` meant both "a signed commitment to a point in the decision
recorder's event log, which ``firewall verify`` reads out of an audit
artifact" and "a signed commitment to a point in an evidence-graph
chain". Different signed field sets over different chains, so neither
verifier can check the other's -- while the shared name suggested that
verifying one said something about the other.

These tests pin the separation, and pin that the separation is the
security-relevant kind: it is about what each value permits a caller to
conclude, not about naming taste.
"""

from __future__ import annotations

import pytest

from firewall.adversarial import AgentSecurityProfile
from firewall.deception import ClaimIntegrityReport
from firewall.defense.mesh import DefenseMesh, MeshState
from firewall.evidence_integrity import IntegrityReport
from firewall.ident import IdentityRegistry
from firewall.immune.engine import ImmuneSystem
from firewall.recorder.checkpoint import Checkpoint as RecorderCheckpoint
from firewall.security_memory import EvidenceCheckpoint


# ======================================================================
# Claim integrity is not evidence integrity
# ======================================================================


class TestIntegrityReportsAreDistinct:
    def test_the_two_reports_are_different_types(self):
        assert ClaimIntegrityReport is not IntegrityReport

    def test_deception_no_longer_exports_the_ambiguous_name(self):
        import firewall.deception as deception

        # A caller writing ``from firewall.deception import
        # IntegrityReport`` now gets an error instead of a type whose
        # name promises a cryptographic verification it never performs.
        assert not hasattr(deception, "IntegrityReport")

    def test_evidence_integrity_keeps_the_name_it_earned(self):
        import firewall.evidence_integrity as evidence_integrity

        assert evidence_integrity.IntegrityReport is IntegrityReport
        assert not hasattr(evidence_integrity, "ClaimIntegrityReport")

    def test_a_high_claim_report_verifies_no_hash_and_no_signature(self):
        # The fields are the tell: claim integrity has no tamper
        # evidence, no checkpoint and no signer, because it never looked
        # at any. A reader who saw "integrity: high" and concluded the
        # evidence log was intact would be reading a different report.
        report = ClaimIntegrityReport(
            agent_id="agent-a", overall_integrity="high"
        )
        fields = report.to_dict()

        assert "tamper_evidence" not in fields
        assert "checkpoint_verified" not in fields
        assert "signer_verified" not in fields

    def test_the_cryptographic_report_is_three_valued_about_absence(self):
        # And the one that does verify signatures refuses to say True or
        # False when it had nothing to check.
        report = IntegrityReport(
            status="unverifiable",
            total_events=0,
            verified_events=0,
            gaps=("no anchor was supplied",),
        )

        assert report.checkpoint_verified is None
        assert report.signer_verified is None

    def test_neither_report_status_vocabulary_leaks_into_the_other(self):
        # "high" is not an evidence-integrity status and "verified" is
        # not a claim-integrity level. Sharing a name invited sharing a
        # vocabulary, which would make the two indistinguishable in a
        # log.
        with pytest.raises(ValueError, match="unknown integrity status"):
            IntegrityReport(status="high", total_events=0, verified_events=0)

        assert (
            ClaimIntegrityReport(agent_id="a").overall_integrity == "unknown"
        )


# ======================================================================
# The two scores disagree about absence
# ======================================================================


def _mesh_with_trust(score: float) -> DefenseMesh:
    """A mesh whose trust provider returns a fixed score for one agent.

    The capability provider is pinned to allowing, so the only thing that
    can move the agent's state is the trust score. The default provider
    consults an SDK, and a mesh built without one would restrict the
    agent for want of a capability -- which would make these tests pass
    without the score being read at all.
    """

    identities = IdentityRegistry()
    identities.create("agent-a")
    return DefenseMesh(
        identities,
        trust_provider=lambda agent: (score, "fixed for the test"),
        capability_provider=lambda agent: (True, "capability allowed"),
    )


class TestScoresAreNotInterchangeable:
    def test_absence_moves_them_in_opposite_directions(self):
        # Same situation -- nothing could be established about the agent
        # -- and the two scores land at opposite ends. Either name would
        # have been read as the other's meaning somewhere.
        unchecked = AgentSecurityProfile(
            agent_id="agent-a",
            gaps=("the identity registry was absent",),
        )

        assert unchecked.finding_score == 1.0
        assert unchecked.risk_level == "unknown"

        mesh = _mesh_with_trust(0.9)
        # No identity verification is possible for an agent the registry
        # does not know, so the mesh floors the score regardless of what
        # the provider would have said.
        state = mesh.evaluate("agent-unknown")

        assert state.trust_score == 0.0
        assert state.identity_verified is False

    def test_the_mesh_score_is_the_one_a_threshold_may_read(self):
        mesh = _mesh_with_trust(0.1)
        state = mesh.evaluate("agent-a")

        # Below the 0.35 default quarantine threshold, and the mesh acted
        # on it: the agent is restricted, with the score named as the
        # cause. (Full quarantine additionally needs a compromised
        # posture; the score alone restricts.) This is a trust score in
        # the sense a threshold needs -- low means bad, and absent means
        # low.
        assert state.trust_score == 0.1
        assert state.state == "restricted"
        assert "trust 0.10" in state.reason

    def test_a_healthy_mesh_score_leaves_the_agent_alone(self):
        mesh = _mesh_with_trust(0.9)

        state = mesh.evaluate("agent-a")

        assert state.state == "active"

    def test_the_profile_score_is_not_a_quarantine_input(self):
        # A profile that scores 1.0 while reporting unknown risk would
        # clear any threshold. Nothing in the mesh reads it, and the
        # rename is what keeps a future wiring from assuming it could.
        profile = AgentSecurityProfile(
            agent_id="agent-a", gaps=("the posture engine was absent",)
        )

        assert profile.finding_score == 1.0
        assert profile.risk_level != "low"
        assert "trust_score" not in profile.to_dict()
        assert "finding_score" not in MeshState.__dataclass_fields__


# ======================================================================
# A missing score is not a collapsed score
# ======================================================================


class TestTrustCollapseDetection:
    def test_a_real_collapse_is_detected(self):
        mesh = _mesh_with_trust(0.1)
        immune = ImmuneSystem(mesh)

        rules = {d.rule_id for d in immune.detect()}

        assert "trust_collapse" in rules

    def test_a_healthy_score_raises_no_collapse(self):
        mesh = _mesh_with_trust(0.9)
        immune = ImmuneSystem(mesh)

        rules = {d.rule_id for d in immune.detect()}

        assert "trust_collapse" not in rules

    def test_a_state_without_a_score_reports_nothing_either_way(
        self, monkeypatch
    ):
        # The rule used to default a missing score to 1.0, answering a
        # question it had no evidence for with the most reassuring number
        # available. A state dict with no score must now produce no
        # collapse finding *and* no clean bill: the rule simply does not
        # apply.
        mesh = _mesh_with_trust(0.1)
        immune = ImmuneSystem(mesh)

        monkeypatch.setattr(
            immune,
            "_agent_state",
            lambda agent: {"agent": agent, "state": "unknown"},
        )

        rules = {d.rule_id for d in immune.detect()}

        assert "trust_collapse" not in rules

    def test_a_non_numeric_score_is_not_compared(self, monkeypatch):
        # ``"low"`` is not a number, and ``"low" < 0.3`` raises in
        # Python 3. An unhandled TypeError inside detect() would abort
        # the whole detection pass, losing the findings for every other
        # agent as well.
        mesh = _mesh_with_trust(0.1)
        immune = ImmuneSystem(mesh)

        monkeypatch.setattr(
            immune,
            "_agent_state",
            lambda agent: {"agent": agent, "trust_score": "low"},
        )

        rules = {d.rule_id for d in immune.detect()}

        assert "trust_collapse" not in rules

    def test_detection_grants_and_removes_nothing(self):
        # The immune loop observes and reports. A collapse detection is
        # not a revocation and not a denial.
        mesh = _mesh_with_trust(0.1)
        immune = ImmuneSystem(mesh)

        detections = immune.detect()

        assert detections
        for detection in detections:
            assert not hasattr(detection, "allowed")
            assert not hasattr(detection, "authorize")


# ======================================================================
# Two chains, two checkpoint formats, neither verifies the other
# ======================================================================


class TestCheckpointsAnchorDifferentChains:
    def test_the_two_checkpoint_types_are_distinct(self):
        assert RecorderCheckpoint is not EvidenceCheckpoint
        assert not issubclass(EvidenceCheckpoint, RecorderCheckpoint)
        assert not issubclass(RecorderCheckpoint, EvidenceCheckpoint)

    def test_security_memory_no_longer_exports_the_ambiguous_name(self):
        import firewall.security_memory as security_memory

        assert not hasattr(security_memory, "Checkpoint")
        assert security_memory.EvidenceCheckpoint is EvidenceCheckpoint

    def test_the_recorder_keeps_the_name_its_artifact_format_uses(self):
        # The released audit-artifact format names this type, so v2.3
        # renamed the newer one instead.
        import firewall.recorder as recorder

        assert recorder.Checkpoint is RecorderCheckpoint

    def test_they_sign_different_field_sets(self):
        recorder_fields = set(RecorderCheckpoint.__dataclass_fields__)
        evidence_fields = set(EvidenceCheckpoint.__dataclass_fields__)

        # Only the event hash, timestamp and signature are common. Chain
        # identity, sequence and signer are all spelled differently, so a
        # checkpoint of one kind cannot be read as the other even by a
        # caller who ignores types and passes dicts.
        assert "chain_id" in evidence_fields
        assert "chain_id" not in recorder_fields
        assert "event_count" in recorder_fields
        assert "event_count" not in evidence_fields
        assert recorder_fields != evidence_fields

    def test_neither_signed_block_covers_the_other_chain(self):
        recorder_checkpoint = RecorderCheckpoint(
            seq=1,
            event_hash="a" * 64,
            event_count=1,
            timestamp=1.0,
            signer="signer-a",
            signature="sig",
        )
        evidence_checkpoint = EvidenceCheckpoint(
            checkpoint_id="cp-1",
            chain_id="chain-a",
            sequence_number=1,
            event_hash="a" * 64,
            previous_checkpoint_hash="0" * 64,
            timestamp=1.0,
            signer_fingerprint="fp",
            signature="sig",
        )

        signed = recorder_checkpoint.signed_block()
        canonical = evidence_checkpoint.canonical_bytes()

        # The recorder's signature says nothing about which chain the
        # events belong to, because its artifact holds exactly one chain.
        # The evidence checkpoint must name its chain, because a
        # SecurityMemory holds many. Signing one field set proves nothing
        # about the other.
        assert "chain_id" not in signed
        assert b"chain_id" in canonical
        assert b"event_count" not in canonical


# ======================================================================
# The duplicate names that remain are reviewed, not overlooked
# ======================================================================


#: Class names defined in more than one module, with the reason each pair
#: is allowed to keep sharing a name. A pair is acceptable when the two
#: types describe the same *kind* of thing over different subject matter
#: and neither name borrows a guarantee from the other -- unlike
#: ``IntegrityReport`` and ``Checkpoint``, which v2.3 split because one
#: side of each pair implied a cryptographic result it never produced.
REVIEWED_DUPLICATE_NAMES = {
    "AttackPath": (
        "firewall.attackgraph.engine",
        "firewall.network.attack_path",
        "two graphs -- the capability attack graph and the agent network "
        "graph -- each carrying provenance in its own shape",
    ),
    "CounterfactualReport": (
        "firewall.replaylab.laboratory",
        "firewall.twin.twin",
        "decision replay vs attack-graph reachability; both label "
        "themselves simulated or unverifiable and neither claims an "
        "observation",
    ),
    "IdentityError": (
        "firewall.ident.registry",
        "firewall.recorder.identity",
        "a malformed agent identity vs a malformed recorder signing "
        "identity; both subclass ValueError and a mis-scoped except "
        "fails closed",
    ),
    "PostureTransition": (
        "firewall.posture.engine",
        "firewall.timeline.trajectory",
        "the live transition record vs its reconstruction on a timeline",
    ),
    "Scenario": (
        "firewall.network.simulator",
        "firewall.ui.demo",
        "a simulator scenario vs a read-only demo fixture that cannot "
        "reach the control plane",
    ),
}


def test_no_duplicate_name_is_secretly_an_alias():
    """A shared name must not become a shared type.

    Two same-named classes in different modules are a readability
    hazard. Two *aliases* would be worse: a caller could pass one where
    the other is expected and inherit a guarantee that was never checked
    for its subject matter. This walks the reviewed list and fails if any
    pair has collapsed into one object.
    """

    import importlib

    for name, (first, second, reason) in REVIEWED_DUPLICATE_NAMES.items():
        left = getattr(importlib.import_module(first), name)
        right = getattr(importlib.import_module(second), name)

        assert left is not right, f"{name}: {first} and {second} aliased"
        assert not issubclass(left, right), (name, reason)
        assert not issubclass(right, left), (name, reason)


def test_the_split_names_are_gone_from_the_duplicate_list():
    """The two pairs v2.3 renamed must not reappear as reviewed.

    A future contributor reintroducing ``IntegrityReport`` or
    ``Checkpoint`` as a second definition would have to add it here,
    which is the point: the list is where that decision becomes visible.
    """

    assert "IntegrityReport" not in REVIEWED_DUPLICATE_NAMES
    assert "Checkpoint" not in REVIEWED_DUPLICATE_NAMES
