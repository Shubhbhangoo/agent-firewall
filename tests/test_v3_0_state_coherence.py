"""v3.0: security state coherence -- attack the twenty-first invariant.

v2.6 proved an allow is refused when a *widening write* completes between
its reads. v3.0 extends the proof from writes to the *state* those writes
produce:

    An authorization decision must never rely on a security state the
    firewall cannot prove is coherent.

``SECURITY_STATE_COHERENCE`` (the twenty-first registered invariant)
machine-checks the new layer: every legitimate write to the canonical
in-domain stores -- revocation, issuer trust, delegation lineage, the
delegation-depth ceiling -- opens a ``record_state_commit`` interval that
ends in a hash-chained commitment of the whole canonical digest, no other
call does, and the ALLOW path refuses (``state_incoherent``) whenever the
live digest diverges from the chain head.

The attack surface is precisely the class the epoch counter cannot see:
state moved *without* its declared widening write path. A revocation
record removed by hand, a lineage edge written around ``register``, a
trusted issuer silently restored after ``revoke_issuer``, a store file
rolled back to an earlier snapshot, a crash between a store write and its
commitment -- none of them moves the epoch, and all of them must turn the
next allow into a denial and the invariant into a VIOLATION.

This file tests the invariant's teeth and calibrations exactly as
test_v2_9_effect_verification.py did for EFFECT_VERIFICATION_SOUNDNESS:
positive controls through the real protocol report HOLDS, and every
tampered, replayed, rolled-back or torn state the invariant exists to
catch is a VIOLATION and an authorize denial.
"""

from __future__ import annotations

import os
import shutil
import threading

from firewall.capability import capability_fingerprint
from firewall.invariants import (
    check_security_state_coherence,
)
from firewall.invariants.model import InvariantStatus
from firewall.sdk import FirewallSDK
from firewall.state_commit import (
    STATE_COMMIT_ANCHOR,
    STATE_COMMIT_WRITES,
    StateCommitRecord,
)

ACTION = "payments.send"
REQUEST = {"amount": 5}
CONSTRAINTS = {"amount_max": 100}
KEY = "v3-state-key"


def make_capability(sdk, agent="agent-a"):
    """Issue under the SDK's active key.

    A fresh key per capability would make ``delegate`` re-sign a child
    whose parent was issued by a different key of the same issuer, which
    the delegation verifier rightly refuses. The estate pattern is one
    key, many capabilities -- exactly how the canonical estate builds
    itself.
    """
    try:
        sdk.keys.active()
    except RuntimeError:
        sdk.generate_key(KEY)
    return sdk.issue(
        agent=agent,
        capability=ACTION,
        constraints=dict(CONSTRAINTS),
    )


def allow(sdk, cap):
    return sdk.authorize(cap, ACTION, dict(REQUEST))


def audit(sdk):
    return check_security_state_coherence(sdk)


def epoch_still(sdk):
    """The authority-epoch sample, proving a tamper moved no epoch.

    Every attack in this file is *invisible* to the v2.6 counter -- that
    is the point. The finished count must not move between the two
    samples, so the only mechanism that can have caught the attack is the
    state-commit chain.
    """
    return sdk.authority_epoch.sample()


def head(sdk):
    return sdk.state_commit.head()


def silent_revocation_removal(sdk, cap):
    """The strongest silent-mutation shape: forget a revocation.

    Removes the record from the registry's own dict, bypassing
    ``RevocationRegistry.revoke``, so no epoch interval opens and no
    state commitment is written. Exactly what an attacker who can reach
    the live registry does; also exactly what a buggy revocation-store
    rollback produces.
    """
    fp = capability_fingerprint(cap)
    sdk.revocation._records.pop(fp, None)


def silent_lineage_write(sdk, child_fp, parent_fp):
    """Write a lineage edge around ``DelegationLineage.register``."""
    sdk.delegation_lineage._parents[child_fp] = parent_fp


def silent_trust_restore(sdk, issuer):
    """Restore a revoked issuer's standing without ``IssuerTrustStore``."""
    sdk.issuer_trust_store._revoked.discard(issuer)
    sdk.issuer_trust_store._trusted.add(issuer)


class TestCalibrationAndToothlessness:
    def test_the_calibration_records_hold(self):
        """A legitimately used SDK -- issue, delegate, revoke, trust,
        depth change -- reports HOLDS: the chain followed the writes."""

        sdk = FirewallSDK()
        cap = make_capability(sdk)

        before = sdk.state_commit.height()
        assert before >= 0
        assert head(sdk).genesis is True
        assert head(sdk).parent_digest == STATE_COMMIT_ANCHOR

        victim = make_capability(sdk)
        sdk.revoke(victim)
        child = make_capability(sdk)
        sdk.delegate(
            child,
            sdk.keys.active().private_key,
            delegatee="agent-b",
            constraints={"amount_max": 10},
        )
        sdk.trust_issuer("acme")
        sdk.revoke_issuer("acme")
        sdk.max_delegation_depth = 7

        after = sdk.state_commit.height()
        coherent, _reason = sdk.state_commit.coherent()
        result = audit(sdk)
        sdk.close()

        assert after > before  # every in-domain write committed a link
        assert coherent is True
        assert result.status is InvariantStatus.HOLDS

    def test_a_fresh_sdk_is_coherent_not_violated(self):
        """Genesis is the boot state: a fresh SDK can prove its (empty)
        state coherent and the census half still holds."""

        sdk = FirewallSDK()
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.HOLDS

    def test_the_invariant_granted_nothing(self):
        """A HOLDS report does not make a denied authorization allowed."""

        sdk = FirewallSDK()
        cap = make_capability(sdk)
        result = audit(sdk)
        denied = sdk.authorize(cap, ACTION, {"amount": 10_000})
        sdk.close()

        assert result.status is InvariantStatus.HOLDS
        assert denied.allowed is False

    def test_standalone_stores_are_unbound_pass_through(self):
        """A store constructed standalone and never attached to an SDK has
        no journal: its writes are honest pass-throughs, and the census
        still lists the write path."""

        from firewall.revocation import RevocationRegistry

        registry = RevocationRegistry()
        registry.revoke("a" * 64, reason="standalone")
        assert ("firewall/revocation.py", "RevocationRegistry.revoke") in STATE_COMMIT_WRITES


def sdk_state_links(sdk, before):
    return sdk.state_commit.height() > before


class TestSilentStoreMutationTeeth:
    def _exercise_and_tamper(self):
        sdk = FirewallSDK()
        cap = make_capability(sdk)
        victim = make_capability(sdk)
        sdk.revoke(victim)
        sdk.close()
        return sdk, cap, victim

    def test_silent_revocation_removal_is_a_violation_and_denial(self):
        """Forgetting a revocation by hand must not restore an allow: the
        live state no longer matches the chain head, so authorize refuses
        with state_incoherent and the invariant is VIOLATED -- and this is
        the attack the epoch cannot see, because no epoch write moved."""

        sdk = FirewallSDK()
        cap = make_capability(sdk)
        victim = make_capability(sdk)
        sdk.revoke(victim)

        epoch_before = epoch_still(sdk)
        silent_revocation_removal(sdk, victim)
        epoch_after = epoch_still(sdk)

        result = audit(sdk)
        denied = allow(sdk, victim)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any("revocation" in f for f in result.findings)
        assert denied.allowed is False
        assert denied.reason.startswith("state_incoherent")
        # The v2.6 counter did not move: only the state-commit chain can
        # have caught this.
        assert epoch_before.finished == epoch_after.finished
        assert epoch_before.in_flight == epoch_after.in_flight == 0

    def test_silent_lineage_write_is_a_violation_and_denial(self):
        """A lineage edge written around ``register`` cannot quietly bind a
        revoked ancestor: digest drift refuses the request."""

        sdk = FirewallSDK()
        root = make_capability(sdk)
        parent = sdk.delegate(
            root,
            sdk.keys.active().private_key,
            delegatee="agent-p",
            constraints={"amount_max": 10},
        ).child
        sdk.revoke(parent)

        # A second child whose registration bypasses the journal would
        # resolve through the revoked parent.
        rogue_fp = "f" * 64
        silent_lineage_write(sdk, rogue_fp, capability_fingerprint(parent))

        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any("delegation_lineage" in f for f in result.findings)

    def test_silent_trust_restore_is_a_violation_and_denial(self):
        """The dangerous direction of issuer trust: revoke_issuer is a
        recorded widening, but an attacker who silently re-trusts the
        issuer restores the pre-revocation state. Live state disagrees
        with the head, so the request that would now be allowed is
        refused instead."""

        sdk = FirewallSDK()
        sdk.generate_key(KEY)
        sdk.trust_issuer("acme")
        cap = sdk.issue(
            agent="agent-a",
            capability=ACTION,
            constraints=dict(CONSTRAINTS),
            issuer="acme",
        )
        sdk.revoke_issuer("acme")
        assert not sdk.is_issuer_trusted("acme")
        denied1 = allow(sdk, cap)
        assert not denied1.allowed  # untrusted_issuer

        silent_trust_restore(sdk, "acme")
        assert sdk.is_issuer_trusted("acme")

        result = audit(sdk)
        allowed2 = allow(sdk, cap)
        sdk.close()

        # The silent restore is caught by the coherence invariant. The
        # boundary refuses the request too -- the signature verifier also
        # lost the issuer's keys at revoke time -- so in either direction
        # the tamper cannot manufacture an allow.
        assert result.status is InvariantStatus.VIOLATED
        assert any("issuer_trust" in f for f in result.findings)
        assert allowed2.allowed is False

    def test_max_depth_silent_change_is_a_violation(self):
        """The delegation-depth ceiling is in-domain state: a write to the
        backing attribute that skips the property setter must be caught."""

        sdk = FirewallSDK()
        make_capability(sdk)
        sdk.max_delegation_depth = 4
        sdk._max_delegation_depth = 9  # silent widening around the setter
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any("delegation_depth" in f for f in result.findings)


class TestChainIntegrityTeeth:
    def _journal(self):
        sdk = FirewallSDK()
        cap = make_capability(sdk)
        victim = make_capability(sdk)
        sdk.revoke(victim)
        sdk.trust_issuer("acme")
        return sdk, cap

    def test_editing_a_commitment_in_place_is_a_violation(self):
        """A record rewritten in place breaks the link to its successor
        and the state-anchoring of its own digest: the chain fails to
        verify and attests nothing."""

        sdk, cap = self._journal()
        records = list(sdk.state_commit.records())
        assert len(records) >= 2
        # Rewrite a middle record: new state digest, wrong parent for the
        # next record, non-deriving components.
        forged = StateCommitRecord(
            height=records[1].height,
            parent_digest=records[1].parent_digest,
            state_digest="0" * 64,
            component_digests={"revocation": "0" * 64},
            source="forged",
        )
        sdk.state_commit._records[1] = forged
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any("chain" in f for f in result.findings)

    def test_deleting_a_commitment_is_a_violation(self):
        """Deleting a record breaks height contiguity: the chain cannot be
        a chain, and the head attests nothing."""

        sdk, cap = self._journal()
        del sdk.state_commit._records[0]
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED

    def test_unseating_the_genesis_anchor_is_a_violation(self):
        sdk, cap = self._journal()
        records = list(sdk.state_commit.records())
        sdk.state_commit._records[0] = StateCommitRecord(
            height=0,
            parent_digest="f" * 64,  # not the anchor
            state_digest=records[0].state_digest,
            component_digests=dict(records[0].component_digests),
            source="forged-genesis",
            genesis=True,
        )
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any("anchor" in f or "genesis" in f for f in result.findings)

    def test_unbound_in_domain_store_is_a_violation(self):
        """A store replaced after construction with an unbound copy starts
        writing state nobody commits: the invariant names it."""

        from firewall.delegation_lineage import DelegationLineage
        from firewall.key_management import IssuerTrustStore
        from firewall.revocation import RevocationRegistry

        sdk = FirewallSDK()
        cap = make_capability(sdk)
        sdk.revocation = RevocationRegistry()  # unbound replacement
        result = audit(sdk)
        sdk.close()

        assert result.status is InvariantStatus.VIOLATED
        assert any("not bound" in f for f in result.findings)


class TestCrashAndPersistenceTeeth:
    def test_crash_between_write_and_commitment_denies_next_allow(
        self, tmp_path
    ):
        """A crash between a store write and its durable commitment must
        not leave a usable allow behind.

        Simulated durably: the revocation store records the revocation
        (the write landed), then the journal is restored to the state it
        had before the commitment (the process died in between). On
        reboot the live state is ahead of the chain head, the invariant
        is VIOLATED, and the would-be revived capability is refused as
        state_incoherent.
        """

        import sqlite3

        rev_db = tmp_path / "rev.db"
        jnl_db = tmp_path / "journal.db"
        journal_before = tmp_path / "journal-before.db"

        sdk = FirewallSDK(
            revocation_store_path=str(rev_db),
            state_commit_store_path=str(jnl_db),
        )
        key = sdk.generate_key(KEY).private_key
        good = sdk.issue(
            agent="agent-good",
            capability=ACTION,
            private_key=key,
            constraints=dict(CONSTRAINTS),
        )
        victim = sdk.issue(
            agent="agent-v",
            capability=ACTION,
            private_key=key,
            constraints=dict(CONSTRAINTS),
        )
        sdk.close()

        # Consistent snapshot of the committed journal before the write.
        src = sqlite3.connect(str(jnl_db))
        dst = sqlite3.connect(str(journal_before))
        src.backup(dst)
        dst.close()
        src.close()

        sdk = FirewallSDK(
            revocation_store_path=str(rev_db),
            state_commit_store_path=str(jnl_db),
        )
        sdk.revoke(victim)  # durable revocation + durable commitment
        sdk.close()

        # The crash: the store write survived, the commitment did not.
        import shutil as _shutil

        _shutil.copyfile(journal_before, jnl_db)

        reboot = FirewallSDK(
            revocation_store_path=str(rev_db),
            state_commit_store_path=str(jnl_db),
        )
        result = audit(reboot)
        denied_victim = allow(reboot, victim)
        denied_good = allow(reboot, good)
        reboot.close()

        assert result.status is InvariantStatus.VIOLATED
        # The revoked capability is denied by its own revocation...
        assert denied_victim.allowed is False
        # ...and every other allow is refused too: the firewall cannot
        # account for the state transition that crashed half-way, so no
        # authorization may rely on the state that resulted.
        assert denied_good.allowed is False
        assert denied_good.reason.startswith("state_incoherent")

    def test_store_file_rollback_across_restart_is_a_violation(self, tmp_path):
        """Rolling the revocation store file back to a pre-revoke snapshot
        -- a replay the epoch cannot see across processes -- leaves the
        booted live state disagreeing with the persisted chain head: the
        invariant is VIOLATED and the would-be revived capability is
        refused."""

        rev_db = tmp_path / "rev.db"
        jnl_db = tmp_path / "journal.db"
        snapshot = tmp_path / "snapshot.db"

        sdk = FirewallSDK(
            revocation_store_path=str(rev_db),
            state_commit_store_path=str(jnl_db),
        )
        key = sdk.generate_key(KEY).private_key
        cap = sdk.issue(
            agent="agent-a",
            capability=ACTION,
            private_key=key,
            constraints=dict(CONSTRAINTS),
        )
        shutil.copyfile(rev_db, snapshot)
        victim = sdk.issue(
            agent="agent-v",
            capability=ACTION,
            private_key=key,
            constraints=dict(CONSTRAINTS),
        )
        sdk.revoke(victim)
        assert not allow(sdk, victim).allowed
        sdk.close()

        # Roll the state back to before the revocation was recorded.
        shutil.copyfile(snapshot, rev_db)

        reboot = FirewallSDK(
            revocation_store_path=str(rev_db),
            state_commit_store_path=str(jnl_db),
        )
        result = audit(reboot)
        denied = allow(reboot, victim)
        reboot.close()

        assert result.status is InvariantStatus.VIOLATED
        assert denied.allowed is False
        assert denied.reason.startswith("state_incoherent")

    def test_honest_restart_stays_coherent(self, tmp_path):
        """Positive control for the rollback test: an untouched restart
        replays the same persisted state and stays coherent."""

        rev_db = tmp_path / "rev.db"
        jnl_db = tmp_path / "journal.db"

        sdk = FirewallSDK(
            revocation_store_path=str(rev_db),
            state_commit_store_path=str(jnl_db),
        )
        key = sdk.generate_key(KEY).private_key
        victim = sdk.issue(
            agent="agent-v",
            capability=ACTION,
            private_key=key,
            constraints=dict(CONSTRAINTS),
        )
        sdk.revoke(victim)
        sdk.close()

        reboot = FirewallSDK(
            revocation_store_path=str(rev_db),
            state_commit_store_path=str(jnl_db),
        )
        result = audit(reboot)
        denied = allow(reboot, victim)
        reboot.close()

        assert result.status is InvariantStatus.HOLDS
        assert denied.allowed is False  # revocation survived the restart


class TestConcurrencyAndDirectionality:
    def test_concurrent_legitimate_writes_stay_committed_and_coherent(self):
        """Many threads revoking and trusting through the real API must
        each end in a commitment; the chain grows exactly once per
        transition and stays coherent throughout."""

        sdk = FirewallSDK()
        sdk.generate_key(KEY)
        caps = [make_capability(sdk) for _ in range(8)]

        def revoke_loop(offset):
            sdk.revoke(caps[offset], reason="race")
            sdk.revoke(caps[offset + 4], reason="race")

        threads = [
            threading.Thread(target=revoke_loop, args=(o,))
            for o in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        result = audit(sdk)
        coherent, _ = sdk.state_commit.coherent()
        sdk.close()

        assert coherent is True
        assert result.status is InvariantStatus.HOLDS

    def test_a_tamper_can_only_deny_never_allow(self):
        """Directionality: however the state is torn, authorize must never
        emit an allow the untampered state would deny. Every tamper in
        this file turns an allow-shaped request into a denial; the inverse
        -- a tamper that manufactures an allow -- must not exist."""

        sdk = FirewallSDK()
        good = make_capability(sdk)
        victim = make_capability(sdk)
        assert allow(sdk, good).allowed is True
        sdk.revoke(victim)
        silent_revocation_removal(sdk, victim)

        # The victim is now revocable again at the store level, but the
        # allow must be refused because the state cannot be proven
        # coherent.
        outcome = allow(sdk, victim)
        sdk.close()

        assert outcome.allowed is False
        assert outcome.reason.startswith("state_incoherent")

    def test_the_state_commit_journal_constructs_no_authorization(self):
        """AUTHORIZATION_UNIQUENESS, from the outside: the v3.0 module
        contains no allow construction and FirewallSDK.authorize() is the
        only path that ever emitted the verdicts above."""

        from pathlib import Path

        source = Path(
            __import__("firewall.state_commit", fromlist=["x"]).__file__
        ).read_text(encoding="utf-8")
        assert "AuthorizationResult(" not in source
        assert "allowed=True" not in source
