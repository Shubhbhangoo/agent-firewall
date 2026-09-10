"""v2.0 adversarial tests: forged/rotated/revoked identities,
delegation escalation, replayed/stale authority, malicious provenance,
passport and attestation forgery."""

from __future__ import annotations

import pytest

from firewall.attest import Attestation, AttestationAuthority
from firewall.ident import IdentityError, IdentityRegistry
from firewall.passport import Passport, PassportBuilder
from firewall.provenance import ProvenanceRegistry
from firewall.task import TaskError, TaskRegistry


def _identities():
    reg = IdentityRegistry()
    reg.create("agent-a")
    reg.create("agent-b")
    reg.create("agent-c")
    return reg


# ----------------------------------------------------------------------
# Identity attacks
# ----------------------------------------------------------------------


def test_forged_identity_rejected():
    """A signature from a different key must not verify."""

    reg = _identities()
    other = IdentityRegistry()
    other.create("intruder")

    foreign = other.sign("intruder", b"payload")
    assert not reg.verify("agent-a", b"payload", foreign)


def test_stolen_identity_with_rotated_key_rejected():
    reg = _identities()
    signature = reg.sign("agent-a", b"data")
    reg.rotate("agent-a")
    # The old key no longer authorizes.
    assert not reg.verify("agent-a", b"data", signature)


def test_revoked_identity_rejects_everything():
    reg = _identities()
    reg.create("victim")
    signature = reg.sign("victim", b"x")
    reg.revoke("victim", reason="stolen")
    assert not reg.verify("victim", b"x", signature)
    with pytest.raises(IdentityError):
        reg.sign("victim", b"x")


def test_missing_identity_rejected():
    reg = _identities()
    assert reg.get("ghost") is None
    assert not reg.verify("ghost", b"x", "AAAA")


def test_incorrect_parent_identity_rejected():
    reg = IdentityRegistry()
    reg.create("real-parent")
    with pytest.raises(IdentityError):
        reg.create("orphan", parent_agent="not-a-parent")


def test_duplicate_identity_rejected():
    reg = _identities()
    with pytest.raises(IdentityError):
        reg.create("agent-a")


def test_untrusted_issuer_identity_rejected():
    reg = IdentityRegistry(trusted_issuers={"issuer-good"})
    reg.create("agent-a", issuer="issuer-good")
    with pytest.raises(IdentityError):
        reg.create("agent-b", issuer="issuer-bad")


# ----------------------------------------------------------------------
# Delegation escalation
# ----------------------------------------------------------------------


def test_delegation_chain_cannot_escalate():
    """A -> B -> C: C can never exceed the narrowest grant in the chain."""

    reg = _identities()
    tasks = TaskRegistry(identity_registry=reg)

    root = tasks.create(
        agent_id="agent-a",
        permissions={"allowed_actions": ["read", "admin"], "amount_max": 100},
    )
    child = tasks.delegate(
        root,
        agent_id="agent-b",
        permissions={"allowed_actions": ["read"]},
    )
    grandchild = tasks.delegate(
        child,
        agent_id="agent-c",
        permissions={"allowed_actions": ["read", "admin"], "amount_max": 9999},
    )

    # C tried to escalate: grant includes admin + huge amount, but the
    # intersection with the chain drops both.
    assert "admin" not in grandchild.permissions["allowed_actions"]
    assert grandchild.permissions.get("amount_max", 9999) == 0 or (
        "amount_max" not in grandchild.permissions
    )
    assert not tasks.check(grandchild.task_id, "admin")
    assert tasks.check(grandchild.task_id, "read")


def test_delegation_of_revoked_rejected():
    reg = _identities()
    tasks = TaskRegistry(identity_registry=reg)
    root = tasks.create(agent_id="agent-a", permissions={})
    tasks.revoke(root.task_id)
    with pytest.raises(TaskError):
        tasks.delegate(root, agent_id="agent-b", permissions={})


def test_malicious_delegation_to_unknown_identity_rejected():
    reg = IdentityRegistry()
    reg.create("agent-a")
    tasks = TaskRegistry(identity_registry=reg)
    root = tasks.create(agent_id="agent-a", permissions={})
    with pytest.raises(TaskError):
        tasks.delegate(root, agent_id="ghost", permissions={})


def test_replayed_stale_task_authority():
    """A completed task grants nothing."""

    reg = _identities()
    tasks = TaskRegistry(identity_registry=reg)
    task = tasks.create(
        agent_id="agent-a",
        permissions={"allowed_actions": ["read"]},
    )
    assert tasks.is_active(task.task_id)
    tasks.complete(task.task_id)
    assert not tasks.is_active(task.task_id)
    assert not tasks.check(task.task_id, "read")


def test_task_lineage_cycle_fails_closed():
    reg = _identities()
    tasks = TaskRegistry(identity_registry=reg)
    task = tasks.create(agent_id="agent-a", permissions={})
    # Manually inject a cycle.
    tasks._tasks[task.task_id] = tasks._tasks[task.task_id]
    # Build a cycle: task.parent_task = task.task_id
    from firewall.task import Task

    cyclic = Task(
        task_id=task.task_id,
        agent_id="agent-a",
        parent_task=task.task_id,
    )
    tasks._tasks[task.task_id] = cyclic
    with pytest.raises(TaskError):
        tasks.effective_permissions(task.task_id)
    # is_active fails closed: a cycle raises (never grants).
    with pytest.raises(TaskError):
        tasks.is_active(task.task_id)


# ----------------------------------------------------------------------
# Passport attacks
# ----------------------------------------------------------------------


def test_passport_forged_identity_fails():
    reg = _identities()
    builder = PassportBuilder(reg)

    passport = builder.build("agent-a")

    # Forge: change the identity inside the passport.
    forged = Passport(
        identity=dict(passport.identity, agent_id="intruder"),
        posture=dict(passport.posture),
        signature=passport.signature,
        key_fingerprint=passport.key_fingerprint,
        created_at=passport.created_at,
    )

    result = builder.verify(forged)
    # The claimed identity is not in the registry: unverifiable, never
    # verified.
    assert result["status"] in {"failed", "unverifiable"}


def test_passport_signed_by_wrong_agent_fails():
    reg = _identities()
    builder = PassportBuilder(reg)
    passport_a = builder.build("agent-a")

    # Re-sign the passport payload with agent-b's key.
    signature_b = reg.sign(
        "agent-b",
        passport_a.payload(),
    )
    forged = Passport(
        identity=dict(passport_a.identity),
        posture=dict(passport_a.posture),
        signature=signature_b,
        key_fingerprint=passport_a.key_fingerprint,
        created_at=passport_a.created_at,
    )
    result = builder.verify(forged)
    assert result["status"] == "failed"


def test_passport_revoked_identity_fails():
    reg = _identities()
    builder = PassportBuilder(reg)
    passport = builder.build("agent-a")
    reg.revoke("agent-a")
    assert builder.verify(passport)["status"] == "failed"


def test_passport_no_private_material():
    reg = _identities()
    builder = PassportBuilder(reg)
    passport = builder.build("agent-a")
    text = repr(passport.to_dict())
    assert "-----BEGIN" not in text
    assert "private" not in text


# ----------------------------------------------------------------------
# Attestation attacks
# ----------------------------------------------------------------------


def test_attestation_replay_with_stale_key():
    reg = _identities()
    authority = AttestationAuthority(reg)
    original = authority.issue(
        agent_id="agent-a",
        subject="s",
        statement_type="authority",
    )
    reg.rotate("agent-a")
    # Old attestation was signed with the pre-rotation key.
    assert authority.verify(original)["status"] == "failed"


def test_attestation_forged_payload():
    reg = _identities()
    authority = AttestationAuthority(reg)
    original = authority.issue(
        agent_id="agent-a",
        subject="s",
        statement_type="authority",
        payload={"capability": "read"},
    )
    forged = Attestation(
        subject=original.subject,
        statement_type=original.statement_type,
        payload={"capability": "admin"},
        agent_id=original.agent_id,
        issued_at=original.issued_at,
        alg=original.alg,
        key_fingerprint=original.key_fingerprint,
        signature=original.signature,
        nonce=original.nonce,
    )
    assert authority.verify(forged)["status"] == "failed"


def test_attestation_confused_deputy_agent():
    """An attestation claiming agent-a but signed by agent-b fails."""

    reg = _identities()
    authority = AttestationAuthority(reg)
    attestation_b = authority.issue(
        agent_id="agent-b",
        subject="s",
        statement_type="authority",
    )
    # Re-label as agent-a: fingerprint + signature mismatch.
    relabeled = Attestation(
        subject=attestation_b.subject,
        statement_type=attestation_b.statement_type,
        payload=attestation_b.payload,
        agent_id="agent-a",
        issued_at=attestation_b.issued_at,
        alg=attestation_b.alg,
        key_fingerprint=attestation_b.key_fingerprint,
        signature=attestation_b.signature,
        nonce=attestation_b.nonce,
    )
    assert authority.verify(relabeled)["status"] == "failed"


# ----------------------------------------------------------------------
# Malicious provenance
# ----------------------------------------------------------------------


def test_provenance_tampered_component_fails_integrity():
    reg = ProvenanceRegistry()

    from firewall.provenance import sha256_digest

    component = reg.register(
        kind="package",
        name="lib",
        version="1.0",
        integrity=sha256_digest(b"original"),
    )
    result = reg.verify_integrity(component.component_id, b"evil")
    assert result["status"] == "failed"


def test_provenance_name_spoofing_does_not_trust():
    """Registering a component named like a trusted one grants nothing."""

    reg = ProvenanceRegistry()
    trusted = reg.register(kind="tool", name="payments.send", version="1.0")
    reg.trust(trusted.component_id)

    # A different component with the same name stays unknown.
    spoofed = reg.register(kind="tool", name="payments.send", version="2.0")
    assert reg.trust_state(spoofed.component_id)["status"] == "unknown"


def test_provenance_revoked_dependency_makes_dependent_suspicious():
    reg = ProvenanceRegistry()
    base = reg.register(kind="package", name="base", version="1", integrity="a")
    reg.trust(base.component_id)
    child = reg.register(
        kind="package",
        name="child",
        version="1",
        dependencies=(base.component_id,),
    )
    reg.trust(child.component_id)
    reg.revoke(base.component_id, reason="malicious")

    state = reg.trust_state(child.component_id)
    assert state["status"] == "suspicious"
    assert any("untrusted" in finding for finding in state["findings"])
