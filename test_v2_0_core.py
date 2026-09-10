"""v2.0 core primitives tests: identity, tasks, attestation, passport."""

from __future__ import annotations

import os

import pytest

from firewall.attest import (
    Attestation,
    AttestationAuthority,
    AttestationError,
)
from firewall.ident import Identity, IdentityError, IdentityRegistry
from firewall.passport import Passport, PassportBuilder, PassportError
from firewall.task import TaskError, TaskRegistry


# ----------------------------------------------------------------------
# Identity
# ----------------------------------------------------------------------


def _registry(tmp_path=None, passphrase=b"pw"):
    return IdentityRegistry(
        state_path=(
            str(tmp_path / "ident.json")
            if tmp_path is not None
            else None
        ),
        passphrase=passphrase,
    )


def test_identity_create_and_verify():
    reg = _registry()
    identity = reg.create("agent-a", owner="me", environment="prod")
    assert identity.status == "active"
    assert identity.identity_version == 1
    assert identity.key_fingerprint
    assert identity.public_key_b64

    signature = reg.sign("agent-a", b"hello")
    assert reg.verify("agent-a", b"hello", signature)
    assert not reg.verify("agent-a", b"tampered", signature)


def test_identity_duplicate_rejected():
    reg = _registry()
    reg.create("agent-a")
    with pytest.raises(IdentityError):
        reg.create("agent-a")


def test_identity_missing_and_stale():
    reg = _registry()
    assert reg.get("ghost") is None
    with pytest.raises(IdentityError):
        reg.require("ghost")

    reg.create("agent-a")
    signature = reg.sign("agent-a", b"x")
    assert reg.verify("agent-a", b"x", signature)

    # Stale key after rotation: old signature must not verify.
    reg.rotate("agent-a")
    assert not reg.verify("agent-a", b"x", signature)


def test_identity_rotation_versioned():
    reg = _registry()
    identity = reg.create("agent-a")
    rotated = reg.rotate("agent-a")
    assert rotated.identity_version == identity.identity_version + 1
    assert rotated.key_fingerprint != identity.key_fingerprint

    # New key signs and verifies.
    signature = reg.sign("agent-a", b"new")
    assert reg.verify("agent-a", b"new", signature)


def test_identity_revocation():
    reg = _registry()
    reg.create("agent-a")
    reg.revoke("agent-a", reason="compromised")
    assert reg.get("agent-a").status == "revoked"

    with pytest.raises(IdentityError):
        reg.sign("agent-a", b"x")

    # A forged signature must not verify against a revoked identity.
    assert not reg.verify("agent-a", b"x", "AAAA")


def test_identity_retirement():
    reg = _registry()
    reg.create("agent-a")
    reg.retire("agent-a")
    assert reg.get("agent-a").status == "retired"
    with pytest.raises(IdentityError):
        reg.rotate("agent-a")


def test_identity_parent_child():
    reg = _registry()
    reg.create("parent")
    child = reg.create("child", parent_agent="parent")
    assert child.parent_agent == "parent"

    with pytest.raises(IdentityError):
        reg.create("orphan", parent_agent="ghost")


def test_identity_persistence(tmp_path):
    path = tmp_path / "ident.json"
    reg = _registry(tmp_path)
    reg.create("agent-x")
    reg.close()

    loaded = IdentityRegistry(
        state_path=str(path),
        passphrase=b"pw",
    )
    assert loaded.get("agent-x") is not None
    assert loaded.require("agent-x").agent_id == "agent-x"


def test_identity_wrong_passphrase_cannot_sign(tmp_path):
    reg = _registry(tmp_path, passphrase=b"right")
    reg.create("agent-x")
    reg.close()

    wrong = IdentityRegistry(
        state_path=str(tmp_path / "ident.json"),
        passphrase=b"wrong",
    )
    # Identity record loads (public material), private key does not.
    assert wrong.get("agent-x") is not None
    with pytest.raises(IdentityError):
        wrong.sign("agent-x", b"x")


def test_identity_forged_signature_rejected():
    reg = _registry()
    reg.create("agent-a")
    # A signature from a different key must not verify.
    other = IdentityRegistry()
    other.create("agent-b")
    foreign = other.sign("agent-b", b"data")
    assert not reg.verify("agent-a", b"data", foreign)


def test_identity_untrusted_issuer():
    reg = IdentityRegistry(trusted_issuers={"issuer-a"})
    reg.create("agent-a", issuer="issuer-a")
    with pytest.raises(IdentityError):
        reg.create("agent-b", issuer="untrusted-issuer")


# ----------------------------------------------------------------------
# Tasks
# ----------------------------------------------------------------------


def _tasks():
    identities = IdentityRegistry()
    identities.create("agent-a")
    identities.create("agent-b")
    identities.create("agent-c")
    return TaskRegistry(identity_registry=identities), identities


def test_task_create_and_permissions():
    tasks, _ = _tasks()
    task = tasks.create(
        agent_id="agent-a",
        permissions={"allowed_actions": ["read", "write"], "amount_max": 50},
    )
    assert tasks.check(task.task_id, "read")
    assert tasks.check(task.task_id, "write")
    assert not tasks.check(task.task_id, "admin")


def test_task_delegation_narrows_authority():
    tasks, _ = _tasks()
    root = tasks.create(
        agent_id="agent-a",
        permissions={
            "allowed_actions": ["read", "write", "admin"],
            "amount_max": 1000,
        },
    )
    child = tasks.delegate(
        root,
        agent_id="agent-b",
        permissions={"allowed_actions": ["read", "admin"], "amount_max": 100},
    )
    assert tasks.check(child.task_id, "read")
    assert not tasks.check(child.task_id, "write")
    # admin was granted but amount narrows... action list keeps admin
    assert "admin" in child.permissions["allowed_actions"]

    grandchild = tasks.delegate(
        child,
        agent_id="agent-c",
        permissions={"allowed_actions": ["read", "write", "admin"], "amount_max": 5000},
    )
    # Grandchild can never exceed the child's narrowed authority.
    assert not tasks.check(grandchild.task_id, "write")
    assert tasks.check(grandchild.task_id, "read")


def test_task_grandchild_cannot_exceed_chain():
    tasks, _ = _tasks()
    root = tasks.create(
        agent_id="agent-a",
        permissions={"allowed_actions": ["read"]},
    )
    child = tasks.delegate(
        root,
        agent_id="agent-b",
        permissions={"allowed_actions": ["read", "admin"]},
    )
    grandchild = tasks.delegate(
        child,
        agent_id="agent-c",
        permissions={"allowed_actions": ["read", "admin"]},
    )
    # "admin" is in the grant but never in the root: intersection drops it.
    assert "admin" not in grandchild.permissions["allowed_actions"]
    assert not tasks.check(grandchild.task_id, "admin")


def test_task_revocation_propagates():
    tasks, _ = _tasks()
    root = tasks.create(
        agent_id="agent-a",
        permissions={"allowed_actions": ["read"]},
    )
    child = tasks.delegate(root, agent_id="agent-b", permissions={})
    grandchild = tasks.delegate(child, agent_id="agent-c", permissions={})

    tasks.revoke(root.task_id, reason="test")
    assert tasks.is_revoked(grandchild.task_id)
    assert not tasks.is_active(grandchild.task_id)
    assert not tasks.check(grandchild.task_id, "read")


def test_task_delegation_of_revoked_rejected():
    tasks, _ = _tasks()
    root = tasks.create(agent_id="agent-a", permissions={})
    tasks.revoke(root.task_id)
    with pytest.raises(TaskError):
        tasks.delegate(root, agent_id="agent-b", permissions={})


def test_task_expiration():
    tasks, _ = _tasks()

    def now():
        return 100.0

    expired_tasks = TaskRegistry(clock=now)
    task = expired_tasks.create(
        agent_id="agent-a",
        permissions={},
        expires_at=150.0,
    )
    assert expired_tasks.is_active(task.task_id)

    later = TaskRegistry(clock=lambda: 200.0)
    # Share state to check the clock-driven behavior.
    later._tasks = expired_tasks._tasks
    assert not later.is_active(task.task_id)


def test_task_missing_identity_rejected():
    identities = IdentityRegistry()
    identities.create("agent-a")
    tasks = TaskRegistry(identity_registry=identities)
    with pytest.raises(TaskError):
        tasks.create(agent_id="ghost", permissions={})


def test_task_persistence(tmp_path):
    identities = IdentityRegistry()
    identities.create("agent-a")
    tasks = TaskRegistry(
        state_path=str(tmp_path / "tasks.json"),
        identity_registry=identities,
    )
    task = tasks.create(agent_id="agent-a", permissions={"allowed_actions": ["x"]})
    tasks.close()

    loaded = TaskRegistry(
        state_path=str(tmp_path / "tasks.json"),
        identity_registry=identities,
    )
    assert loaded.get(task.task_id) is not None


# ----------------------------------------------------------------------
# Attestation
# ----------------------------------------------------------------------


def _attest():
    identities = IdentityRegistry()
    identities.create("agent-a")
    return identities, AttestationAuthority(identities)


def test_attestation_issue_and_verify():
    identities, authority = _attest()
    attestation = authority.issue(
        agent_id="agent-a",
        subject="task:1",
        statement_type="authority",
        payload={"task_id": "task-1"},
    )
    assert attestation.alg == "Ed25519"
    assert attestation.key_fingerprint
    assert authority.verify(attestation)["status"] == "verified"


def test_attestation_tamper_fails():
    identities, authority = _attest()
    original = authority.issue(
        agent_id="agent-a",
        subject="task:1",
        statement_type="authority",
        payload={"task_id": "task-1"},
    )
    tampered = Attestation(
        subject=original.subject,
        statement_type=original.statement_type,
        payload={"task_id": "task-other"},
        agent_id=original.agent_id,
        issued_at=original.issued_at,
        alg=original.alg,
        key_fingerprint=original.key_fingerprint,
        signature=original.signature,
        nonce=original.nonce,
    )
    assert authority.verify(tampered)["status"] == "failed"


def test_attestation_unknown_identity_unverifiable():
    _, authority = _attest()
    ghost = Attestation(
        subject="x",
        statement_type="authority",
        agent_id="ghost",
        alg="Ed25519",
    )
    assert authority.verify(ghost)["status"] == "unverifiable"


def test_attestation_unsupported_algorithm_unverifiable():
    _, authority = _attest()
    pq = Attestation(
        subject="x",
        statement_type="authority",
        agent_id="agent-a",
        alg="Kyber768",
    )
    assert authority.verify(pq)["status"] == "unverifiable"


def test_attestation_revoked_identity_fails():
    identities, authority = _attest()
    original = authority.issue(
        agent_id="agent-a",
        subject="s",
        statement_type="authority",
    )
    identities.revoke("agent-a")
    assert authority.verify(original)["status"] == "failed"


def test_attestation_issuance_rejects_unknown_alg():
    _, authority = _attest()
    with pytest.raises(AttestationError):
        authority.issue(
            agent_id="agent-a",
            subject="s",
            statement_type="authority",
            alg="Kyber768",
        )


def test_attestation_rotation_invalidates_old():
    identities, authority = _attest()
    original = authority.issue(
        agent_id="agent-a",
        subject="s",
        statement_type="authority",
    )
    identities.rotate("agent-a")
    assert authority.verify(original)["status"] == "failed"


# ----------------------------------------------------------------------
# Passport
# ----------------------------------------------------------------------


def _passport_builder():
    identities = IdentityRegistry()
    identities.create("agent-p", owner="me")
    tasks = TaskRegistry(identity_registry=identities)
    tasks.create(
        agent_id="agent-p",
        permissions={"allowed_actions": ["read"]},
    )

    class Posture:
        @staticmethod
        def get(agent_id):
            return {"posture": "healthy", "basis": "test"}

    builder = PassportBuilder(
        identities,
        task_registry=tasks,
        posture_provider=Posture(),
    )
    return builder


def test_passport_build_and_verify():
    builder = _passport_builder()
    passport = builder.build("agent-p")
    assert passport.signature
    assert passport.identity["agent_id"] == "agent-p"
    assert passport.posture["posture"] == "healthy"
    assert builder.verify(passport)["status"] == "verified"


def test_passport_tamper_fails():
    from dataclasses import replace

    builder = _passport_builder()
    passport = builder.build("agent-p")
    tampered = replace(
        passport,
        capabilities=("admin.bypass",),
    )
    assert builder.verify(tampered)["status"] == "failed"


def test_passport_export_import_round_trip(tmp_path):
    builder = _passport_builder()
    passport = builder.build("agent-p")
    path = builder.export(passport, str(tmp_path / "passport.json"))
    loaded = builder.load(path)
    assert builder.verify(loaded)["status"] == "verified"


def test_passport_no_private_keys():
    builder = _passport_builder()
    passport = builder.build("agent-p")
    text = repr(passport.to_dict())
    assert "private" not in text
    assert "-----BEGIN" not in text


def test_passport_unknown_agent_rejected():
    builder = _passport_builder()
    with pytest.raises(PassportError):
        builder.build("ghost")


def test_passport_revoked_identity_fails():
    builder = _passport_builder()
    passport = builder.build("agent-p")
    builder._identities.revoke("agent-p")
    result = builder.verify(passport)
    assert result["status"] == "failed"
