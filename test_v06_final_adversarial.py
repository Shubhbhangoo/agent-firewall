import threading
import time

import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from firewall.authorization import authorize
from firewall.attenuation import attenuate_capability
from firewall.capability import (
    Capability,
    CapabilityVerifier,
    generate_capability_key_pair,
    sign_capability,
)
from firewall.delegation import (
    delegate_capability,
    verify_delegation,
)
from firewall.engine import Firewall
from firewall.replay import (
    ReplayProtector,
    make_replay_key,
)


class Agent:
    def __init__(self, agent_id, capabilities):
        self.agent_id = agent_id
        self.issuer = "trusted-issuer"
        self.authenticated = True
        self.capabilities = tuple(capabilities)


def make_capability(private_key, **overrides):
    now = time.time()

    values = {
        "agent_id": "finance-agent",
        "capability": "payments.send",
        "constraints": {},
        "issuer": "trusted-issuer",
        "issued_at": now - 10,
        "expires_at": now + 3600,
    }

    values.update(overrides)

    return sign_capability(
        private_key=private_key,
        **values,
    )


def make_policy(tmp_path, rules):
    policy = tmp_path / "policies.yaml"
    policy.write_text(
        yaml.safe_dump({"rules": rules}),
        encoding="utf-8",
    )
    return policy


def make_fw(
    tmp_path,
    action="allow",
    agent="finance-agent",
    tool="payments.send",
    **extra,
):
    rule = {
        "tool": tool,
        "agent": agent,
        "action": action,
    }
    rule.update(extra)

    return Firewall(
        str(
            make_policy(
                tmp_path,
                [rule],
            )
        )
    )


# ============================================================
# Capability forgery / tampering
# ============================================================


def test_forged_signature_rejected():
    private_key, _ = generate_capability_key_pair()
    capability = make_capability(private_key)

    verifier = CapabilityVerifier(
        {"trusted-issuer"},
        clock=time.time,
    )

    attacker_key = Ed25519PrivateKey.generate()

    forged_signature = attacker_key.sign(
        capability.signing_payload()
    )

    forged = Capability(
        **{
            **capability.to_dict(),
            "signature": __import__(
                "base64"
            ).b64encode(
                forged_signature
            ).decode(
                "ascii"
            ),
        }
    )

    assert verifier.verify(forged) is False


def test_agent_tampering_rejected():
    private_key, _ = generate_capability_key_pair()
    capability = make_capability(private_key)

    tampered = Capability(
        **{
            **capability.to_dict(),
            "agent_id": "attacker",
        }
    )

    verifier = CapabilityVerifier(
        {"trusted-issuer"},
        clock=time.time,
    )

    assert verifier.verify(tampered) is False


def test_capability_scope_tampering_rejected():
    private_key, _ = generate_capability_key_pair()
    capability = make_capability(
        private_key,
        capability="payments.send",
    )

    tampered = Capability(
        **{
            **capability.to_dict(),
            "capability": "payments.admin",
        }
    )

    verifier = CapabilityVerifier(
        {"trusted-issuer"},
        clock=time.time,
    )

    assert verifier.verify(tampered) is False


def test_constraint_tampering_rejected():
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        constraints={
            "amount_max": 100,
        },
    )

    tampered = Capability(
        **{
            **capability.to_dict(),
            "constraints": {
                "amount_max": 10000,
            },
        }
    )

    verifier = CapabilityVerifier(
        {"trusted-issuer"},
        clock=time.time,
    )

    assert verifier.verify(tampered) is False


def test_issuer_tampering_rejected():
    private_key, _ = generate_capability_key_pair()
    capability = make_capability(private_key)

    tampered = Capability(
        **{
            **capability.to_dict(),
            "issuer": "evil",
        }
    )

    verifier = CapabilityVerifier(
        {"trusted-issuer", "evil"},
        clock=time.time,
    )

    assert verifier.verify(tampered) is False


# ============================================================
# Time attacks
# ============================================================


def test_expired_capability_rejected():
    private_key, _ = generate_capability_key_pair()
    now = time.time()

    capability = make_capability(
        private_key,
        issued_at=now - 100,
        expires_at=now - 1,
    )

    verifier = CapabilityVerifier(
        {"trusted-issuer"},
        clock=lambda: now,
    )

    assert verifier.verify(capability) is False


def test_future_capability_rejected():
    private_key, _ = generate_capability_key_pair()
    now = time.time()

    capability = make_capability(
        private_key,
        issued_at=now + 100,
        expires_at=now + 200,
    )

    verifier = CapabilityVerifier(
        {"trusted-issuer"},
        clock=lambda: now,
    )

    assert verifier.verify(capability) is False


def test_engine_denies_expired_capability(tmp_path):
    private_key, _ = generate_capability_key_pair()
    now = time.time()

    capability = make_capability(
        private_key,
        issued_at=now - 100,
        expires_at=now - 1,
    )

    fw = make_fw(tmp_path)

    agent = Agent(
        "finance-agent",
        [capability],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "deny"


# ============================================================
# Namespace attacks
# ============================================================


def test_prefix_confusion_denied(tmp_path):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        capability="pay",
    )

    fw = make_fw(
        tmp_path,
        tool="payments.send",
    )

    agent = Agent(
        "finance-agent",
        [capability],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "deny"


def test_send_cannot_access_admin(tmp_path):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        capability="payments.send",
    )

    fw = make_fw(
        tmp_path,
        tool="payments.admin",
    )

    agent = Agent(
        "finance-agent",
        [capability],
    )

    result = fw.check(
        agent,
        "payments.admin",
        {},
    )

    assert result.action == "deny"


def test_payments_wildcard_cannot_access_accounts(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        capability="payments.*",
    )

    fw = make_fw(
        tmp_path,
        tool="accounts.read",
    )

    agent = Agent(
        "finance-agent",
        [capability],
    )

    result = fw.check(
        agent,
        "accounts.read",
        {},
    )

    assert result.action == "deny"


def test_wildcard_cannot_be_used_as_action():
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        capability="payments.send",
    )

    result = authorize(
        capability,
        "payments.*",
        {},
        clock=time.time,
    )

    assert result.allowed is False


# ============================================================
# Attenuation attacks
# ============================================================


def test_attenuation_cannot_raise_amount_limit():
    private_key, _ = generate_capability_key_pair()

    parent = make_capability(
        private_key,
        constraints={
            "amount_max": 100,
        },
    )

    try:
        attenuate_capability(
            parent,
            private_key,
            constraints={
                "amount_max": 1000,
            },
        )
    except ValueError:
        return

    assert False


def test_attenuation_cannot_extend_expiry():
    private_key, _ = generate_capability_key_pair()

    parent = make_capability(
        private_key
    )

    try:
        attenuate_capability(
            parent,
            private_key,
            expires_at=parent.expires_at + 1000,
        )
    except ValueError:
        return

    assert False


def test_attenuation_cannot_remove_constraint():
    private_key, _ = generate_capability_key_pair()

    parent = make_capability(
        private_key,
        constraints={
            "amount_max": 100,
            "currency": "USD",
        },
    )

    try:
        attenuate_capability(
            parent,
            private_key,
            constraints={
                "amount_max": 100,
            },
        )
    except ValueError:
        return

    assert False


# ============================================================
# Delegation attacks
# ============================================================


def test_delegation_cannot_escalate_amount():
    private_key, _ = generate_capability_key_pair()

    parent = make_capability(
        private_key,
        agent_id="agent-a",
        constraints={
            "amount_max": 100,
        },
    )

    with_exception = False

    try:
        delegate_capability(
            parent,
            private_key,
            "agent-b",
            constraints={
                "amount_max": 1000,
            },
        )
    except ValueError:
        with_exception = True

    assert with_exception


def test_delegation_cannot_change_delegatee_after_creation():
    private_key, _ = generate_capability_key_pair()

    parent = make_capability(
        private_key,
        agent_id="agent-a",
    )

    delegation = delegate_capability(
        parent,
        private_key,
        "agent-b",
    )

    forged = type(delegation)(
        parent=delegation.parent,
        child=delegation.child,
        delegator="agent-a",
        delegatee="attacker",
    )

    assert forged.is_valid() is False


def test_delegation_chain_escalation_rejected():
    private_key, _ = generate_capability_key_pair()

    parent = make_capability(
        private_key,
        agent_id="agent-a",
        constraints={
            "amount_max": 1000,
        },
    )

    first = delegate_capability(
        parent,
        private_key,
        "agent-b",
        constraints={
            "amount_max": 500,
        },
    )

    try:
        delegate_capability(
            first.child,
            private_key,
            "agent-c",
            constraints={
                "amount_max": 900,
            },
        )
    except ValueError:
        return

    assert False


def test_invalid_delegation_fails_verification():
    private_key, _ = generate_capability_key_pair()

    parent = make_capability(
        private_key,
        agent_id="agent-a",
    )

    delegation = delegate_capability(
        parent,
        private_key,
        "agent-b",
    )

    verifier = CapabilityVerifier(
        {"trusted-issuer"},
        clock=time.time,
    )

    tampered = type(delegation)(
        parent=delegation.parent,
        child=Capability(
            **{
                **delegation.child.to_dict(),
                "capability": "payments.admin",
            }
        ),
        delegator="agent-a",
        delegatee="agent-b",
    )

    assert verify_delegation(
        tampered,
        verifier,
    ) is False


# ============================================================
# Replay attacks
# ============================================================


def test_same_nonce_replayed():
    private_key, _ = generate_capability_key_pair()
    capability = make_capability(private_key)

    protector = ReplayProtector()

    key = make_replay_key(
        "finance-agent",
        capability,
        "nonce-1",
    )

    assert protector.check_and_consume(
        key,
        capability.expires_at,
    )

    assert not protector.check_and_consume(
        key,
        capability.expires_at,
    )


def test_same_nonce_different_agents_is_allowed():
    private_key, _ = generate_capability_key_pair()
    capability = make_capability(private_key)

    protector = ReplayProtector()

    first = make_replay_key(
        "agent-a",
        capability,
        "nonce-1",
    )

    second = make_replay_key(
        "agent-b",
        capability,
        "nonce-1",
    )

    assert protector.check_and_consume(
        first,
        capability.expires_at,
    )

    assert protector.check_and_consume(
        second,
        capability.expires_at,
    )


def test_same_nonce_different_capabilities_is_allowed():
    private_key, _ = generate_capability_key_pair()

    first_capability = make_capability(
        private_key,
        capability="payments.send",
    )

    second_capability = make_capability(
        private_key,
        capability="payments.refund",
    )

    protector = ReplayProtector()

    first = make_replay_key(
        "finance-agent",
        first_capability,
        "nonce-1",
    )

    second = make_replay_key(
        "finance-agent",
        second_capability,
        "nonce-1",
    )

    assert protector.check_and_consume(
        first,
        first_capability.expires_at,
    )

    assert protector.check_and_consume(
        second,
        second_capability.expires_at,
    )


def test_expired_replay_is_not_accepted():
    private_key, _ = generate_capability_key_pair()
    now = time.time()

    capability = make_capability(
        private_key,
        issued_at=now - 100,
        expires_at=now - 1,
    )

    protector = ReplayProtector(
        clock=lambda: now
    )

    key = make_replay_key(
        "finance-agent",
        capability,
        "nonce-1",
    )

    assert not protector.check_and_consume(
        key,
        capability.expires_at,
    )


def test_replay_race_only_one_wins():
    private_key, _ = generate_capability_key_pair()
    capability = make_capability(private_key)

    protector = ReplayProtector()

    key = make_replay_key(
        "finance-agent",
        capability,
        "race",
    )

    results = []
    lock = threading.Lock()

    def worker():
        value = protector.check_and_consume(
            key,
            capability.expires_at,
        )

        with lock:
            results.append(value)

    threads = [
        threading.Thread(
            target=worker
        )
        for _ in range(25)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert results.count(True) == 1
    assert results.count(False) == 24


# ============================================================
# Engine attacks
# ============================================================


def test_engine_wrong_agent_capability_denied(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        agent_id="agent-a",
    )

    fw = make_fw(
        tmp_path,
        agent="agent-b",
    )

    agent = Agent(
        "agent-b",
        [capability],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "deny"


def test_engine_tampered_capability_denied(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        capability="payments.send",
    )

    tampered = Capability(
        **{
            **capability.to_dict(),
            "capability": "payments.admin",
        }
    )

    fw = make_fw(
        tmp_path,
        tool="payments.admin",
    )

    agent = Agent(
        "finance-agent",
        [tampered],
    )

    result = fw.check(
        agent,
        "payments.admin",
        {},
    )

    assert result.action == "deny"


def test_engine_constraint_escalation_denied(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        constraints={
            "amount_max": 100,
        },
    )

    fw = make_fw(tmp_path)

    agent = Agent(
        "finance-agent",
        [capability],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 101},
    )

    assert result.action == "deny"


def test_engine_wildcard_escalation_denied(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        capability="payments.send",
    )

    fw = make_fw(
        tmp_path,
        tool="payments.admin",
    )

    agent = Agent(
        "finance-agent",
        [capability],
    )

    result = fw.check(
        agent,
        "payments.admin",
        {},
    )

    assert result.action == "deny"


# ============================================================
# Budget / replay / rate-limit interactions
# ============================================================


def test_budget_failure_does_not_allow_second_execution(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()
    capability = make_capability(private_key)

    fw = make_fw(
        tmp_path,
        budget=10,
    )

    agent = Agent(
        "finance-agent",
        [capability],
    )

    first = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    second = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert first.action == "allow"
    assert second.action == "deny"


def test_rate_limit_failure_does_not_reverse_first_success(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()
    capability = make_capability(private_key)

    fw = make_fw(
        tmp_path,
        rate_limit=1,
    )

    agent = Agent(
        "finance-agent",
        [capability],
    )

    first = fw.check(
        agent,
        "payments.send",
        {"amount": 1},
    )

    second = fw.check(
        agent,
        "payments.send",
        {"amount": 1},
    )

    assert first.action == "allow"
    assert second.action == "deny"


# ============================================================
# Evidence security
# ============================================================


def test_evidence_does_not_expose_private_key(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    fw = make_fw(tmp_path)

    agent = Agent(
        "finance-agent",
        [capability],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    encoded = result.evidence.to_json()

    assert "private_key" not in encoded
    assert "secret_key" not in encoded
    assert "mnemonic" not in encoded


def test_evidence_fingerprint_is_stable(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    fw = make_fw(tmp_path)

    agent = Agent(
        "finance-agent",
        [capability],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    first = result.evidence.fingerprint()
    second = result.evidence.fingerprint()

    assert first == second


def test_denial_evidence_records_reason(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        capability="payments.read",
    )

    fw = make_fw(tmp_path)

    agent = Agent(
        "finance-agent",
        [capability],
    )

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "deny"
    assert result.evidence.reason


# ============================================================
# v0.5 compatibility
# ============================================================


def test_legacy_string_capability_still_works(
    tmp_path,
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "capability": "payments.write",
                "action": "allow",
            }
        ],
    )

    fw = Firewall(
        str(policy)
    )

    agent = type(
        "LegacyAgent",
        (),
        {
            "agent_id": "finance-agent",
            "authenticated": True,
            "capabilities": frozenset(
                {"payments.write"}
            ),
        },
    )()

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "allow"


def test_missing_v06_capability_does_not_break_legacy_policy(
    tmp_path,
):
    fw = make_fw(tmp_path)

    agent = type(
        "LegacyAgent",
        (),
        {
            "agent_id": "finance-agent",
            "authenticated": True,
            "capabilities": frozenset(),
        },
    )()

    result = fw.check(
        agent,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "allow"