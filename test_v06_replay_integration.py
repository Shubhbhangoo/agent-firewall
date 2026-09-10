import time
import uuid

import yaml

from firewall.capability import (
    generate_capability_key_pair,
    sign_capability,
)

from firewall.engine import Firewall

from firewall.replay import (
    ReplayProtector,
    make_replay_key,
)


class CapabilityAgent:
    def __init__(
        self,
        agent_id,
        capability,
        nonce,
    ):
        self.agent_id = agent_id
        self.issuer = "trusted-issuer"
        self.authenticated = True
        self.capabilities = (capability,)
        self.nonce = nonce


def make_policy(tmp_path):
    policy = tmp_path / "policies.yaml"

    policy.write_text(
        yaml.safe_dump(
            {
                "rules": [
                    {
                        "tool": "payments.send",
                        "agent": "finance-agent",
                        "action": "allow",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    return policy


def make_capability(
    private_key,
    **overrides,
):
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


def test_same_capability_same_nonce_first_use_allowed(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    protector = ReplayProtector(
        clock=time.time
    )

    nonce = uuid.uuid4().hex

    key = make_replay_key(
        "finance-agent",
        capability,
        nonce,
    )

    assert protector.check_and_consume(
        key,
        capability.expires_at,
    ) is True


def test_same_capability_same_nonce_second_use_rejected(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    protector = ReplayProtector(
        clock=time.time
    )

    nonce = uuid.uuid4().hex

    key = make_replay_key(
        "finance-agent",
        capability,
        nonce,
    )

    first = protector.check_and_consume(
        key,
        capability.expires_at,
    )

    second = protector.check_and_consume(
        key,
        capability.expires_at,
    )

    assert first is True
    assert second is False


def test_different_nonce_allowed(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    protector = ReplayProtector()

    first = make_replay_key(
        "finance-agent",
        capability,
        "nonce-a",
    )

    second = make_replay_key(
        "finance-agent",
        capability,
        "nonce-b",
    )

    assert protector.check_and_consume(
        first,
        capability.expires_at,
    ) is True

    assert protector.check_and_consume(
        second,
        capability.expires_at,
    ) is True


def test_different_agent_allowed(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    protector = ReplayProtector()

    first = make_replay_key(
        "agent-a",
        capability,
        "nonce-a",
    )

    second = make_replay_key(
        "agent-b",
        capability,
        "nonce-a",
    )

    assert protector.check_and_consume(
        first,
        capability.expires_at,
    ) is True

    assert protector.check_and_consume(
        second,
        capability.expires_at,
    ) is True


def test_expired_capability_cannot_consume_replay_nonce(
    tmp_path,
):
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
        "nonce-a",
    )

    assert protector.check_and_consume(
        key,
        capability.expires_at,
    ) is False


def test_replay_key_changes_when_capability_changes(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    first = make_capability(
        private_key,
        capability="payments.send",
    )

    second = make_capability(
        private_key,
        capability="payments.refund",
    )

    first_key = make_replay_key(
        "finance-agent",
        first,
        "nonce",
    )

    second_key = make_replay_key(
        "finance-agent",
        second,
        "nonce",
    )

    assert (
        first_key.capability_fingerprint
        != second_key.capability_fingerprint
    )


def test_replay_key_binds_agent(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    first = make_replay_key(
        "agent-a",
        capability,
        "nonce",
    )

    second = make_replay_key(
        "agent-b",
        capability,
        "nonce",
    )

    assert first != second


def test_replay_key_binds_nonce(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    first = make_replay_key(
        "agent-a",
        capability,
        "nonce-a",
    )

    second = make_replay_key(
        "agent-a",
        capability,
        "nonce-b",
    )

    assert first != second


def test_tampered_capability_gets_different_fingerprint(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    original = make_capability(
        private_key,
        capability="payments.send",
    )

    from firewall.capability import Capability

    tampered = Capability(
        **{
            **original.to_dict(),
            "capability": "payments.admin",
        }
    )

    original_key = make_replay_key(
        "finance-agent",
        original,
        "nonce",
    )

    tampered_key = make_replay_key(
        "finance-agent",
        tampered,
        "nonce",
    )

    assert (
        original_key.capability_fingerprint
        != tampered_key.capability_fingerprint
    )


def test_replay_protector_is_empty_initially():
    protector = ReplayProtector()

    assert protector.size() == 0


def test_replay_protector_tracks_consumed_nonce():
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    protector = ReplayProtector()

    key = make_replay_key(
        "finance-agent",
        capability,
        "nonce",
    )

    protector.check_and_consume(
        key,
        capability.expires_at,
    )

    assert protector.size() == 1


def test_replay_protector_clear_allows_reuse():
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    protector = ReplayProtector()

    key = make_replay_key(
        "finance-agent",
        capability,
        "nonce",
    )

    assert protector.check_and_consume(
        key,
        capability.expires_at,
    ) is True

    protector.clear()

    assert protector.check_and_consume(
        key,
        capability.expires_at,
    ) is True


def test_same_nonce_different_capability_scope_is_not_replay(
    tmp_path,
):
    private_key, _ = generate_capability_key_pair()

    send = make_capability(
        private_key,
        capability="payments.send",
    )

    refund = make_capability(
        private_key,
        capability="payments.refund",
    )

    protector = ReplayProtector()

    send_key = make_replay_key(
        "finance-agent",
        send,
        "same-nonce",
    )

    refund_key = make_replay_key(
        "finance-agent",
        refund,
        "same-nonce",
    )

    assert protector.check_and_consume(
        send_key,
        send.expires_at,
    ) is True

    assert protector.check_and_consume(
        refund_key,
        refund.expires_at,
    ) is True


def test_same_capability_same_nonce_is_replay_even_if_agent_object_differs():
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    protector = ReplayProtector()

    first = make_replay_key(
        "finance-agent",
        capability,
        "same",
    )

    second = make_replay_key(
        "finance-agent",
        capability,
        "same",
    )

    assert protector.check_and_consume(
        first,
        capability.expires_at,
    ) is True

    assert protector.check_and_consume(
        second,
        capability.expires_at,
    ) is False


def test_future_expiration_allows_use():
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    protector = ReplayProtector(
        clock=lambda: time.time()
    )

    key = make_replay_key(
        "finance-agent",
        capability,
        "nonce",
    )

    assert protector.check_and_consume(
        key,
        capability.expires_at,
    ) is True


def test_expired_replay_entry_can_be_cleaned():
    current = [1000.0]

    protector = ReplayProtector(
        clock=lambda: current[0]
    )

    key = ReplayKeyForTest = make_replay_key

    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key,
        issued_at=900,
        expires_at=1100,
    )

    replay_key = key(
        "finance-agent",
        capability,
        "nonce",
    )

    assert protector.check_and_consume(
        replay_key,
        capability.expires_at,
    ) is True

    current[0] = 1200

    assert protector.seen(
        replay_key
    ) is False


def test_multiple_unique_requests_are_allowed():
    private_key, _ = generate_capability_key_pair()

    capability = make_capability(
        private_key
    )

    protector = ReplayProtector()

    results = []

    for index in range(10):
        key = make_replay_key(
            "finance-agent",
            capability,
            f"nonce-{index}",
        )

        results.append(
            protector.check_and_consume(
                key,
                capability.expires_at,
            )
        )

    assert all(results)
    assert protector.size() == 10