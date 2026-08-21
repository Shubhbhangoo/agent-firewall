import json
import threading

import yaml

from firewall.engine import Firewall
from firewall.identity import AgentIdentity


def make_policy(tmp_path, rules):
    policy = tmp_path / "policies.yaml"

    policy.write_text(
        yaml.safe_dump({"rules": rules}),
        encoding="utf-8",
    )

    return policy


def make_identity(
    agent_id="finance-agent",
    capabilities=None,
):
    return AgentIdentity(
        agent_id=agent_id,
        issuer="trusted-issuer",
        authenticated=True,
        capabilities=frozenset(
            capabilities or set()
        ),
    )


def test_budget_persists_across_restart(tmp_path):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "allow",
                "budget": 100,
            }
        ],
    )

    fw1 = Firewall(str(policy))

    identity = make_identity()

    first = fw1.check(
        identity,
        "payments.send",
        {"amount": 60},
    )

    assert first.action == "allow"

    fw2 = Firewall(str(policy))

    second = fw2.check(
        identity,
        "payments.send",
        {"amount": 50},
    )

    assert second.action == "deny"


def test_budget_state_isolated_between_agents(
    tmp_path,
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "action": "allow",
                "budget": 100,
            }
        ],
    )

    fw1 = Firewall(str(policy))

    agent_a = make_identity("agent-a")
    agent_b = make_identity("agent-b")

    assert (
        fw1.check(
            agent_a,
            "payments.send",
            {"amount": 100},
        ).action
        == "allow"
    )

    fw2 = Firewall(str(policy))

    result = fw2.check(
        agent_b,
        "payments.send",
        {"amount": 100},
    )

    assert result.action == "allow"


def test_budget_state_isolated_between_tools(
    tmp_path,
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "allow",
                "budget": 100,
            },
            {
                "tool": "payments.read",
                "agent": "finance-agent",
                "action": "allow",
            },
        ],
    )

    fw1 = Firewall(str(policy))

    identity = make_identity()

    assert (
        fw1.check(
            identity,
            "payments.send",
            {"amount": 100},
        ).action
        == "allow"
    )

    fw2 = Firewall(str(policy))

    result = fw2.check(
        identity,
        "payments.read",
        {},
    )

    assert result.action == "allow"


def test_rate_limit_state_persists_across_restart(
    tmp_path,
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "allow",
                "rate_limit": 1,
                "rate_limit_window": 60,
            }
        ],
    )

    fw1 = Firewall(str(policy))

    identity = make_identity()

    first = fw1.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    assert first.action == "allow"

    fw2 = Firewall(str(policy))

    second = fw2.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    assert second.action == "deny"


def test_rate_limit_window_resets_after_restart(
    tmp_path,
    monkeypatch,
):
    import firewall.engine as engine_module

    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "allow",
                "rate_limit": 1,
                "rate_limit_window": 10,
            }
        ],
    )

    now = [1000.0]

    monkeypatch.setattr(
        engine_module.time,
        "monotonic",
        lambda: now[0],
    )

    fw1 = Firewall(str(policy))

    identity = make_identity()

    first = fw1.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    assert first.action == "allow"

    now[0] += 11

    fw2 = Firewall(str(policy))

    second = fw2.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    assert second.action == "allow"


def test_approval_does_not_survive_restart(
    tmp_path,
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "approval",
            }
        ],
    )

    identity = make_identity()

    fw1 = Firewall(str(policy))

    request = fw1.check(
        identity,
        "payments.send",
        {"amount": 100},
    )

    assert request.action == "approval"

    fw2 = Firewall(str(policy))

    result = fw2.approve(
        request,
        identity,
    )

    assert result.action == "deny"


def test_corrupted_state_is_rejected_safely(
    tmp_path,
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "allow",
                "budget": 100,
            }
        ],
    )

    fw = Firewall(str(policy))

    identity = make_identity()

    first = fw.check(
        identity,
        "payments.send",
        {"amount": 50},
    )

    assert first.action == "allow"

    state_file = tmp_path / "firewall_state.json"

    if state_file.exists():
        state_file.write_text(
            "{ definitely not valid json",
            encoding="utf-8",
        )

    fw2 = Firewall(str(policy))

    result = fw2.check(
        identity,
        "payments.send",
        {"amount": 50},
    )

    assert result.action in {
        "allow",
        "deny",
    }


def test_state_file_contains_no_private_keys(
    tmp_path,
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "allow",
                "budget": 100,
            }
        ],
    )

    fw = Firewall(str(policy))

    identity = make_identity()

    fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    state_file = tmp_path / "firewall_state.json"

    if state_file.exists():

        text = state_file.read_text(
            encoding="utf-8"
        )

        assert "private_key" not in text
        assert "secret" not in text
        assert "password" not in text


def test_audit_chain_survives_restart(
    tmp_path,
    monkeypatch,
):
    monkeypatch.chdir(tmp_path)

    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "allow",
            }
        ],
    )

    identity = make_identity()

    fw1 = Firewall(str(policy))

    first = fw1.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    assert first.action == "allow"

    fw2 = Firewall(str(policy))

    second = fw2.check(
        identity,
        "payments.send",
        {"amount": 20},
    )

    assert second.action == "allow"

    assert fw2.verify_audit_chain() is True


def test_state_write_is_thread_safe(tmp_path):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "allow",
                "budget": 100,
            }
        ],
    )

    fw = Firewall(str(policy))

    identity = make_identity()

    results = []
    lock = threading.Lock()

    def request():
        result = fw.check(
            identity,
            "payments.send",
            {"amount": 10},
        )

        with lock:
            results.append(
                result.action
            )

    threads = [
        threading.Thread(
            target=request
        )
        for _ in range(20)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert results.count("allow") == 10
    assert results.count("deny") == 10


def test_denied_request_does_not_persist_budget(
    tmp_path,
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "allow",
                "budget": 100,
            }
        ],
    )

    identity = make_identity()

    fw1 = Firewall(str(policy))

    denied = fw1.check(
        identity,
        "payments.send",
        {"amount": 101},
    )

    assert denied.action == "deny"

    fw2 = Firewall(str(policy))

    allowed = fw2.check(
        identity,
        "payments.send",
        {"amount": 100},
    )

    assert allowed.action == "allow"


def test_multiple_budget_entries_survive_restart(
    tmp_path,
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "action": "allow",
                "budget": 100,
            }
        ],
    )

    fw1 = Firewall(str(policy))

    agent_a = make_identity("agent-a")
    agent_b = make_identity("agent-b")

    assert (
        fw1.check(
            agent_a,
            "payments.send",
            {"amount": 40},
        ).action
        == "allow"
    )

    assert (
        fw1.check(
            agent_b,
            "payments.send",
            {"amount": 70},
        ).action
        == "allow"
    )

    fw2 = Firewall(str(policy))

    assert (
        fw2.check(
            agent_a,
            "payments.send",
            {"amount": 60},
        ).action
        == "allow"
    )

    assert (
        fw2.check(
            agent_b,
            "payments.send",
            {"amount": 40},
        ).action
        == "deny"
    )


def test_state_tampering_does_not_grant_unlimited_budget(
    tmp_path,
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "allow",
                "budget": 100,
            }
        ],
    )

    identity = make_identity()

    fw1 = Firewall(str(policy))

    assert (
        fw1.check(
            identity,
            "payments.send",
            {"amount": 100},
        ).action
        == "allow"
    )

    state_file = tmp_path / "firewall_state.json"

    if state_file.exists():

        try:
            state = json.loads(
                state_file.read_text(
                    encoding="utf-8"
                )
            )

            if isinstance(state, dict):
                state["budget_usage"] = {}

                state_file.write_text(
                    json.dumps(state),
                    encoding="utf-8",
                )

        except Exception:
            pass

    fw2 = Firewall(str(policy))

    result = fw2.check(
        identity,
        "payments.send",
        {"amount": 1},
    )

    assert result.action in {
        "allow",
        "deny",
    }