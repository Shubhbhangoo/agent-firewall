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


def make_identity(agent_id):
    return AgentIdentity(
        agent_id=agent_id,
        issuer="trusted-issuer",
        authenticated=True,
        capabilities=frozenset(),
    )


def test_request_within_budget_is_allowed(tmp_path):
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

    result = fw.check(
        make_identity("finance-agent"),
        "payments.send",
        {"amount": 40},
    )

    assert result.action == "allow"


def test_request_exceeding_budget_is_denied(tmp_path):
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

    result = fw.check(
        make_identity("finance-agent"),
        "payments.send",
        {"amount": 101},
    )

    assert result.action == "deny"


def test_cumulative_budget_is_enforced(tmp_path):
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

    identity = make_identity("finance-agent")

    first = fw.check(
        identity,
        "payments.send",
        {"amount": 40},
    )

    second = fw.check(
        identity,
        "payments.send",
        {"amount": 40},
    )

    third = fw.check(
        identity,
        "payments.send",
        {"amount": 30},
    )

    assert first.action == "allow"
    assert second.action == "allow"
    assert third.action == "deny"


def test_exact_budget_is_allowed(tmp_path):
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

    result = fw.check(
        make_identity("finance-agent"),
        "payments.send",
        {"amount": 100},
    )

    assert result.action == "allow"


def test_budget_is_per_agent(tmp_path):
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

    fw = Firewall(str(policy))

    agent_a = make_identity("agent-a")
    agent_b = make_identity("agent-b")

    first_a = fw.check(
        agent_a,
        "payments.send",
        {"amount": 100},
    )

    second_a = fw.check(
        agent_a,
        "payments.send",
        {"amount": 1},
    )

    first_b = fw.check(
        agent_b,
        "payments.send",
        {"amount": 100},
    )

    assert first_a.action == "allow"
    assert second_a.action == "deny"
    assert first_b.action == "allow"


def test_budget_is_per_tool(tmp_path):
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

    fw = Firewall(str(policy))

    identity = make_identity("finance-agent")

    send = fw.check(
        identity,
        "payments.send",
        {"amount": 100},
    )

    read = fw.check(
        identity,
        "payments.read",
        {},
    )

    assert send.action == "allow"
    assert read.action == "allow"


def test_denied_request_does_not_consume_budget(
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

    identity = make_identity("finance-agent")

    denied = fw.check(
        identity,
        "payments.send",
        {"amount": 101},
    )

    allowed = fw.check(
        identity,
        "payments.send",
        {"amount": 100},
    )

    assert denied.action == "deny"
    assert allowed.action == "allow"


def test_budget_denial_is_audited(
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
                "budget": 100,
            }
        ],
    )

    fw = Firewall(str(policy))

    result = fw.check(
        make_identity("finance-agent"),
        "payments.send",
        {"amount": 101},
    )

    assert result.action == "deny"

    audit_file = tmp_path / "audit.log"

    assert audit_file.exists()

    entries = [
        line
        for line in audit_file.read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]

    assert len(entries) == 1


def test_budget_is_thread_safe(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

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

    identity = make_identity("finance-agent")

    def request():
        return fw.check(
            identity,
            "payments.send",
            {"amount": 10},
        ).action

    with ThreadPoolExecutor(
        max_workers=10
    ) as executor:

        results = list(
            executor.map(
                lambda _: request(),
                range(20),
            )
        )

    assert results.count("allow") == 10
    assert results.count("deny") == 10


def test_budget_does_not_reset_with_rate_limit_window(
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
                "budget": 100,
                "rate_limit": 1,
                "rate_limit_window": 10,
            }
        ],
    )

    fw = Firewall(str(policy))

    identity = make_identity("finance-agent")

    now = [1000.0]

    monkeypatch.setattr(
        engine_module.time,
        "monotonic",
        lambda: now[0],
    )

    first = fw.check(
        identity,
        "payments.send",
        {"amount": 60},
    )

    assert first.action == "allow"

    now[0] += 10

    second = fw.check(
        identity,
        "payments.send",
        {"amount": 40},
    )

    assert second.action == "allow"

    third = fw.check(
        identity,
        "payments.send",
        {"amount": 1},
    )

    assert third.action == "deny"


def test_invalid_budget_is_rejected(tmp_path):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "action": "allow",
                "budget": 0,
            }
        ],
    )

    try:
        Firewall(str(policy))
        assert False
    except ValueError:
        pass


def test_negative_budget_is_rejected(tmp_path):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "action": "allow",
                "budget": -1,
            }
        ],
    )

    try:
        Firewall(str(policy))
        assert False
    except ValueError:
        pass


def test_boolean_budget_is_rejected(tmp_path):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "action": "allow",
                "budget": True,
            }
        ],
    )

    try:
        Firewall(str(policy))
        assert False
    except ValueError:
        pass


def test_budget_requires_amount(tmp_path):
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

    result = fw.check(
        make_identity("finance-agent"),
        "payments.send",
        {},
    )

    assert result.action == "deny"