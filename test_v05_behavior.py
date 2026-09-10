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


def test_normal_request_is_allowed(tmp_path):
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

    fw = Firewall(str(policy))

    result = fw.check(
        make_identity("finance-agent"),
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "allow"


def test_rate_limit_can_deny_excess_requests(tmp_path):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "allow",
                "rate_limit": 2,
            }
        ],
    )

    fw = Firewall(str(policy))
    identity = make_identity("finance-agent")

    first = fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    second = fw.check(
        identity,
        "payments.send",
        {"amount": 20},
    )

    third = fw.check(
        identity,
        "payments.send",
        {"amount": 30},
    )

    assert first.action == "allow"
    assert second.action == "allow"
    assert third.action == "deny"


def test_rate_limit_is_per_agent(tmp_path):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "action": "allow",
                "rate_limit": 1,
            }
        ],
    )

    fw = Firewall(str(policy))

    agent_a = make_identity("agent-a")
    agent_b = make_identity("agent-b")

    first_a = fw.check(
        agent_a,
        "payments.send",
        {"amount": 10},
    )

    second_a = fw.check(
        agent_a,
        "payments.send",
        {"amount": 20},
    )

    first_b = fw.check(
        agent_b,
        "payments.send",
        {"amount": 30},
    )

    assert first_a.action == "allow"
    assert second_a.action == "deny"
    assert first_b.action == "allow"


def test_rate_limit_applies_to_matching_tool(tmp_path):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "allow",
                "rate_limit": 1,
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

    first = fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    second = fw.check(
        identity,
        "payments.send",
        {"amount": 20},
    )

    read = fw.check(
        identity,
        "payments.read",
        {},
    )

    assert first.action == "allow"
    assert second.action == "deny"
    assert read.action == "allow"


def test_rate_limit_cannot_be_bypassed_by_arguments(
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
            }
        ],
    )

    fw = Firewall(str(policy))
    identity = make_identity("finance-agent")

    first = fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    second = fw.check(
        identity,
        "payments.send",
        {"amount": 999999},
    )

    assert first.action == "allow"
    assert second.action == "deny"


def test_rate_limit_denial_is_audited(
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
                "rate_limit": 1,
            }
        ],
    )

    fw = Firewall(str(policy))
    identity = make_identity("finance-agent")

    fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    result = fw.check(
        identity,
        "payments.send",
        {"amount": 20},
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

    assert len(entries) == 2


def test_rate_limit_is_thread_safe(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "allow",
                "rate_limit": 5,
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

    assert results.count("allow") == 5
    assert results.count("deny") == 15


def test_agents_have_independent_limits(tmp_path):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "action": "allow",
                "rate_limit": 2,
            }
        ],
    )

    fw = Firewall(str(policy))

    agent_a = make_identity("agent-a")
    agent_b = make_identity("agent-b")

    for _ in range(2):
        assert (
            fw.check(
                agent_a,
                "payments.send",
                {"amount": 10},
            ).action
            == "allow"
        )

    assert (
        fw.check(
            agent_a,
            "payments.send",
            {"amount": 10},
        ).action
        == "deny"
    )

    assert (
        fw.check(
            agent_b,
            "payments.send",
            {"amount": 10},
        ).action
        == "allow"
    )


def test_rate_limit_resets_after_window(
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
                "rate_limit": 2,
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

    assert (
        fw.check(
            identity,
            "payments.send",
            {"amount": 10},
        ).action
        == "allow"
    )

    assert (
        fw.check(
            identity,
            "payments.send",
            {"amount": 20},
        ).action
        == "allow"
    )

    assert (
        fw.check(
            identity,
            "payments.send",
            {"amount": 30},
        ).action
        == "deny"
    )

    now[0] += 10

    assert (
        fw.check(
            identity,
            "payments.send",
            {"amount": 40},
        ).action
        == "allow"
    )


def test_rate_limit_window_does_not_reset_early(
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

    fw = Firewall(str(policy))
    identity = make_identity("finance-agent")

    now = [1000.0]

    monkeypatch.setattr(
        engine_module.time,
        "monotonic",
        lambda: now[0],
    )

    assert (
        fw.check(
            identity,
            "payments.send",
            {"amount": 10},
        ).action
        == "allow"
    )

    now[0] += 9.999

    assert (
        fw.check(
            identity,
            "payments.send",
            {"amount": 20},
        ).action
        == "deny"
    )


def test_rate_limit_windows_are_per_agent(
    tmp_path,
    monkeypatch,
):
    import firewall.engine as engine_module

    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "action": "allow",
                "rate_limit": 1,
                "rate_limit_window": 10,
            }
        ],
    )

    fw = Firewall(str(policy))

    agent_a = make_identity("agent-a")
    agent_b = make_identity("agent-b")

    now = [1000.0]

    monkeypatch.setattr(
        engine_module.time,
        "monotonic",
        lambda: now[0],
    )

    assert (
        fw.check(
            agent_a,
            "payments.send",
            {"amount": 10},
        ).action
        == "allow"
    )

    assert (
        fw.check(
            agent_a,
            "payments.send",
            {"amount": 20},
        ).action
        == "deny"
    )

    assert (
        fw.check(
            agent_b,
            "payments.send",
            {"amount": 30},
        ).action
        == "allow"
    )


def test_rate_limit_windows_are_per_tool(
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
            },
            {
                "tool": "payments.read",
                "agent": "finance-agent",
                "action": "allow",
                "rate_limit": 1,
                "rate_limit_window": 10,
            },
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

    assert (
        fw.check(
            identity,
            "payments.send",
            {"amount": 10},
        ).action
        == "allow"
    )

    assert (
        fw.check(
            identity,
            "payments.send",
            {"amount": 20},
        ).action
        == "deny"
    )

    assert (
        fw.check(
            identity,
            "payments.read",
            {},
        ).action
        == "allow"
    )


def test_invalid_rate_limit_window_is_rejected(
    tmp_path,
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "action": "allow",
                "rate_limit": 1,
                "rate_limit_window": 0,
            }
        ],
    )

    try:
        Firewall(str(policy))
        assert False
    except ValueError:
        pass


def test_missing_rate_limit_window_uses_default(
    tmp_path,
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "action": "allow",
                "rate_limit": 1,
            }
        ],
    )

    fw = Firewall(str(policy))

    identity = make_identity("finance-agent")

    first = fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    second = fw.check(
        identity,
        "payments.send",
        {"amount": 20},
    )

    assert first.action == "allow"
    assert second.action == "deny"