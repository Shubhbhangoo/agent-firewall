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


def test_deny_beats_allow(tmp_path):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "allow",
            },
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "deny",
            },
        ],
    )

    fw = Firewall(str(policy))

    result = fw.check(
        make_identity(),
        "payments.send",
        {"amount": 100},
    )

    assert result.action == "deny"


def test_deny_beats_approval(tmp_path):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "approval",
            },
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "deny",
            },
        ],
    )

    fw = Firewall(str(policy))

    result = fw.check(
        make_identity(),
        "payments.send",
        {"amount": 100},
    )

    assert result.action == "deny"


def test_approval_beats_allow(tmp_path):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "allow",
            },
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "approval",
            },
        ],
    )

    fw = Firewall(str(policy))

    result = fw.check(
        make_identity(),
        "payments.send",
        {"amount": 100},
    )

    assert result.action == "approval"


def test_conflicting_rules_are_deterministic(
    tmp_path,
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "action": "allow",
            },
            {
                "tool": "payments.send",
                "action": "approval",
            },
            {
                "tool": "payments.send",
                "action": "deny",
            },
        ],
    )

    fw = Firewall(str(policy))

    identity = make_identity()

    results = [
        fw.check(
            identity,
            "payments.send",
            {"amount": 10},
        ).action
        for _ in range(20)
    ]

    assert all(
        action == "deny"
        for action in results
    )


def test_capability_rule_cannot_be_bypassed_by_broad_allow(
    tmp_path,
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "action": "allow",
            },
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "capability": "payments.write",
                "action": "deny",
            },
        ],
    )

    fw = Firewall(str(policy))

    identity = make_identity(
        capabilities=set()
    )

    result = fw.check(
        identity,
        "payments.send",
        {"amount": 100},
    )

    assert result.action == "allow"


def test_capability_deny_wins_when_capability_matches(
    tmp_path,
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "action": "allow",
            },
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "capability": "payments.write",
                "action": "deny",
            },
        ],
    )

    fw = Firewall(str(policy))

    identity = make_identity(
        capabilities={"payments.write"}
    )

    result = fw.check(
        identity,
        "payments.send",
        {"amount": 100},
    )

    assert result.action == "deny"


def test_missing_capability_does_not_match_deny_rule(
    tmp_path,
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "action": "allow",
            },
            {
                "tool": "payments.send",
                "capability": "payments.write",
                "action": "deny",
            },
        ],
    )

    fw = Firewall(str(policy))

    identity = make_identity()

    result = fw.check(
        identity,
        "payments.send",
        {"amount": 100},
    )

    assert result.action == "allow"


def test_budget_rule_cannot_be_bypassed_by_unlimited_allow(
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
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "allow",
            },
        ],
    )

    fw = Firewall(str(policy))

    identity = make_identity()

    first = fw.check(
        identity,
        "payments.send",
        {"amount": 100},
    )

    second = fw.check(
        identity,
        "payments.send",
        {"amount": 1},
    )

    assert first.action == "allow"
    assert second.action == "deny"


def test_rate_limit_rule_cannot_be_bypassed_by_unlimited_allow(
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
            },
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "allow",
            },
        ],
    )

    fw = Firewall(str(policy))

    identity = make_identity()

    first = fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    second = fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    assert first.action == "allow"
    assert second.action == "deny"


def test_deny_cannot_be_downgraded_by_later_allow(
    tmp_path,
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "deny",
            },
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "allow",
            },
        ],
    )

    fw = Firewall(str(policy))

    result = fw.check(
        make_identity(),
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "deny"


def test_deny_cannot_be_downgraded_by_approval(
    tmp_path,
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "deny",
            },
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "approval",
            },
        ],
    )

    fw = Firewall(str(policy))

    result = fw.check(
        make_identity(),
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "deny"


def test_agent_specific_deny_beats_generic_allow(
    tmp_path,
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "action": "allow",
            },
            {
                "tool": "payments.send",
                "agent": "blocked-agent",
                "action": "deny",
            },
        ],
    )

    fw = Firewall(str(policy))

    blocked = fw.check(
        make_identity("blocked-agent"),
        "payments.send",
        {"amount": 10},
    )

    allowed = fw.check(
        make_identity("finance-agent"),
        "payments.send",
        {"amount": 10},
    )

    assert blocked.action == "deny"
    assert allowed.action == "allow"


def test_agent_specific_approval_beats_generic_allow(
    tmp_path,
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "action": "allow",
            },
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "approval",
            },
        ],
    )

    fw = Firewall(str(policy))

    finance = fw.check(
        make_identity("finance-agent"),
        "payments.send",
        {"amount": 10},
    )

    other = fw.check(
        make_identity("other-agent"),
        "payments.send",
        {"amount": 10},
    )

    assert finance.action == "approval"
    assert other.action == "allow"


def test_tool_specific_deny_beats_other_tool_allow(
    tmp_path,
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "action": "deny",
            },
            {
                "tool": "payments.read",
                "action": "allow",
            },
        ],
    )

    fw = Firewall(str(policy))

    send = fw.check(
        make_identity(),
        "payments.send",
        {"amount": 10},
    )

    read = fw.check(
        make_identity(),
        "payments.read",
        {},
    )

    assert send.action == "deny"
    assert read.action == "allow"


def test_no_matching_rule_never_falls_back_to_allow(
    tmp_path,
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.read",
                "action": "allow",
            }
        ],
    )

    fw = Firewall(str(policy))

    result = fw.check(
        make_identity(),
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "deny"


def test_final_decision_is_audited(
    tmp_path,
    monkeypatch,
):
    monkeypatch.chdir(tmp_path)

    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "action": "allow",
            },
            {
                "tool": "payments.send",
                "action": "deny",
            },
        ],
    )

    fw = Firewall(str(policy))

    result = fw.check(
        make_identity(),
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "deny"

    audit = (
        tmp_path / "audit.log"
    ).read_text(
        encoding="utf-8"
    )

    assert '"decision": "deny"' in audit


def test_conflicting_rules_are_thread_safe(
    tmp_path,
):
    from concurrent.futures import ThreadPoolExecutor

    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "action": "allow",
            },
            {
                "tool": "payments.send",
                "action": "approval",
            },
            {
                "tool": "payments.send",
                "action": "deny",
            },
        ],
    )

    fw = Firewall(str(policy))

    identity = make_identity()

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
                range(50),
            )
        )

    assert results
    assert all(
        result == "deny"
        for result in results
    )