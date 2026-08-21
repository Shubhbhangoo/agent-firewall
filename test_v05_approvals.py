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


def test_approval_policy_requires_approval(tmp_path):
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

    fw = Firewall(str(policy))

    result = fw.check(
        make_identity("finance-agent"),
        "payments.send",
        {"amount": 100},
    )

    assert result.action == "approval"


def test_approval_policy_does_not_execute_request(tmp_path):
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

    fw = Firewall(str(policy))

    result = fw.check(
        make_identity("finance-agent"),
        "payments.send",
        {"amount": 100},
    )

    assert result.action != "allow"


def test_approval_can_be_granted(tmp_path):
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

    fw = Firewall(str(policy))

    identity = make_identity("finance-agent")

    result = fw.check(
        identity,
        "payments.send",
        {"amount": 100},
    )

    assert result.action == "approval"

    approval = fw.approve(result)

    assert approval.action == "allow"


def test_approval_for_wrong_agent_is_rejected(tmp_path):
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

    fw = Firewall(str(policy))

    finance = make_identity("finance-agent")
    attacker = make_identity("attacker")

    result = fw.check(
        finance,
        "payments.send",
        {"amount": 100},
    )

    assert result.action == "approval"

    approval = fw.approve(
        result,
        attacker,
    )

    assert approval.action == "deny"


def test_approval_is_bound_to_request(tmp_path):
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

    fw = Firewall(str(policy))

    identity = make_identity("finance-agent")

    first = fw.check(
        identity,
        "payments.send",
        {"amount": 100},
    )

    second = fw.check(
        identity,
        "payments.send",
        {"amount": 200},
    )

    assert first.action == "approval"
    assert second.action == "approval"

    assert first.request_id != second.request_id

    approved = fw.approve(first)

    assert approved.action == "allow"

    reused = fw.approve(first)

    assert reused.action == "deny"


def test_approval_cannot_be_reused(tmp_path):
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

    fw = Firewall(str(policy))

    identity = make_identity("finance-agent")

    request = fw.check(
        identity,
        "payments.send",
        {"amount": 100},
    )

    first = fw.approve(request)
    second = fw.approve(request)

    assert first.action == "allow"
    assert second.action == "deny"


def test_approval_cannot_bypass_deny(tmp_path):
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
        make_identity("finance-agent"),
        "payments.send",
        {"amount": 100},
    )

    assert result.action == "deny"


def test_approval_is_audited(
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
                "action": "approval",
            }
        ],
    )

    fw = Firewall(str(policy))

    result = fw.check(
        make_identity("finance-agent"),
        "payments.send",
        {"amount": 100},
    )

    assert result.action == "approval"

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


def test_approval_does_not_consume_budget(tmp_path):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "approval",
                "budget": 100,
            }
        ],
    )

    fw = Firewall(str(policy))

    identity = make_identity("finance-agent")

    request = fw.check(
        identity,
        "payments.send",
        {"amount": 100},
    )

    assert request.action == "approval"

    approved = fw.approve(request)

    assert approved.action == "allow"


def test_approval_does_not_consume_rate_limit(tmp_path):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "approval",
                "rate_limit": 1,
            }
        ],
    )

    fw = Firewall(str(policy))

    identity = make_identity("finance-agent")

    first = fw.check(
        identity,
        "payments.send",
        {"amount": 100},
    )

    second = fw.check(
        identity,
        "payments.send",
        {"amount": 200},
    )

    assert first.action == "approval"
    assert second.action == "approval"


def test_approval_and_capability_are_both_required(
    tmp_path,
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "capability": "payments.approve",
                "action": "approval",
            }
        ],
    )

    fw = Firewall(str(policy))

    identity = AgentIdentity(
        agent_id="finance-agent",
        issuer="trusted-issuer",
        authenticated=True,
        capabilities=frozenset(),
    )

    result = fw.check(
        identity,
        "payments.send",
        {"amount": 100},
    )

    assert result.action == "deny"


def test_capable_agent_can_reach_approval(tmp_path):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "capability": "payments.approve",
                "action": "approval",
            }
        ],
    )

    fw = Firewall(str(policy))

    identity = AgentIdentity(
        agent_id="finance-agent",
        issuer="trusted-issuer",
        authenticated=True,
        capabilities=frozenset(
            {"payments.approve"}
        ),
    )

    result = fw.check(
        identity,
        "payments.send",
        {"amount": 100},
    )

    assert result.action == "approval"


def test_approval_requires_matching_request_arguments(
    tmp_path,
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "approval",
                "arguments": {
                    "currency": "USD",
                },
            }
        ],
    )

    fw = Firewall(str(policy))

    identity = make_identity("finance-agent")

    result = fw.check(
        identity,
        "payments.send",
        {
            "amount": 100,
            "currency": "USD",
        },
    )

    assert result.action == "approval"


def test_approval_request_has_unique_identity(tmp_path):
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

    fw = Firewall(str(policy))

    identity = make_identity("finance-agent")

    first = fw.check(
        identity,
        "payments.send",
        {"amount": 100},
    )

    second = fw.check(
        identity,
        "payments.send",
        {"amount": 200},
    )

    assert first is not second
    assert first.request_id
    assert second.request_id
    assert first.request_id != second.request_id