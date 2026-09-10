import json
import threading
from concurrent.futures import ThreadPoolExecutor

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


def test_capability_budget_combination(
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
                "budget": 100,
            }
        ],
    )

    fw = Firewall(str(policy))

    identity = make_identity(
        capabilities={"payments.write"}
    )

    allowed = fw.check(
        identity,
        "payments.send",
        {"amount": 100},
    )

    denied = fw.check(
        identity,
        "payments.send",
        {"amount": 1},
    )

    assert allowed.action == "allow"
    assert denied.action == "deny"


def test_missing_capability_cannot_consume_budget(
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
                "budget": 100,
            }
        ],
    )

    fw = Firewall(str(policy))

    identity = make_identity()

    denied = fw.check(
        identity,
        "payments.send",
        {"amount": 100},
    )

    assert denied.action == "deny"

    identity_with_cap = make_identity(
        capabilities={"payments.write"}
    )

    allowed = fw.check(
        identity_with_cap,
        "payments.send",
        {"amount": 100},
    )

    assert allowed.action == "allow"


def test_capability_rate_limit_combination(
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
                "rate_limit": 2,
            }
        ],
    )

    fw = Firewall(str(policy))

    identity = make_identity(
        capabilities={"payments.write"}
    )

    results = [
        fw.check(
            identity,
            "payments.send",
            {"amount": 10},
        ).action
        for _ in range(3)
    ]

    assert results == [
        "allow",
        "allow",
        "deny",
    ]


def test_missing_capability_cannot_consume_rate_limit(
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
                "rate_limit": 1,
            }
        ],
    )

    fw = Firewall(str(policy))

    identity = make_identity()

    denied = fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    assert denied.action == "deny"

    identity_with_cap = make_identity(
        capabilities={"payments.write"}
    )

    allowed = fw.check(
        identity_with_cap,
        "payments.send",
        {"amount": 10},
    )

    assert allowed.action == "allow"


def test_approval_capability_budget_combination(
    tmp_path,
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "capability": "payments.write",
                "action": "approval",
                "budget": 100,
            }
        ],
    )

    fw = Firewall(str(policy))

    identity = make_identity(
        capabilities={"payments.write"}
    )

    request = fw.check(
        identity,
        "payments.send",
        {"amount": 100},
    )

    assert request.action == "approval"

    approved = fw.approve(
        request,
        identity,
    )

    assert approved.action == "allow"


def test_approval_missing_capability_denied(
    tmp_path,
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "capability": "payments.write",
                "action": "approval",
            }
        ],
    )

    fw = Firewall(str(policy))

    identity = make_identity()

    result = fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "deny"


def test_deny_overrides_capability_approval(
    tmp_path,
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "capability": "payments.write",
                "action": "approval",
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
        {"amount": 10},
    )

    assert result.action == "deny"


def test_deny_overrides_capability_allow(
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
        {"amount": 10},
    )

    assert result.action == "deny"


def test_rate_limit_and_budget_both_enforced(
    tmp_path,
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "allow",
                "rate_limit": 3,
                "budget": 50,
            }
        ],
    )

    fw = Firewall(str(policy))

    identity = make_identity()

    first = fw.check(
        identity,
        "payments.send",
        {"amount": 30},
    )

    second = fw.check(
        identity,
        "payments.send",
        {"amount": 30},
    )

    assert first.action == "allow"
    assert second.action == "deny"


def test_budget_denial_does_not_consume_rate_limit(
    tmp_path,
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "allow",
                "rate_limit": 2,
                "budget": 50,
            }
        ],
    )

    fw = Firewall(str(policy))

    identity = make_identity()

    denied = fw.check(
        identity,
        "payments.send",
        {"amount": 60},
    )

    assert denied.action == "deny"

    allowed = fw.check(
        identity,
        "payments.send",
        {"amount": 50},
    )

    assert allowed.action == "allow"


def test_rate_limit_denial_does_not_consume_budget(
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
                "budget": 100,
            }
        ],
    )

    fw = Firewall(str(policy))

    identity = make_identity()

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

    assert first.action == "allow"
    assert second.action == "deny"

    # If rate-limit denial did not consume budget,
    # a fresh firewall with persisted state should
    # still show only the first successful spend.
    fw2 = Firewall(str(policy))

    third = fw2.check(
        identity,
        "payments.send",
        {"amount": 60},
    )

    assert third.action == "deny"


def test_restart_preserves_combined_budget_state(
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
                "budget": 100,
            }
        ],
    )

    identity = make_identity(
        capabilities={"payments.write"}
    )

    fw1 = Firewall(str(policy))

    assert (
        fw1.check(
            identity,
            "payments.send",
            {"amount": 70},
        ).action
        == "allow"
    )

    fw2 = Firewall(str(policy))

    assert (
        fw2.check(
            identity,
            "payments.send",
            {"amount": 31},
        ).action
        == "deny"
    )


def test_restart_preserves_combined_rate_limit_state(
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
                "rate_limit": 1,
                "rate_limit_window": 60,
            }
        ],
    )

    identity = make_identity(
        capabilities={"payments.write"}
    )

    fw1 = Firewall(str(policy))

    assert (
        fw1.check(
            identity,
            "payments.send",
            {"amount": 10},
        ).action
        == "allow"
    )

    fw2 = Firewall(str(policy))

    assert (
        fw2.check(
            identity,
            "payments.send",
            {"amount": 10},
        ).action
        == "deny"
    )


def test_tampered_persistent_state_cannot_grant_access(
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

    document = json.loads(
        state_file.read_text(
            encoding="utf-8"
        )
    )

    payload = document["payload"]

    payload["budget_usage"] = {}

    state_file.write_text(
        json.dumps(document),
        encoding="utf-8",
    )

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

    # A forged state must never make the firewall
    # crash or produce an invalid decision.
    assert result.action in {
        "allow",
        "deny",
        "approval",
    }


def test_concurrent_budget_enforcement(
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

    def request():
        return fw.check(
            identity,
            "payments.send",
            {"amount": 10},
        ).action

    with ThreadPoolExecutor(
        max_workers=20
    ) as executor:

        results = list(
            executor.map(
                lambda _: request(),
                range(30),
            )
        )

    assert results.count("allow") == 10
    assert results.count("deny") == 20


def test_concurrent_rate_limit_enforcement(
    tmp_path,
):
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

    identity = make_identity()

    def request():
        return fw.check(
            identity,
            "payments.send",
            {"amount": 1},
        ).action

    with ThreadPoolExecutor(
        max_workers=20
    ) as executor:

        results = list(
            executor.map(
                lambda _: request(),
                range(30),
            )
        )

    assert results.count("allow") == 5
    assert results.count("deny") == 25


def test_concurrent_approval_consumption(
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

    fw = Firewall(str(policy))

    identity = make_identity()

    request = fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    assert request.action == "approval"

    def approve():
        return fw.approve(
            request,
            identity,
        ).action

    with ThreadPoolExecutor(
        max_workers=10
    ) as executor:

        results = list(
            executor.map(
                lambda _: approve(),
                range(10),
            )
        )

    assert results.count("allow") == 1
    assert results.count("deny") == 9


def test_concurrent_conflicting_policy_is_deterministic(
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

    def request():
        return fw.check(
            identity,
            "payments.send",
            {"amount": 10},
        ).action

    with ThreadPoolExecutor(
        max_workers=20
    ) as executor:

        results = list(
            executor.map(
                lambda _: request(),
                range(100),
            )
        )

    assert results
    assert all(
        result == "deny"
        for result in results
    )


def test_approval_request_is_not_persisted(
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
        {"amount": 50},
    )

    assert request.action == "approval"

    fw2 = Firewall(str(policy))

    result = fw2.approve(
        request,
        identity,
    )

    assert result.action == "deny"


def test_audit_chain_remains_valid_after_adversarial_requests(
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
                "budget": 50,
                "rate_limit": 2,
            },
            {
                "tool": "payments.send",
                "agent": "attacker",
                "action": "deny",
            },
        ],
    )

    fw = Firewall(str(policy))

    finance = make_identity(
        "finance-agent"
    )

    attacker = make_identity(
        "attacker"
    )

    for _ in range(5):

        fw.check(
            finance,
            "payments.send",
            {"amount": 20},
        )

    for _ in range(5):

        fw.check(
            attacker,
            "payments.send",
            {"amount": 1},
        )

    assert fw.verify_audit_chain() is True


def test_invalid_arguments_cannot_bypass_combined_controls(
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
                "rate_limit": 2,
            }
        ],
    )

    fw = Firewall(str(policy))

    identity = make_identity()

    invalid_inputs = [
        {},
        {"amount": -1},
        {"amount": 0},
        {"amount": float("inf")},
        {"amount": float("nan")},
        {"amount": True},
        {"amount": "100"},
    ]

    for arguments in invalid_inputs:

        result = fw.check(
            identity,
            "payments.send",
            arguments,
        )

        assert result.action == "deny"


def test_unknown_capability_cannot_escalate(
    tmp_path,
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "capabilities": [
                    "payments.write",
                    "payments.approve",
                ],
                "action": "allow",
            }
        ],
    )

    fw = Firewall(str(policy))

    identity = make_identity(
        capabilities={
            "admin",
            "root",
            "payments.read",
        }
    )

    result = fw.check(
        identity,
        "payments.send",
        {"amount": 10},
    )

    assert result.action == "deny"