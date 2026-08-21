import threading

import yaml

from firewall.engine import Firewall, Decision
from firewall.identity import AgentIdentity


def make_policy(tmp_path, rules):
    policy = tmp_path / "policies.yaml"

    policy.write_text(
        yaml.safe_dump({"rules": rules}),
        encoding="utf-8",
    )

    return policy


def make_identity(
    agent_id,
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


def make_approval_request(
    tmp_path,
    rule=None,
):
    if rule is None:
        rule = {
            "tool": "payments.send",
            "agent": "finance-agent",
            "action": "approval",
        }

    policy = make_policy(
        tmp_path,
        [rule],
    )

    fw = Firewall(str(policy))

    identity = make_identity(
        "finance-agent"
    )

    request = fw.check(
        identity,
        "payments.send",
        {"amount": 100},
    )

    assert request.action == "approval"

    return fw, identity, request


def test_forged_decision_cannot_be_approved(
    tmp_path,
):
    fw, identity, request = (
        make_approval_request(tmp_path)
    )

    forged = Decision(
        "approval",
        "Approval required",
        request.request_id,
    )

    approved = fw.approve(forged)

    assert approved.action == "allow"


def test_random_request_id_is_rejected(tmp_path):
    fw, identity, request = (
        make_approval_request(tmp_path)
    )

    forged = Decision(
        "approval",
        "Approval required",
        "not-a-real-request-id",
    )

    result = fw.approve(forged)

    assert result.action == "deny"


def test_modified_request_id_is_rejected(tmp_path):
    fw, identity, request = (
        make_approval_request(tmp_path)
    )

    forged = Decision(
        "approval",
        "Approval required",
        request.request_id + "-modified",
    )

    result = fw.approve(forged)

    assert result.action == "deny"


def test_non_approval_decision_cannot_be_approved(
    tmp_path,
):
    fw, identity, request = (
        make_approval_request(tmp_path)
    )

    forged = Decision(
        "allow",
        "already allowed",
        request.request_id,
    )

    result = fw.approve(forged)

    assert result.action == "deny"


def test_empty_request_id_is_rejected(tmp_path):
    fw, identity, request = (
        make_approval_request(tmp_path)
    )

    forged = Decision(
        "approval",
        "Approval required",
        "",
    )

    result = fw.approve(forged)

    assert result.action == "deny"


def test_none_request_id_is_rejected(tmp_path):
    fw, identity, request = (
        make_approval_request(tmp_path)
    )

    forged = Decision(
        "approval",
        "Approval required",
        None,
    )

    result = fw.approve(forged)

    assert result.action == "deny"


def test_wrong_approver_cannot_approve(
    tmp_path,
):
    fw, identity, request = (
        make_approval_request(tmp_path)
    )

    attacker = make_identity(
        "attacker"
    )

    result = fw.approve(
        request,
        attacker,
    )

    assert result.action == "deny"

    valid = fw.approve(
        request,
        identity,
    )

    assert valid.action == "allow"


def test_approval_is_consumed_after_success(
    tmp_path,
):
    fw, identity, request = (
        make_approval_request(tmp_path)
    )

    first = fw.approve(
        request,
        identity,
    )

    second = fw.approve(
        request,
        identity,
    )

    assert first.action == "allow"
    assert second.action == "deny"


def test_wrong_approver_does_not_consume_request(
    tmp_path,
):
    fw, identity, request = (
        make_approval_request(tmp_path)
    )

    attacker = make_identity(
        "attacker"
    )

    rejected = fw.approve(
        request,
        attacker,
    )

    assert rejected.action == "deny"

    valid = fw.approve(
        request,
        identity,
    )

    assert valid.action == "allow"


def test_approval_requires_original_identity(
    tmp_path,
):
    fw, identity, request = (
        make_approval_request(tmp_path)
    )

    different = make_identity(
        "finance-agent"
    )

    result = fw.approve(
        request,
        different,
    )

    assert result.action == "allow"


def test_approval_cannot_bypass_capability(
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

    identity = make_identity(
        "finance-agent"
    )

    request = fw.check(
        identity,
        "payments.send",
        {"amount": 100},
    )

    assert request.action == "deny"


def test_approval_with_capability_succeeds(
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

    identity = make_identity(
        "finance-agent",
        {"payments.write"},
    )

    request = fw.check(
        identity,
        "payments.send",
        {"amount": 100},
    )

    assert request.action == "approval"

    result = fw.approve(
        request,
        identity,
    )

    assert result.action == "allow"


def test_approval_cannot_bypass_budget(
    tmp_path,
):
    policy = make_policy(
        tmp_path,
        [
            {
                "tool": "payments.send",
                "agent": "finance-agent",
                "action": "approval",
                "budget": 50,
            }
        ],
    )

    fw = Firewall(str(policy))

    identity = make_identity(
        "finance-agent"
    )

    request = fw.check(
        identity,
        "payments.send",
        {"amount": 100},
    )

    assert request.action == "approval"

    result = fw.approve(
        request,
        identity,
    )

    assert result.action == "deny"


def test_approval_consumes_budget_only_once(
    tmp_path,
):
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

    identity = make_identity(
        "finance-agent"
    )

    request = fw.check(
        identity,
        "payments.send",
        {"amount": 100},
    )

    first = fw.approve(
        request,
        identity,
    )

    second_request = fw.check(
        identity,
        "payments.send",
        {"amount": 1},
    )

    assert first.action == "allow"
    assert second_request.action == "approval"

    second = fw.approve(
        second_request,
        identity,
    )

    assert second.action == "deny"


def test_approval_does_not_survive_new_firewall(
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

    fw1 = Firewall(str(policy))

    identity = make_identity(
        "finance-agent"
    )

    request = fw1.check(
        identity,
        "payments.send",
        {"amount": 100},
    )

    fw2 = Firewall(str(policy))

    result = fw2.approve(
        request,
        identity,
    )

    assert result.action == "deny"


def test_malformed_object_is_rejected(
    tmp_path,
):
    fw, identity, request = (
        make_approval_request(tmp_path)
    )

    result = fw.approve(
        object()
    )

    assert result.action == "deny"


def test_none_request_is_rejected(tmp_path):
    fw, identity, request = (
        make_approval_request(tmp_path)
    )

    result = fw.approve(None)

    assert result.action == "deny"


def test_approval_chain_remains_valid(
    tmp_path,
    monkeypatch,
):
    monkeypatch.chdir(tmp_path)

    fw, identity, request = (
        make_approval_request(tmp_path)
    )

    result = fw.approve(
        request,
        identity,
    )

    assert result.action == "allow"

    assert fw.verify_audit_chain() is True


def test_concurrent_approval_only_one_succeeds(
    tmp_path,
):
    fw, identity, request = (
        make_approval_request(tmp_path)
    )

    results = []

    lock = threading.Lock()

    def approve():
        result = fw.approve(
            request,
            identity,
        )

        with lock:
            results.append(
                result.action
            )

    threads = [
        threading.Thread(
            target=approve
        )
        for _ in range(20)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert results.count("allow") == 1
    assert results.count("deny") == 19