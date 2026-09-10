import json

import pytest

from firewall.evidence import (
    Evidence,
    allow_evidence,
    approval_evidence,
    deny_evidence,
    evidence_from_dict,
    make_evidence,
)


def test_allow_evidence():
    evidence = allow_evidence()

    assert evidence.decision == "allow"
    assert evidence.reason == "authorized"


def test_deny_evidence():
    evidence = deny_evidence(
        "namespace_denied"
    )

    assert evidence.decision == "deny"
    assert (
        evidence.reason
        == "namespace_denied"
    )


def test_approval_evidence():
    evidence = approval_evidence()

    assert evidence.decision == "approval"


def test_agent_identity_is_recorded():
    evidence = allow_evidence(
        agent_id="finance-agent"
    )

    assert (
        evidence.agent_id
        == "finance-agent"
    )


def test_capability_is_recorded():
    evidence = allow_evidence(
        capability="payments.send"
    )

    assert (
        evidence.capability
        == "payments.send"
    )


def test_namespace_result_is_recorded():
    evidence = allow_evidence(
        namespace_match=True
    )

    assert (
        evidence.namespace_match
        is True
    )


def test_constraint_result_is_recorded():
    evidence = allow_evidence(
        constraints_ok=True
    )

    assert (
        evidence.constraints_ok
        is True
    )


def test_time_result_is_recorded():
    evidence = allow_evidence(
        time_valid=True
    )

    assert (
        evidence.time_valid
        is True
    )


def test_policy_is_recorded():
    evidence = allow_evidence(
        policy="finance-policy"
    )

    assert (
        evidence.policy
        == "finance-policy"
    )


def test_request_id_is_recorded():
    evidence = allow_evidence(
        request_id="req-123"
    )

    assert (
        evidence.request_id
        == "req-123"
    )


def test_details_are_recorded():
    evidence = allow_evidence(
        details={
            "budget_remaining": 50,
        }
    )

    assert (
        evidence.details[
            "budget_remaining"
        ]
        == 50
    )


def test_to_dict():
    evidence = Evidence(
        decision="allow",
        reason="authorized",
        agent_id="agent-a",
        capability="payments.send",
        namespace_match=True,
        constraints_ok=True,
        time_valid=True,
        policy="policy-a",
        request_id="req-1",
        details={
            "x": 1,
        },
    )

    data = evidence.to_dict()

    assert data["decision"] == "allow"
    assert data["reason"] == "authorized"
    assert data["agent_id"] == "agent-a"
    assert data["capability"] == "payments.send"
    assert data["namespace_match"] is True
    assert data["constraints_ok"] is True
    assert data["time_valid"] is True
    assert data["policy"] == "policy-a"
    assert data["request_id"] == "req-1"
    assert data["details"]["x"] == 1


def test_to_json_is_valid_json():
    evidence = allow_evidence(
        agent_id="agent-a"
    )

    decoded = json.loads(
        evidence.to_json()
    )

    assert decoded["decision"] == "allow"


def test_json_is_deterministic():
    first = allow_evidence(
        details={
            "b": 2,
            "a": 1,
        }
    )

    second = allow_evidence(
        details={
            "a": 1,
            "b": 2,
        }
    )

    assert (
        first.to_json()
        == second.to_json()
    )


def test_fingerprint_is_deterministic():
    evidence = allow_evidence(
        agent_id="agent-a"
    )

    assert (
        evidence.fingerprint()
        == evidence.fingerprint()
    )


def test_different_evidence_has_different_fingerprint():
    first = allow_evidence(
        reason="authorized"
    )

    second = allow_evidence(
        reason="different"
    )

    assert (
        first.fingerprint()
        != second.fingerprint()
    )


def test_round_trip():
    evidence = Evidence(
        decision="deny",
        reason="expired",
        agent_id="agent-a",
        capability="payments.send",
        namespace_match=True,
        constraints_ok=True,
        time_valid=False,
        policy="policy-a",
        request_id="req-1",
        details={
            "x": 10,
        },
    )

    restored = evidence_from_dict(
        evidence.to_dict()
    )

    assert (
        restored.to_dict()
        == evidence.to_dict()
    )


def test_private_key_is_removed():
    evidence = allow_evidence(
        details={
            "private_key": "secret-value",
            "safe": "value",
        }
    )

    data = evidence.to_dict()

    assert (
        "private_key"
        not in data["details"]
    )

    assert (
        data["details"]["safe"]
        == "value"
    )


def test_nested_secrets_are_removed():
    evidence = allow_evidence(
        details={
            "nested": {
                "secret": "hidden",
                "visible": True,
            }
        }
    )

    nested = evidence.to_dict()[
        "details"
    ]["nested"]

    assert "secret" not in nested
    assert nested["visible"] is True


def test_multiple_sensitive_fields_are_removed():
    evidence = allow_evidence(
        details={
            "password": "x",
            "token": "y",
            "seed": "z",
            "mnemonic": "q",
            "normal": "safe",
        }
    )

    details = evidence.to_dict()[
        "details"
    ]

    assert "password" not in details
    assert "token" not in details
    assert "seed" not in details
    assert "mnemonic" not in details
    assert details["normal"] == "safe"


def test_private_key_never_appears_in_json():
    evidence = allow_evidence(
        details={
            "private_key": "SUPER_SECRET",
        }
    )

    assert (
        "SUPER_SECRET"
        not in evidence.to_json()
    )


def test_private_key_never_affects_fingerprint():
    first = allow_evidence(
        details={
            "private_key": "one",
            "safe": True,
        }
    )

    second = allow_evidence(
        details={
            "private_key": "two",
            "safe": True,
        }
    )

    assert (
        first.fingerprint()
        == second.fingerprint()
    )


def test_invalid_decision_rejected():
    with pytest.raises(ValueError):
        make_evidence(
            "",
            "reason",
        )


def test_invalid_reason_rejected():
    with pytest.raises(ValueError):
        make_evidence(
            "deny",
            "",
        )


def test_non_dict_details_rejected():
    with pytest.raises(TypeError):
        make_evidence(
            "deny",
            "reason",
            details=[],
        )


def test_details_are_copied():
    source = {
        "value": 1,
    }

    evidence = allow_evidence(
        details=source
    )

    source["value"] = 2

    assert (
        evidence.details["value"]
        == 1
    )


def test_evidence_is_immutable():
    evidence = allow_evidence()

    with pytest.raises(
        AttributeError
    ):
        evidence.decision = "deny"


def test_nested_lists_are_sanitized():
    evidence = allow_evidence(
        details={
            "items": [
                {
                    "private_key": "secret",
                    "value": 1,
                }
            ]
        }
    )

    items = evidence.to_dict()[
        "details"
    ]["items"]

    assert (
        "private_key"
        not in items[0]
    )

    assert items[0]["value"] == 1


def test_nested_sets_are_serializable():
    evidence = allow_evidence(
        details={
            "values": {
                "b",
                "a",
            }
        }
    )

    encoded = evidence.to_json()

    decoded = json.loads(
        encoded
    )

    assert decoded["details"][
        "values"
    ] == ["a", "b"]


def test_evidence_from_dict_rejects_non_dict():
    with pytest.raises(TypeError):
        evidence_from_dict(
            []
        )


def test_evidence_from_dict_preserves_optional_fields():
    evidence = evidence_from_dict(
        {
            "decision": "deny",
            "reason": "expired",
        }
    )

    assert evidence.agent_id is None
    assert evidence.capability is None
    assert evidence.policy is None
    assert evidence.details == {}