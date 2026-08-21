import pytest

from firewall.namespace import (
    is_broader,
    is_narrower,
    is_wildcard,
    matches,
    namespace_contains,
    namespace_depth,
    normalize_namespace,
    parent_namespace,
    validate_namespace,
)


# ============================================================
# Validation
# ============================================================


def test_valid_simple_namespace():
    assert validate_namespace(
        "payments"
    ) is True


def test_valid_nested_namespace():
    assert validate_namespace(
        "payments.send"
    ) is True


def test_valid_deep_namespace():
    assert validate_namespace(
        "payments.transactions.send"
    ) is True


def test_valid_wildcard_namespace():
    assert validate_namespace(
        "payments.*"
    ) is True


def test_empty_namespace_rejected():
    assert validate_namespace(
        ""
    ) is False


def test_none_namespace_rejected():
    assert validate_namespace(
        None
    ) is False


def test_leading_dot_rejected():
    assert validate_namespace(
        ".payments"
    ) is False


def test_trailing_dot_rejected():
    assert validate_namespace(
        "payments."
    ) is False


def test_double_dot_rejected():
    assert validate_namespace(
        "payments..send"
    ) is False


def test_wildcard_must_be_final():
    assert validate_namespace(
        "payments.*.send"
    ) is False


def test_multiple_wildcards_rejected():
    assert validate_namespace(
        "payments.*.*"
    ) is False


def test_invalid_special_character_rejected():
    assert validate_namespace(
        "payments.send!"
    ) is False


def test_spaces_rejected():
    assert validate_namespace(
        "payments send"
    ) is False


def test_whitespace_around_namespace_rejected():
    assert validate_namespace(
        " payments.send "
    ) is False


# ============================================================
# Exact matching
# ============================================================


def test_exact_namespace_matches_itself():
    assert matches(
        "payments.send",
        "payments.send",
    ) is True


def test_different_actions_do_not_match():
    assert matches(
        "payments.send",
        "payments.refund",
    ) is False


def test_different_roots_do_not_match():
    assert matches(
        "payments.send",
        "accounts.send",
    ) is False


def test_parent_namespace_does_not_match_child_without_wildcard():
    assert matches(
        "payments",
        "payments.send",
    ) is False


def test_child_namespace_does_not_match_parent():
    assert matches(
        "payments.send",
        "payments",
    ) is False


# ============================================================
# Wildcard matching
# ============================================================


def test_wildcard_matches_direct_child():
    assert matches(
        "payments.*",
        "payments.send",
    ) is True


def test_wildcard_matches_refund():
    assert matches(
        "payments.*",
        "payments.refund",
    ) is True


def test_wildcard_matches_nested_action():
    assert matches(
        "payments.*",
        "payments.transactions.send",
    ) is True


def test_wildcard_does_not_match_different_root():
    assert matches(
        "payments.*",
        "accounts.send",
    ) is False


def test_wildcard_does_not_match_parent():
    assert matches(
        "payments.*",
        "payments",
    ) is False


def test_action_wildcard_is_rejected():
    assert matches(
        "payments.send",
        "payments.*",
    ) is False


def test_root_wildcard_matches_namespace():
    assert matches(
        "*",
        "payments",
    ) is True


def test_root_wildcard_matches_deep_action():
    assert matches(
        "*",
        "payments.transactions.send",
    ) is True


# ============================================================
# Wildcard detection
# ============================================================


def test_wildcard_detected():
    assert is_wildcard(
        "payments.*"
    ) is True


def test_non_wildcard_detected():
    assert is_wildcard(
        "payments.send"
    ) is False


def test_invalid_wildcard_is_false():
    assert is_wildcard(
        "payments.*.send"
    ) is False


# ============================================================
# Narrowing
# ============================================================


def test_exact_namespace_is_narrower_than_itself():
    assert is_narrower(
        "payments.send",
        "payments.send",
    ) is True


def test_exact_namespace_is_not_narrower_than_different_action():
    assert is_narrower(
        "payments.send",
        "payments.refund",
    ) is False


def test_action_is_narrower_than_wildcard():
    assert is_narrower(
        "payments.send",
        "payments.*",
    ) is True


def test_refund_is_narrower_than_wildcard():
    assert is_narrower(
        "payments.refund",
        "payments.*",
    ) is True


def test_nested_action_is_narrower_than_wildcard():
    assert is_narrower(
        "payments.transactions.send",
        "payments.*",
    ) is True


def test_wildcard_is_not_narrower_than_specific_action():
    assert is_narrower(
        "payments.*",
        "payments.send",
    ) is False


def test_different_root_is_not_narrower():
    assert is_narrower(
        "accounts.send",
        "payments.*",
    ) is False


def test_invalid_child_is_not_narrower():
    assert is_narrower(
        "payments..send",
        "payments.*",
    ) is False


def test_invalid_parent_is_not_narrower():
    assert is_narrower(
        "payments.send",
        "payments..*",
    ) is False


# ============================================================
# Broader
# ============================================================


def test_wildcard_is_broader_than_action():
    assert is_broader(
        "payments.*",
        "payments.send",
    ) is True


def test_action_is_not_broader_than_wildcard():
    assert is_broader(
        "payments.send",
        "payments.*",
    ) is False


def test_exact_namespace_is_broader_than_itself():
    assert is_broader(
        "payments.send",
        "payments.send",
    ) is True


# ============================================================
# Parent namespace
# ============================================================


def test_parent_namespace():
    assert parent_namespace(
        "payments.send"
    ) == "payments"


def test_deep_parent_namespace():
    assert parent_namespace(
        "payments.transactions.send"
    ) == "payments.transactions"


def test_root_namespace_has_no_parent():
    assert parent_namespace(
        "payments"
    ) is None


def test_invalid_parent_namespace_rejected():
    with pytest.raises(ValueError):
        parent_namespace(
            "payments..send"
        )


# ============================================================
# Depth
# ============================================================


def test_namespace_depth_one():
    assert namespace_depth(
        "payments"
    ) == 1


def test_namespace_depth_two():
    assert namespace_depth(
        "payments.send"
    ) == 2


def test_namespace_depth_three():
    assert namespace_depth(
        "payments.transactions.send"
    ) == 3


def test_wildcard_counts_as_segment():
    assert namespace_depth(
        "payments.*"
    ) == 2


# ============================================================
# Containment
# ============================================================


def test_namespace_contains_action():
    assert namespace_contains(
        "payments.*",
        "payments.send",
    ) is True


def test_namespace_does_not_contain_other_root():
    assert namespace_contains(
        "payments.*",
        "accounts.send",
    ) is False


def test_namespace_contains_nested_action():
    assert namespace_contains(
        "payments.*",
        "payments.transactions.send",
    ) is True


# ============================================================
# Normalization
# ============================================================


def test_normalization_strips_whitespace():
    assert normalize_namespace(
        " payments.send "
    ) == "payments.send"


def test_normalization_preserves_valid_namespace():
    assert normalize_namespace(
        "payments.*"
    ) == "payments.*"


def test_normalization_rejects_invalid_namespace():
    with pytest.raises(ValueError):
        normalize_namespace(
            "payments..send"
        )


def test_normalization_rejects_non_string():
    with pytest.raises(ValueError):
        normalize_namespace(
            None
        )


# ============================================================
# Escalation resistance
# ============================================================


def test_specific_permission_cannot_escalate_to_wildcard():
    assert is_narrower(
        "payments.*",
        "payments.send",
    ) is False


def test_payments_permission_cannot_authorize_accounts():
    assert matches(
        "payments.*",
        "accounts.delete",
    ) is False


def test_send_permission_cannot_authorize_refund():
    assert matches(
        "payments.send",
        "payments.refund",
    ) is False


def test_send_permission_cannot_authorize_admin():
    assert matches(
        "payments.send",
        "payments.admin",
    ) is False


def test_wildcard_cannot_change_root():
    assert is_narrower(
        "accounts.*",
        "payments.*",
    ) is False


def test_prefix_confusion_is_rejected():
    assert matches(
        "pay",
        "payments.send",
    ) is False


def test_prefix_confusion_with_wildcard_is_rejected():
    assert matches(
        "pay.*",
        "payments.send",
    ) is False


# ============================================================
# Nested namespace security
# ============================================================


def test_nested_namespace_exact_match():
    assert matches(
        "payments.transactions.send",
        "payments.transactions.send",
    ) is True


def test_nested_namespace_wrong_leaf_rejected():
    assert matches(
        "payments.transactions.send",
        "payments.transactions.refund",
    ) is False


def test_nested_wildcard_matches_leaf():
    assert matches(
        "payments.transactions.*",
        "payments.transactions.send",
    ) is True


def test_nested_wildcard_matches_deeper_action():
    assert matches(
        "payments.transactions.*",
        "payments.transactions.crypto.send",
    ) is True


def test_nested_wildcard_wrong_root_rejected():
    assert matches(
        "payments.transactions.*",
        "accounts.transactions.send",
    ) is False