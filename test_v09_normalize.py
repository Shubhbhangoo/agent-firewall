from __future__ import annotations

import pytest

from firewall.adapters.generic import (
    GenericToolCall,
)

from firewall.adapters.normalize import (
    normalize_tool_call,
)


def test_normalize_keyword_form():
    result = normalize_tool_call(
        name="payments.send",
        arguments={
            "amount": 50,
        },
    )

    assert isinstance(
        result,
        GenericToolCall,
    )

    assert result.name == (
        "payments.send"
    )

    assert result.arguments == {
        "amount": 50,
    }


def test_normalize_mapping_form():
    result = normalize_tool_call(
        {
            "name": "payments.send",
            "arguments": {
                "amount": 50,
            },
        }
    )

    assert result == GenericToolCall(
        name="payments.send",
        arguments={
            "amount": 50,
        },
    )


def test_normalize_existing_generic_call():
    original = GenericToolCall(
        name="payments.send",
        arguments={
            "amount": 50,
        },
    )

    result = normalize_tool_call(
        original
    )

    assert result == original
    assert result is not original


def test_missing_arguments_defaults_to_empty():
    result = normalize_tool_call(
        {
            "name": "payments.send",
        }
    )

    assert result.arguments == {}


def test_none_arguments_defaults_to_empty():
    result = normalize_tool_call(
        name="payments.send",
        arguments=None,
    )

    assert result.arguments == {}


def test_argument_mapping_is_copied():
    arguments = {
        "amount": 50,
    }

    result = normalize_tool_call(
        name="payments.send",
        arguments=arguments,
    )

    arguments["amount"] = 999

    assert result.arguments == {
        "amount": 50,
    }


def test_mapping_arguments_are_copied():
    call = {
        "name": "payments.send",
        "arguments": {
            "amount": 50,
        },
    }

    result = normalize_tool_call(
        call
    )

    call["arguments"]["amount"] = 999

    assert result.arguments == {
        "amount": 50,
    }


def test_name_is_stripped():
    result = normalize_tool_call(
        name="  payments.send  ",
        arguments={},
    )

    assert result.name == (
        "payments.send"
    )


def test_empty_name_rejected():
    with pytest.raises(
        ValueError
    ):
        normalize_tool_call(
            name="",
            arguments={},
        )


def test_whitespace_name_rejected():
    with pytest.raises(
        ValueError
    ):
        normalize_tool_call(
            name="   ",
            arguments={},
        )


def test_non_string_name_rejected():
    with pytest.raises(
        TypeError
    ):
        normalize_tool_call(
            name=123,
            arguments={},
        )


def test_non_mapping_call_rejected():
    with pytest.raises(
        TypeError
    ):
        normalize_tool_call(
            "payments.send"
        )


def test_non_mapping_arguments_rejected():
    with pytest.raises(
        TypeError
    ):
        normalize_tool_call(
            name="payments.send",
            arguments="bad",
        )


def test_mapping_with_invalid_name_rejected():
    with pytest.raises(
        TypeError
    ):
        normalize_tool_call(
            {
                "name": 123,
                "arguments": {},
            }
        )


def test_mapping_with_empty_name_rejected():
    with pytest.raises(
        ValueError
    ):
        normalize_tool_call(
            {
                "name": "",
                "arguments": {},
            }
        )


def test_mapping_with_invalid_arguments_rejected():
    with pytest.raises(
        TypeError
    ):
        normalize_tool_call(
            {
                "name": "payments.send",
                "arguments": "bad",
            }
        )


def test_generic_call_cannot_be_combined_with_name():
    call = GenericToolCall(
        name="payments.send",
        arguments={},
    )

    with pytest.raises(
        ValueError
    ):
        normalize_tool_call(
            call,
            name="other",
        )


def test_generic_call_cannot_be_combined_with_arguments():
    call = GenericToolCall(
        name="payments.send",
        arguments={},
    )

    with pytest.raises(
        ValueError
    ):
        normalize_tool_call(
            call,
            arguments={},
        )


def test_mapping_call_cannot_be_combined_with_explicit_fields():
    with pytest.raises(
        ValueError
    ):
        normalize_tool_call(
            {
                "name": "payments.send",
                "arguments": {},
            },
            name="other",
        )


def test_empty_call_rejected():
    with pytest.raises(
        TypeError
    ):
        normalize_tool_call()


def test_mapping_without_name_rejected():
    with pytest.raises(
        TypeError
    ):
        normalize_tool_call(
            {
                "arguments": {},
            }
        )