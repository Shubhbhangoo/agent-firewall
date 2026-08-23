from __future__ import annotations

from typing import Any, Mapping

from firewall.adapters.generic import GenericToolCall


def normalize_tool_call(
    call: Any = None,
    *,
    name: str | None = None,
    arguments: Mapping[str, Any] | None = None,
) -> GenericToolCall:
    """
    Normalize common tool-call representations into GenericToolCall.

    Accepted forms:

        normalize_tool_call(
            name="payments.send",
            arguments={"amount": 50},
        )

        normalize_tool_call(
            {
                "name": "payments.send",
                "arguments": {"amount": 50},
            }
        )

        normalize_tool_call(
            GenericToolCall(...)
        )

    The normalized arguments are copied so later caller mutation
    does not alter the normalized call.
    """

    if isinstance(
        call,
        GenericToolCall,
    ):
        if name is not None or arguments is not None:
            raise ValueError(
                "do not combine GenericToolCall with "
                "name or arguments"
            )

        return GenericToolCall(
            name=call.name,
            arguments=dict(
                call.arguments
            ),
        )

    if call is not None:

        if name is not None or arguments is not None:
            raise ValueError(
                "do not combine call with "
                "name or arguments"
            )

        if not isinstance(
            call,
            Mapping,
        ):
            raise TypeError(
                "call must be a mapping or GenericToolCall"
            )

        name = call.get("name")

        arguments = call.get(
            "arguments",
            {},
        )

    if not isinstance(
        name,
        str,
    ):
        raise TypeError(
            "tool call name must be a string"
        )

    name = name.strip()

    if not name:
        raise ValueError(
            "tool call name cannot be empty"
        )

    if arguments is None:
        arguments = {}

    if not isinstance(
        arguments,
        Mapping,
    ):
        raise TypeError(
            "tool call arguments must be a mapping"
        )

    return GenericToolCall(
        name=name,
        arguments=dict(arguments),
    )