import pytest

from firewall.delegation import (
    delegate_capability,
)
from firewall.capability import (
    generate_capability_key_pair,
    sign_capability,
)


def test_delegate_with_mismatched_private_key_fails_closed():
    parent_private, _ = (
        generate_capability_key_pair()
    )

    wrong_private, _ = (
        generate_capability_key_pair()
    )

    parent = sign_capability(
        parent_private,
        agent_id="agent-a",
        capability="payments.send",
        constraints={
            "amount_max": 1000,
        },
    )

    with pytest.raises(
        ValueError,
        match="invalid delegation",
    ):
        delegate_capability(
            parent,
            wrong_private,
            "agent-b",
            constraints={
                "amount_max": 100,
            },
        )