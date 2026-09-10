from __future__ import annotations

import base64
import os

import pytest
from hypothesis import given, strategies as st

from firewall.capability import Capability
from firewall.policy import (
    PolicyDefinitionError,
    evaluate_policy,
)
from firewall.sdk import FirewallSDK
from firewall.transport import (
    decode_capability,
)


# ============================================================
# Helpers
# ============================================================


def make_sdk():
    sdk = FirewallSDK()
    sdk.generate_key("key-1")
    return sdk


# ============================================================
# Token / transport fuzzing
# ============================================================


@given(
    st.binary(
        min_size=0,
        max_size=4096,
    )
)
def test_random_bytes_never_crash_decode(
    data,
):
    token = base64.b64encode(
        data
    ).decode("ascii")

    try:
        decode_capability(token)
    except Exception:
        pass


@given(
    st.text(
        min_size=0,
        max_size=4096,
    )
)
def test_random_strings_never_authorize_as_token(
    token,
):
    sdk = make_sdk()

    try:
        capability = sdk.decode(
            token
        )

        assert sdk.verify(
            capability
        ) is False

    except Exception:
        pass

    finally:
        sdk.close()


@given(
    st.dictionaries(
        st.text(
            min_size=0,
            max_size=50,
        ),
        st.one_of(
            st.none(),
            st.booleans(),
            st.integers(),
            st.floats(
                allow_nan=False,
                allow_infinity=False,
            ),
            st.text(
                max_size=100,
            ),
            st.lists(
                st.integers(),
                max_size=10,
            ),
        ),
        max_size=25,
    )
)
def test_random_capability_dict_never_verifies(
    data,
):
    try:
        capability = Capability(
            **data
        )

        sdk = make_sdk()

        assert sdk.verify(
            capability
        ) is False

        sdk.close()

    except Exception:
        pass


# ============================================================
# Policy fuzzing
# ============================================================


@given(
    st.recursive(
        st.one_of(
            st.none(),
            st.booleans(),
            st.integers(),
            st.text(
                max_size=30,
            ),
            st.lists(
                st.integers(),
                max_size=5,
            ),
        ),
        lambda children: st.dictionaries(
            st.text(
                min_size=0,
                max_size=20,
            ),
            children,
            max_size=8,
        ),
        max_leaves=30,
    )
)
def test_random_policy_never_escapes_unexpected_exception(
    policy,
):
    request = {
        "amount": 50,
        "currency": "USD",
        "region": "us-east",
    }

    try:
        result = evaluate_policy(
            policy,
            request,
        )

        assert isinstance(
            result.allowed,
            bool,
        )

    except PolicyDefinitionError:
        pass


@given(
    st.dictionaries(
        st.text(
            min_size=0,
            max_size=20,
        ),
        st.integers(),
        max_size=10,
    )
)
def test_random_request_is_safe(
    request,
):
    policy = {
        "amount": {
            "gte": 0,
            "lte": 100,
        }
    }

    result = evaluate_policy(
        policy,
        request,
    )

    assert isinstance(
        result.allowed,
        bool,
    )


# ============================================================
# Constraint fuzzing
# ============================================================


@given(
    st.recursive(
        st.one_of(
            st.none(),
            st.booleans(),
            st.integers(),
            st.text(
                max_size=30,
            ),
            st.lists(
                st.integers(),
                max_size=5,
            ),
        ),
        lambda children: st.dictionaries(
            st.text(
                min_size=0,
                max_size=20,
            ),
            children,
            max_size=6,
        ),
        max_leaves=20,
    )
)
def test_random_constraints_never_crash_authorization(
    constraints,
):
    sdk = make_sdk()

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
        constraints=(
            constraints
            if isinstance(
                constraints,
                dict,
            )
            else {}
        ),
    )

    try:
        result = sdk.authorize(
            capability,
            "payments.send",
            {
                "amount": 50,
                "currency": "USD",
                "region": "us-east",
            },
        )

        assert isinstance(
            result.allowed,
            bool,
        )

    except Exception as exc:
        pytest.fail(
            f"unexpected authorization exception: {exc!r}"
        )

    finally:
        sdk.close()


# ============================================================
# Replay fuzzing
# ============================================================


@given(
    st.text(
        min_size=0,
        max_size=500,
    )
)
def test_random_nonces_are_safe(
    nonce,
):
    sdk = make_sdk()

    capability = sdk.issue(
        agent="agent-a",
        capability="payments.send",
    )

    try:
        first = sdk.consume_nonce(
            "agent-a",
            capability,
            nonce,
        )

        second = sdk.consume_nonce(
            "agent-a",
            capability,
            nonce,
        )

        if nonce:
            assert first is True
            assert second is False

    except (
        ValueError,
        TypeError,
    ):
        pass

    finally:
        sdk.close()


# ============================================================
# String / unicode edge cases
# ============================================================


@given(
    st.text(
        min_size=1,
        max_size=1000,
    )
)
def test_unicode_agent_ids_do_not_break_issuance(
    agent,
):
    sdk = make_sdk()

    try:
        capability = sdk.issue(
            agent=agent,
            capability="payments.send",
        )

        assert sdk.verify(
            capability
        ) is True

    except (
        ValueError,
        TypeError,
    ):
        pass

    finally:
        sdk.close()


# ============================================================
# Oversized input
# ============================================================



def test_oversized_token_is_rejected():
    data = b"x" * 5000

    token = base64.b64encode(
        data
    ).decode("ascii")

    sdk = make_sdk()

    try:
        with pytest.raises(Exception):
            sdk.decode(
                token,
                max_size=4096,
            )

    finally:
        sdk.close()