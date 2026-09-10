

import math

import pytest

from firewall.capability import (
    CapabilityVerifier,
    generate_capability_key_pair,
    sign_capability,
)
from firewall.sdk import FirewallSDK


def make_sdk(clock=None):
    sdk = FirewallSDK(
        clock=clock,
    )
    sdk.generate_key("finite-key")
    return sdk


@pytest.mark.parametrize(
    "value",
    [
        math.nan,
        math.inf,
        -math.inf,
    ],
)
def test_sign_capability_rejects_non_finite_issued_at(value):
    private_key, _ = generate_capability_key_pair()

    with pytest.raises(
        (TypeError, ValueError),
    ):
        sign_capability(
            private_key,
            agent_id="agent-a",
            capability="filesystem.read",
            issued_at=value,
            expires_at=100.0,
        )


@pytest.mark.parametrize(
    "value",
    [
        math.nan,
        math.inf,
        -math.inf,
    ],
)
def test_sign_capability_rejects_non_finite_expires_at(value):
    private_key, _ = generate_capability_key_pair()

    with pytest.raises(
        (TypeError, ValueError),
    ):
        sign_capability(
            private_key,
            agent_id="agent-a",
            capability="filesystem.read",
            issued_at=1.0,
            expires_at=value,
        )


@pytest.mark.parametrize(
    "ttl",
    [
        math.nan,
        math.inf,
        -math.inf,
    ],
)
def test_session_mint_rejects_non_finite_ttl(ttl):
    sdk = make_sdk()

    with pytest.raises(
        ValueError,
    ):
        sdk.mint_session_capability(
            agent="agent-a",
            tool="filesystem.read",
            capability="filesystem.read",
            ttl=ttl,
        )


@pytest.mark.parametrize(
    "clock_value",
    [
        math.nan,
        math.inf,
        -math.inf,
    ],
)
def test_session_mint_rejects_non_finite_clock(clock_value):
    sdk = make_sdk(
        clock=lambda: clock_value,
    )

    with pytest.raises(
        ValueError,
    ):
        sdk.mint_session_capability(
            agent="agent-a",
            tool="filesystem.read",
            capability="filesystem.read",
            ttl=60,
        )


def test_session_mint_rejects_overflowed_expiration():
    sdk = make_sdk(
        clock=lambda: float("1.79e308"),
    )

    with pytest.raises(
        ValueError,
    ):
        sdk.mint_session_capability(
            agent="agent-a",
            tool="filesystem.read",
            capability="filesystem.read",
            ttl=1e308,
        )


def test_verifier_rejects_non_finite_clock():
    private_key, _ = generate_capability_key_pair()

    capability = sign_capability(
        private_key,
        agent_id="agent-a",
        capability="filesystem.read",
        issued_at=1.0,
        expires_at=100.0,
    )

    verifier = CapabilityVerifier(
        clock=lambda: math.nan,
    )

    assert verifier.verify(
        capability
    ) is False


def test_verifier_rejects_non_finite_capability_timestamps():
    private_key, _ = generate_capability_key_pair()

    capability = sign_capability(
        private_key,
        agent_id="agent-a",
        capability="filesystem.read",
        issued_at=1.0,
        expires_at=100.0,
    )

    tampered_issued = capability.__class__(
        agent_id=capability.agent_id,
        capability=capability.capability,
        constraints=capability.constraints,
        issuer=capability.issuer,
        issued_at=math.nan,
        expires_at=capability.expires_at,
        public_key=capability.public_key,
        signature=capability.signature,
        key_id=capability.key_id,
        tool=capability.tool,
    )

    tampered_expires = capability.__class__(
        agent_id=capability.agent_id,
        capability=capability.capability,
        constraints=capability.constraints,
        issuer=capability.issuer,
        issued_at=capability.issued_at,
        expires_at=math.inf,
        public_key=capability.public_key,
        signature=capability.signature,
        key_id=capability.key_id,
        tool=capability.tool,
    )

    verifier = CapabilityVerifier(
        clock=lambda: 50.0,
    )

    assert verifier.verify(
        tampered_issued
    ) is False

    assert verifier.verify(
        tampered_expires
    ) is False
