from firewall.capability import Capability
from firewall.sdk import FirewallSDK


def test_legacy_firewall_path_respects_parent_revocation():
    sdk = FirewallSDK()
    sdk.generate_key("test-key")

    root = sdk.issue(
        agent="agent-root",
        capability="payments.send",
        constraints={"amount_max": 1000},
    )

    child = sdk.delegate(
        root,
        sdk.active_key().private_key,
        delegatee="agent-child",
        constraints={"amount_max": 500},
    ).child

    sdk.revoke(root)

    result = sdk.authorize(
        child,
        "payments.send",
        {"amount": 1},
    )

    assert not result.allowed
    assert result.reason == "capability_revoked"