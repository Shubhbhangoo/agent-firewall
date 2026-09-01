import pytest
import time
from firewall.sdk import FirewallSDK
from firewall.continuous_auth.monitor import MonitoringConfig
from firewall.continuous_auth.engine import RevalidationTrigger
from firewall.capability import sign_capability, capability_fingerprint

def test_sdk_continuous_auth_integration():
    # 1. Setup SDK with continuous auth config
    config = MonitoringConfig(
        periodic_interval=0.1,
        enable_periodic_revalidation=True,
        max_decision_age=0.5,
        min_revalidation_interval=0.05
    )
    sdk = FirewallSDK(continuous_auth_config=config)
    sdk.generate_key("test-key")

    # 2. Issue a capability
    cap = sdk.issue(agent="agent-a", capability="read")
    action = "read"
    request = {"path": "secret.txt"}

    # 3. Authorize using the continuous path
    result = sdk.authorize_continuous(cap, action, request)
    assert result.allowed

    # 4. Verify it's being monitored
    assert sdk.continuous_auth_monitor is not None
    decisions = sdk.continuous_auth_monitor.get_monitored_decisions()
    assert len(decisions) == 1

    # 5. Revoke the capability
    sdk.revoke(cap)

    # 6. Manual revalidation via SDK
    reval = sdk.revalidate(cap, action, request, trigger=RevalidationTrigger.EXPLICIT_REQUEST)
    assert reval is not None
    assert reval.revalidated_allowed == False
    assert "capability_revoked" in reval.reason

def test_sdk_continuous_auth_periodic():
    config = MonitoringConfig(
        periodic_interval=0.1,
        enable_periodic_revalidation=True,
        max_decision_age=0.5,
        min_revalidation_interval=0.05
    )
    sdk = FirewallSDK(continuous_auth_config=config)
    sdk.generate_key("test-key")

    cap = sdk.issue(agent="agent-a", capability="read")
    action = "read"
    request = {"path": "secret.txt"}

    # Authorize and start monitoring
    sdk.authorize_continuous(cap, action, request)
    sdk.continuous_auth_monitor.start_periodic_monitoring()

    try:
        # Revoke
        sdk.revoke(cap)

        # Wait for periodic check
        time.sleep(0.3)

        stats = sdk.continuous_auth_monitor.get_revalidation_stats()
        assert stats["total_revalidations"] > 0
        assert stats["decisions_changed_allow_to_deny"] > 0
    finally:
        sdk.close()

def test_sdk_no_continuous_auth_fallback():
    # SDK without continuous config
    sdk = FirewallSDK()
    sdk.generate_key("test-key")

    cap = sdk.issue(agent="agent-a", capability="read")
    action = "read"
    request = {"path": "secret.txt"}

    # Should fallback to regular authorize
    result = sdk.authorize_continuous(cap, action, request)
    assert result.allowed
    assert sdk.continuous_auth_engine is None
    assert sdk.continuous_auth_monitor is None

def test_sdk_delegation_monotonicity_enforcement():
    sdk = FirewallSDK()
    sdk.generate_key("test-key")

    # Root: read /data
    root = sdk.issue(agent="root", capability="read", constraints={"path": "/data"})

    # Manually create a child capability with WIDER constraints: read /
    # This bypasses sdk.delegate()'s constraint check.
    child = sign_capability(
        sdk.keys.active().private_key,
        agent_id="agent-a",
        capability="read",
        constraints={"path": "/"}, # WIDER than /data
        issuer=root.issuer,
        issued_at=root.issued_at,
        expires_at=root.expires_at,
        tool=root.tool,
        parent_fingerprint=capability_fingerprint(root),
    )

    # Register the delegation in the lineage registry
    sdk.delegation_lineage.register(
        child_fingerprint=capability_fingerprint(child),
        parent_fingerprint=capability_fingerprint(root)
    )

    # Now authorize with the child
    result = sdk.authorize(child, "read", {"path": "/etc/passwd"})

    # It should be denied due to monotonicity widening
    assert result.allowed == False
    assert "delegation_widening" in result.reason
    assert child.parent_fingerprint == capability_fingerprint(root)
