from typing import Any
import pytest
import time

from firewall.capability import Capability
from firewall.capability2 import Capability2
from firewall.delegation import Delegation
from firewall.sdk import FirewallSDK
from firewall.continuous_auth.engine import (
    ContinuousAuthorizationEngine,
    RevalidationTrigger,
)
from firewall.continuous_auth.monitor import (
    ContinuousAuthorizationMonitor,
    MonitoringConfig,
)
from firewall.continuous_auth.predicates import (
    is_narrower_than,
    authority_monotonicity_check,
    MonotonicityResult,
)

# --- Mocking helpers ---

def create_capability(agent_id: str, capability: str, constraints: dict = None, expires_at: float = None):
    # Use a dummy key pair for structural tests
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw().hex()

    # Just a dummy signature
    sig = "dummy_signature"

    return Capability(
        agent_id=agent_id,
        capability=capability,
        constraints=constraints or {},
        issuer="trusted-issuer",
        tool="test-tool",
        issued_at=time.time(),
        expires_at=expires_at or (time.time() + 3600),
        public_key=pub,
        signature=sig,
    )

# --- Monotonicity Predicate Tests ---

def test_capability_narrowing_success():
    parent = create_capability("agent-p", "read", {"path": "/data"})
    child = create_capability("agent-c", "read", {"path": "/data/public"})

    # Identical capabilities should be monotonic (equal is narrower or equal)
    parent_2 = create_capability("agent-p", "read", {"path": "/data/*"})
    child_2 = create_capability("agent-c", "read", {"path": "/data/*"})
    res = is_narrower_than(parent_2, child_2)
    assert res.monotonic

def test_capability_widening_fails():
    parent = create_capability("agent-p", "read", {"path": "/data/public"})
    child = create_capability("agent-c", "read", {"path": "/data"})

    res = is_narrower_than(parent, child)
    assert not res.monotonic

def test_capability2_narrowing():
    # Capability2 uses a different constraint model (composable namespaces)
    parent = Capability2(
        capability="read",
        constraints={"scope": "/data", "lineage": {"max_depth": 2}}
    )
    child = Capability2(
        capability="read",
        constraints={"scope": "/data/public", "lineage": {"max_depth": 1}}
    )

    res = is_narrower_than(parent, child)
    assert res.monotonic

def test_capability2_widening_fails():
    parent = Capability2(
        capability="read",
        constraints={"scope": "/data/public"}
    )
    child = Capability2(
        capability="read",
        constraints={"scope": "/data"}
    )

    res = is_narrower_than(parent, child)
    assert not res.monotonic

def test_authority_monotonicity_check_success():
    sdk = FirewallSDK()
    sdk.generate_key("test-key")

    # Root capability
    root = sdk.issue(agent="root", capability="read", constraints={"path": "/data"})

    # Delegate to agent-a (narrower)
    delegation = sdk.delegate(
        root,
        sdk.keys.active().private_key,
        delegatee="agent-a",
        constraints={"path": "/data/public"}
    )
    child = delegation.child

    res = authority_monotonicity_check(
        original_capability=root,
        derived_capability=child,
        delegation_lineage=sdk.delegation_lineage,
        revocation_registry=sdk.revocation,
    )
    assert res.monotonic

def test_authority_monotonicity_check_revocation_fails():
    sdk = FirewallSDK()
    sdk.generate_key("test-key")

    root = sdk.issue(agent="root", capability="read")
    delegation = sdk.delegate(root, sdk.keys.active().private_key, delegatee="agent-a")
    child = delegation.child

    # Revoke root
    sdk.revoke(root)

    res = authority_monotonicity_check(
        original_capability=root,
        derived_capability=child,
        delegation_lineage=sdk.delegation_lineage,
        revocation_registry=sdk.revocation,
    )
    assert not res.monotonic
    assert "revoked" in res.reason

# --- Continuous Authorization Engine Tests ---

def test_continuous_auth_engine_revalidation():
    sdk = FirewallSDK()
    sdk.generate_key("test-key")
    engine = ContinuousAuthorizationEngine(sdk)

    cap = sdk.issue(agent="agent-a", capability="read")
    action = "read"
    request = {"path": "secret.txt"}

    # 1. Initial authorization
    result = engine.authorize_with_context(cap, action, request)
    assert result.allowed

    # 2. Revalidate without state change
    reval = engine.revalidate(cap, action, request)
    assert reval.revalidated_allowed == True
    assert not reval.state_changed

    # 3. Change state (revoke capability)
    sdk.revoke(cap)

    # 4. Revalidate after state change
    reval = engine.revalidate(cap, action, request)
    assert reval.revalidated_allowed == False
    assert reval.state_changed
    assert "capability_revoked" in reval.reason

def test_continuous_auth_monitor_basic():
    sdk = FirewallSDK()
    sdk.generate_key("test-key")
    engine = ContinuousAuthorizationEngine(sdk)
    monitor = ContinuousAuthorizationMonitor(engine, sdk)

    cap = sdk.issue(agent="agent-a", capability="read")
    action = "read"
    request = {"path": "secret.txt"}

    # Use the engine to authorize and get a cache key
    result = engine.authorize_with_context(cap, action, request)

    # We need the cache key. Let's look at how it's generated in engine.py
    # fingerprint:action:hash(request)
    from firewall.capability import capability_fingerprint
    fp = capability_fingerprint(cap)
    import hashlib, json
    req_str = json.dumps(request, sort_keys=True, separators=(",", ":"))
    cache_key = f"{fp}:{action}:{hashlib.sha256(req_str.encode()).hexdigest()[:16]}"

    monitor.monitor_decision(fp, action, request, "hash", cache_key)

    # Trigger revalidation
    reval = monitor.check_and_revalidate(fp, action, request, cache_key, RevalidationTrigger.EXPLICIT_REQUEST)
    assert reval is not None
    assert reval.revalidated_allowed == True

def test_continuous_auth_periodic_revalidation():
    sdk = FirewallSDK()
    sdk.generate_key("test-key")
    engine = ContinuousAuthorizationEngine(sdk)

    # Use a very short interval for testing
    config = MonitoringConfig(
        periodic_interval=0.1,
        enable_periodic_revalidation=True,
        max_decision_age=0.5
    )
    monitor = ContinuousAuthorizationMonitor(engine, sdk, config=config)

    cap = sdk.issue(agent="agent-a", capability="read")
    action = "read"
    request = {"path": "secret.txt"}

    # Authorize and monitor
    result = engine.authorize_with_context(cap, action, request)

    from firewall.capability import capability_fingerprint
    fp = capability_fingerprint(cap)
    import hashlib, json
    req_str = json.dumps(request, sort_keys=True, separators=(",", ":"))
    cache_key = f"{fp}:{action}:{hashlib.sha256(req_str.encode()).hexdigest()[:16]}"

    monitor.monitor_decision(fp, action, request, "hash", cache_key)
    monitor.start_periodic_monitoring()

    try:
        # 1. Initially allowed
        assert result.allowed

        # 2. Revoke the capability
        sdk.revoke(cap)

        # 3. Wait for the periodic loop to trigger revalidation
        # We wait slightly longer than the periodic_interval
        time.sleep(0.3)

        # 4. Check stats to see if it was revalidated and denied
        stats = monitor.get_revalidation_stats()
        assert stats["total_revalidations"] > 0
        assert stats["decisions_changed_allow_to_deny"] > 0

        # Verify the actual decision in the monitor
        monitored = monitor.get_monitored_decisions()[cache_key]
        assert monitored.last_result.revalidated_allowed == False
    finally:
        monitor.stop_periodic_monitoring()
