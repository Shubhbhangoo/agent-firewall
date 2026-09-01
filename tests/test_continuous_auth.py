"""v2.2 §1 Continuous Authorization tests.

Covers the thirteen required cases: valid authorization, revalidation,
revoked capability, expired capability, changed policy, changed posture,
changed identity, changed delegation, missing context, failed security
dependency, repeated monitoring, monitor shutdown, and fail-closed
behaviour -- plus the monotonicity predicates the engine relies on.

Two conventions in here are deliberate and worth knowing before editing:

* ``make_capability`` signs every capability with ONE module-level key.
  An earlier version generated a fresh key pair per capability, which
  made every pair look like a signing-key substitution to
  ``is_narrower_than`` and quietly defeated the check it was meant to
  exercise. Real delegation preserves the issuer's key; the test data
  has to as well.

* Narrowing is asserted with list-subset and ``*_max`` constraints, not
  string prefixes. ``_constraints_are_narrower`` treats strings as exact
  match, so ``"/data" -> "/data/public"`` is a *change*, not a
  narrowing, and ``delegate_capability`` rejects it. Using a prefix here
  tests the test, not the system.

Where a subsystem exists in the codebase (IdentityRegistry,
PostureEngine) the tests drive the real thing. Stubs appear only for the
failure-injection cases, where the point is a dependency that raises.
"""

import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from firewall.capability import Capability, capability_fingerprint
from firewall.capability2 import Capability2
from firewall.ident.registry import IdentityRegistry
from firewall.posture.engine import PostureEngine, PostureSignal
from firewall.sdk import FirewallSDK
from firewall.continuous_auth.engine import (
    PROBE_FAILED,
    UNKNOWN,
    ContinuousAuthorizationEngine,
    RevalidationTrigger,
)
from firewall.continuous_auth.monitor import (
    ContinuousAuthorizationMonitor,
    MonitoringConfig,
    RevalidationOutcome,
)
from firewall.continuous_auth.predicates import (
    authority_monotonicity_check,
    is_narrower_than,
)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

# One key pair for the whole module. See the module docstring.
_PRIVATE_KEY = Ed25519PrivateKey.generate()
_PUBLIC_KEY_HEX = _PRIVATE_KEY.public_key().public_bytes_raw().hex()


def make_capability(
    agent_id: str,
    capability: str = "read",
    constraints: dict | None = None,
    *,
    issued_at: float | None = None,
    expires_at: float | None = None,
):
    """A structurally valid capability for predicate tests.

    The signature is not a real one; these tests exercise structural
    monotonicity, which runs before and independently of signature
    verification. Anything that authorizes goes through the SDK instead,
    where the signature is genuine.
    """
    now = time.time()
    return Capability(
        agent_id=agent_id,
        capability=capability,
        constraints=constraints or {},
        issuer="trusted-issuer",
        tool="test-tool",
        issued_at=issued_at if issued_at is not None else now,
        expires_at=expires_at if expires_at is not None else now + 3600,
        public_key=_PUBLIC_KEY_HEX,
        signature="structural-test-signature",
    )


def make_sdk(**kwargs) -> FirewallSDK:
    sdk = FirewallSDK(**kwargs)
    sdk.generate_key("test-key")
    return sdk


class RaisingIdentityRegistry:
    """An identity registry that is wired up and cannot answer."""

    def get(self, agent_id):
        raise RuntimeError("identity backend unreachable")


class RaisingPostureEngine:
    def state(self, agent_id):
        raise RuntimeError("posture backend unreachable")


# --------------------------------------------------------------------------
# Monotonicity predicates
# --------------------------------------------------------------------------


def test_equal_authority_is_monotonic():
    """child == parent satisfies child <= parent."""
    parent = make_capability("agent-p", constraints={"paths": ["/data"]})
    child = make_capability("agent-c", constraints={"paths": ["/data"]})

    assert is_narrower_than(parent, child).monotonic


def test_narrower_authority_is_monotonic():
    parent = make_capability("agent-p", constraints={"paths": ["/data", "/logs"]})
    child = make_capability("agent-c", constraints={"paths": ["/data"]})

    assert is_narrower_than(parent, child).monotonic


def test_wider_authority_is_not_monotonic():
    parent = make_capability("agent-p", constraints={"paths": ["/data"]})
    child = make_capability("agent-c", constraints={"paths": ["/data", "/etc"]})

    result = is_narrower_than(parent, child)
    assert not result.monotonic
    assert "constraints" in result.reason


def test_wider_numeric_bound_is_not_monotonic():
    parent = make_capability("agent-p", constraints={"size_max": 10})
    child = make_capability("agent-c", constraints={"size_max": 1000})

    assert not is_narrower_than(parent, child).monotonic


def test_dropping_a_parent_constraint_is_not_monotonic():
    """Removing a constraint removes a limit, which widens authority."""
    parent = make_capability(
        "agent-p", constraints={"paths": ["/data"], "size_max": 10}
    )
    child = make_capability("agent-c", constraints={"paths": ["/data"]})

    assert not is_narrower_than(parent, child).monotonic


def test_changed_capability_name_is_not_monotonic():
    parent = make_capability("agent-p", capability="read")
    child = make_capability("agent-c", capability="write")

    result = is_narrower_than(parent, child)
    assert not result.monotonic
    assert "capability name changed" in result.reason


def test_changed_signing_key_is_not_monotonic():
    """A different signing key is a different authority, not a narrower one."""
    parent = make_capability("agent-p", constraints={"paths": ["/data"]})
    other_key = Ed25519PrivateKey.generate()
    child = Capability(
        agent_id="agent-c",
        capability="read",
        constraints={"paths": ["/data"]},
        issuer=parent.issuer,
        tool=parent.tool,
        issued_at=parent.issued_at,
        expires_at=parent.expires_at,
        public_key=other_key.public_key().public_bytes_raw().hex(),
        signature="structural-test-signature",
    )

    result = is_narrower_than(parent, child)
    assert not result.monotonic
    assert "signing key" in result.reason


def test_longer_expiry_is_not_monotonic():
    now = time.time()
    parent = make_capability("agent-p", expires_at=now + 60)
    child = make_capability("agent-c", expires_at=now + 3600)

    result = is_narrower_than(parent, child)
    assert not result.monotonic
    assert "expires after" in result.reason


def test_malformed_comparison_is_denied():
    """Unsupported or mismatched types fail closed rather than pass."""

    class NotACapability:
        permissions = {"read": ["/"]}

    parent = make_capability("agent-p")

    assert not is_narrower_than(parent, NotACapability()).monotonic
    assert not is_narrower_than(None, None).monotonic
    assert not is_narrower_than(parent, "not-a-capability").monotonic


def test_capability2_narrowing():
    parent = Capability2(
        capability="read",
        constraints={"scope": "/data", "lineage": {"max_depth": 2}},
    )
    child = Capability2(
        capability="read",
        constraints={"scope": "/data/public", "lineage": {"max_depth": 1}},
    )

    assert is_narrower_than(parent, child).monotonic


def test_capability2_widening_fails():
    parent = Capability2(capability="read", constraints={"scope": "/data/public"})
    child = Capability2(capability="read", constraints={"scope": "/data"})

    assert not is_narrower_than(parent, child).monotonic


def test_authority_monotonicity_check_success():
    sdk = make_sdk()
    root = sdk.issue(
        agent="root", capability="read", constraints={"paths": ["/data", "/logs"]}
    )
    delegation = sdk.delegate(
        root,
        sdk.keys.active().private_key,
        delegatee="agent-a",
        constraints={"paths": ["/data"]},
    )

    result = authority_monotonicity_check(
        original_capability=root,
        derived_capability=delegation.child,
        delegation_lineage=sdk.delegation_lineage,
        revocation_registry=sdk.revocation,
    )
    assert result.monotonic


def test_authority_monotonicity_check_revoked_parent_fails():
    sdk = make_sdk()
    root = sdk.issue(agent="root", capability="read")
    delegation = sdk.delegate(
        root, sdk.keys.active().private_key, delegatee="agent-a"
    )

    sdk.revoke(root)

    result = authority_monotonicity_check(
        original_capability=root,
        derived_capability=delegation.child,
        delegation_lineage=sdk.delegation_lineage,
        revocation_registry=sdk.revocation,
    )
    assert not result.monotonic
    assert "revoked" in result.reason


def test_nested_delegation_stays_monotonic():
    """authority(C) <= authority(B) <= authority(A)."""
    sdk = make_sdk()
    key = sdk.keys.active().private_key

    root = sdk.issue(
        agent="root",
        capability="read",
        constraints={"paths": ["/data", "/logs", "/tmp"]},
    )
    first = sdk.delegate(
        root, key, delegatee="agent-b", constraints={"paths": ["/data", "/logs"]}
    ).child
    second = sdk.delegate(
        first, key, delegatee="agent-c", constraints={"paths": ["/data"]}
    ).child

    assert is_narrower_than(root, first).monotonic
    assert is_narrower_than(first, second).monotonic
    assert is_narrower_than(root, second).monotonic


def test_delegation_cannot_widen_at_any_depth():
    sdk = make_sdk()
    key = sdk.keys.active().private_key

    root = sdk.issue(
        agent="root", capability="read", constraints={"paths": ["/data", "/logs"]}
    )
    first = sdk.delegate(
        root, key, delegatee="agent-b", constraints={"paths": ["/data"]}
    ).child

    with pytest.raises(ValueError):
        sdk.delegate(
            first,
            key,
            delegatee="agent-c",
            constraints={"paths": ["/data", "/logs"]},
        )


# --------------------------------------------------------------------------
# §1 case 1: valid authorization
# --------------------------------------------------------------------------


def test_valid_authorization_is_allowed_and_snapshotted():
    sdk = make_sdk()
    engine = ContinuousAuthorizationEngine(sdk)
    cap = sdk.issue(agent="agent-a", capability="read")
    request = {"path": "secret.txt"}

    result = engine.authorize_with_context(cap, "read", request)

    assert result.allowed
    snapshot = engine.snapshot_for(cap, "read", request)
    assert snapshot is not None
    assert snapshot.capability_fingerprint == capability_fingerprint(cap)
    assert not snapshot.capability_revoked
    assert not snapshot.degraded


def test_engine_verdict_comes_from_the_sdk_not_the_engine():
    """The engine reports authorize()'s answer; it does not compute one.

    Guards MODEL_NON_AUTHORITY at the subsystem seam: if the engine ever
    grew its own allow path, this would keep returning True after
    authorize() started refusing.
    """
    sdk = make_sdk()
    engine = ContinuousAuthorizationEngine(sdk)
    cap = sdk.issue(agent="agent-a", capability="read")

    calls = []
    real_authorize = sdk.authorize

    def counting_authorize(*args, **kwargs):
        calls.append(args[:2])
        return real_authorize(*args, **kwargs)

    sdk.authorize = counting_authorize
    try:
        assert engine.authorize_with_context(cap, "read", {}).allowed
    finally:
        sdk.authorize = real_authorize

    assert len(calls) == 1


# --------------------------------------------------------------------------
# §1 case 2: revalidation with no material change
# --------------------------------------------------------------------------


def test_revalidation_without_state_change_is_stable():
    sdk = make_sdk()
    engine = ContinuousAuthorizationEngine(sdk)
    cap = sdk.issue(agent="agent-a", capability="read")
    request = {"path": "secret.txt"}

    assert engine.authorize_with_context(cap, "read", request).allowed

    result = engine.revalidate(cap, "read", request)

    assert result.revalidated_allowed
    assert not result.state_changed
    assert result.reason == "no_material_state_change"
    assert not result.authority_revoked


# --------------------------------------------------------------------------
# §1 case 3: revoked capability
# --------------------------------------------------------------------------


def test_revoked_capability_loses_authority_on_revalidation():
    sdk = make_sdk()
    engine = ContinuousAuthorizationEngine(sdk)
    cap = sdk.issue(agent="agent-a", capability="read")
    request = {"path": "secret.txt"}

    assert engine.authorize_with_context(cap, "read", request).allowed

    sdk.revoke(cap)
    result = engine.revalidate(
        cap, "read", request, trigger=RevalidationTrigger.CAPABILITY_REVOKED
    )

    assert result.state_changed
    assert not result.revalidated_allowed
    assert result.authority_revoked
    assert "capability_revoked" in result.reason


def test_revocation_of_parent_revokes_delegated_authority():
    """§1 case 8: changed delegation."""
    sdk = make_sdk()
    engine = ContinuousAuthorizationEngine(sdk)

    root = sdk.issue(
        agent="root", capability="read", constraints={"paths": ["/data"]}
    )
    child = sdk.delegate(
        root,
        sdk.keys.active().private_key,
        delegatee="agent-a",
        constraints={"paths": ["/data"]},
    ).child
    # A list constraint means "the request value must be a member", so the
    # request carries the scalar the delegated capability permits.
    request = {"paths": "/data"}

    assert engine.authorize_with_context(child, "read", request).allowed

    sdk.revoke(root)
    result = engine.revalidate(
        child, "read", request, trigger=RevalidationTrigger.DELEGATION_REVOKED
    )

    assert not result.revalidated_allowed
    assert result.authority_revoked


# --------------------------------------------------------------------------
# §1 case 4: expired capability
# --------------------------------------------------------------------------


def test_expired_capability_loses_authority_on_revalidation():
    """Time alone withdraws authority -- no state mutation involved."""
    # Ahead of the real clock that stamps issued_at, so the capability
    # starts inside its validity window rather than not-yet-valid.
    now = [time.time() + 5]
    sdk = make_sdk(clock=lambda: now[0])
    engine = ContinuousAuthorizationEngine(sdk, clock=lambda: now[0])

    cap = sdk.issue(
        agent="agent-a", capability="read", expires_at=now[0] + 60
    )
    request = {"path": "secret.txt"}

    assert engine.authorize_with_context(cap, "read", request).allowed

    now[0] += 120
    result = engine.revalidate(cap, "read", request, trigger=RevalidationTrigger.TIME)

    assert result.state_changed
    assert not result.revalidated_allowed
    assert result.authority_revoked
    assert "capability_expired" in result.reason


# --------------------------------------------------------------------------
# §1 case 5: changed policy
# --------------------------------------------------------------------------


def test_changed_policy_version_is_detected():
    sdk = make_sdk()
    version = ["policy-v1"]
    engine = ContinuousAuthorizationEngine(
        sdk, policy_version_provider=lambda: version[0]
    )
    cap = sdk.issue(agent="agent-a", capability="read")
    request = {"path": "secret.txt"}

    assert engine.authorize_with_context(cap, "read", request).allowed

    version[0] = "policy-v2"
    result = engine.revalidate(
        cap, "read", request, trigger=RevalidationTrigger.POLICY_CHANGED
    )

    assert result.state_changed
    assert "policy_version" in result.reason


def test_sdk_default_policy_version_tracks_trusted_issuers():
    """The default provider must actually move when policy moves.

    A provider that returned a constant would make POLICY_CHANGED
    undetectable while looking wired up.
    """
    sdk = make_sdk()
    before = sdk._authorization_policy_version()

    sdk.trust_issuer("another-issuer")

    assert sdk._authorization_policy_version() != before
    assert before.startswith("sdk-policy:")


# --------------------------------------------------------------------------
# §1 case 6: changed posture
# --------------------------------------------------------------------------


def test_changed_posture_is_detected():
    sdk = make_sdk()
    posture = PostureEngine()
    engine = ContinuousAuthorizationEngine(sdk, posture_engine=posture)
    cap = sdk.issue(agent="agent-a", capability="read")
    request = {"path": "secret.txt"}

    assert engine.authorize_with_context(cap, "read", request).allowed
    assert engine.snapshot_for(cap, "read", request).posture == "unknown"

    posture.ingest(
        "agent-a",
        PostureSignal(
            name="credential-theft",
            severity=5,
            description="observed exfiltration of a signing key",
            agent="agent-a",
        ),
    )

    result = engine.revalidate(
        cap, "read", request, trigger=RevalidationTrigger.POSTURE_CHANGED
    )

    assert result.state_changed
    assert "posture" in result.reason
    assert result.snapshot_after.posture == "compromised"


def test_posture_change_alone_does_not_grant_authority():
    """Posture is advisory. A healthy posture cannot revive a revoked
    capability, because the verdict still comes from authorize()."""
    sdk = make_sdk()
    posture = PostureEngine()
    engine = ContinuousAuthorizationEngine(sdk, posture_engine=posture)
    cap = sdk.issue(agent="agent-a", capability="read")
    request = {"path": "secret.txt"}

    engine.authorize_with_context(cap, "read", request)
    sdk.revoke(cap)

    posture.ingest(
        "agent-a",
        PostureSignal(
            name="all-clear", severity=1, description="looks fine", agent="agent-a"
        ),
    )

    result = engine.revalidate(cap, "read", request)
    assert not result.revalidated_allowed


# --------------------------------------------------------------------------
# §1 case 7: changed identity
# --------------------------------------------------------------------------


def test_changed_identity_is_detected():
    sdk = make_sdk()
    identities = IdentityRegistry()
    identities.create("agent-a")
    engine = ContinuousAuthorizationEngine(sdk, identity_registry=identities)
    cap = sdk.issue(agent="agent-a", capability="read")
    request = {"path": "secret.txt"}

    assert engine.authorize_with_context(cap, "read", request).allowed
    assert engine.snapshot_for(cap, "read", request).identity_status == "active"

    identities.revoke("agent-a")
    result = engine.revalidate(
        cap, "read", request, trigger=RevalidationTrigger.IDENTITY_CHANGED
    )

    assert result.state_changed
    assert "identity_status" in result.reason
    assert result.snapshot_after.identity_status == "revoked"


def test_identity_rotation_is_detected():
    sdk = make_sdk()
    identities = IdentityRegistry()
    identities.create("agent-a")
    engine = ContinuousAuthorizationEngine(sdk, identity_registry=identities)
    cap = sdk.issue(agent="agent-a", capability="read")
    request = {"path": "secret.txt"}

    engine.authorize_with_context(cap, "read", request)
    before = engine.snapshot_for(cap, "read", request).identity_version

    identities.rotate("agent-a")
    result = engine.revalidate(cap, "read", request)

    assert result.state_changed
    assert result.snapshot_after.identity_version > before


# --------------------------------------------------------------------------
# §1 case 9: missing context
# --------------------------------------------------------------------------


def test_unwired_subsystems_record_unknown_not_healthy():
    """Missing context is UNKNOWN, never a healthy placeholder."""
    sdk = make_sdk()
    engine = ContinuousAuthorizationEngine(sdk)
    cap = sdk.issue(agent="agent-a", capability="read")

    engine.authorize_with_context(cap, "read", {})
    snapshot = engine.snapshot_for(cap, "read", {})

    assert snapshot.identity_status == UNKNOWN
    assert snapshot.identity_version == -1
    assert snapshot.posture == UNKNOWN
    assert snapshot.provenance_state == UNKNOWN
    assert snapshot.policy_version == UNKNOWN
    assert snapshot.trust_findings == -1
    # Not configured is not the same as broken: an unwired subsystem was
    # never part of the decision, so it is not a degradation.
    assert snapshot.degraded_dependencies == ()


def test_revalidating_an_unknown_decision_is_not_reported_as_unchanged():
    """A cache miss must not launder into "nothing changed"."""
    sdk = make_sdk()
    engine = ContinuousAuthorizationEngine(sdk)
    cap = sdk.issue(agent="agent-a", capability="read")

    result = engine.revalidate(cap, "read", {"path": "x"})

    assert result.original_allowed is False
    assert result.state_changed
    assert result.reason == "no_previous_decision"


# --------------------------------------------------------------------------
# §1 case 10: failed security dependency
# --------------------------------------------------------------------------


def test_failed_identity_dependency_withholds_authority():
    """A configured dependency that raises must not read as all-clear."""
    sdk = make_sdk()
    engine = ContinuousAuthorizationEngine(
        sdk, identity_registry=RaisingIdentityRegistry()
    )
    cap = sdk.issue(agent="agent-a", capability="read")
    request = {"path": "secret.txt"}

    engine.authorize_with_context(cap, "read", request)
    snapshot = engine.snapshot_for(cap, "read", request)
    assert snapshot.identity_status == PROBE_FAILED
    assert snapshot.degraded
    assert "identity" in snapshot.degraded_dependencies

    result = engine.revalidate(cap, "read", request)

    # authorize() still says yes -- it never consulted identity -- but the
    # engine will not report a live authority it cannot verify.
    assert sdk.authorize(cap, "read", request).allowed
    assert not result.revalidated_allowed
    assert "security_dependency_unavailable" in result.reason


def test_failed_posture_dependency_withholds_authority():
    sdk = make_sdk()
    engine = ContinuousAuthorizationEngine(
        sdk, posture_engine=RaisingPostureEngine()
    )
    cap = sdk.issue(agent="agent-a", capability="read")

    engine.authorize_with_context(cap, "read", {})
    result = engine.revalidate(cap, "read", {})

    assert not result.revalidated_allowed
    assert "posture" in result.details["degraded_dependencies"]


def test_failed_policy_provider_withholds_authority():
    sdk = make_sdk()

    def broken_policy():
        raise RuntimeError("policy store unreachable")

    engine = ContinuousAuthorizationEngine(
        sdk, policy_version_provider=broken_policy
    )
    cap = sdk.issue(agent="agent-a", capability="read")

    engine.authorize_with_context(cap, "read", {})
    result = engine.revalidate(cap, "read", {})

    assert not result.revalidated_allowed
    assert "policy" in result.details["degraded_dependencies"]


def test_degradation_cannot_turn_a_denial_into_an_allow():
    """The degraded gate only ever restricts. It is not a second verdict."""
    sdk = make_sdk()
    engine = ContinuousAuthorizationEngine(
        sdk, identity_registry=RaisingIdentityRegistry()
    )
    cap = sdk.issue(agent="agent-a", capability="read")

    engine.authorize_with_context(cap, "read", {})
    sdk.revoke(cap)

    result = engine.revalidate(cap, "read", {})
    assert not result.revalidated_allowed


# --------------------------------------------------------------------------
# §1 case 11: repeated monitoring
# --------------------------------------------------------------------------


def test_repeated_monitoring_reports_a_revocation_that_already_happened():
    """Cumulative counters, not last-result snapshots.

    The engine rebases its baseline once drift is seen, so an allow ->
    deny transition appears in exactly one revalidation. Counters derived
    from the latest result reported "nothing was revoked" one sweep
    later, which is the exact failure this subsystem exists to prevent.
    """
    sdk = make_sdk()
    engine = ContinuousAuthorizationEngine(sdk)
    monitor = ContinuousAuthorizationMonitor(
        engine,
        sdk,
        config=MonitoringConfig(
            enable_periodic_revalidation=False, min_revalidation_interval=0.0
        ),
    )
    cap = sdk.issue(agent="agent-a", capability="read")
    request = {"path": "secret.txt"}

    engine.authorize_with_context(cap, "read", request)
    monitor.monitor_decision(
        capability_fingerprint=capability_fingerprint(cap),
        action="read",
        request=request,
        request_hash=engine.request_hash(request),
        cache_key=engine.cache_key(cap, "read", request),
    )

    assert monitor.sweep()[0].result.revalidated_allowed

    sdk.revoke(cap)

    for _ in range(4):
        monitor.sweep()

    stats = monitor.get_revalidation_stats()
    assert stats["total_revalidations"] >= 5
    assert stats["decisions_changed_allow_to_deny"] == 1
    assert stats["currently_denied"] == 1
    assert stats["revalidation_failures"] == 0


def test_monitor_reports_an_unresolvable_capability_as_a_failure():
    """Not being able to re-ask is a failure, not a quiet pass."""
    sdk = make_sdk()
    engine = ContinuousAuthorizationEngine(sdk)
    monitor = ContinuousAuthorizationMonitor(
        engine, sdk, config=MonitoringConfig(enable_periodic_revalidation=False)
    )

    monitor.monitor_decision(
        capability_fingerprint="0" * 64,
        action="read",
        request={},
        request_hash="deadbeef",
        cache_key="0" * 64 + ":read:deadbeef",
    )

    attempt = monitor.sweep()[0]

    assert attempt.outcome is RevalidationOutcome.CAPABILITY_UNAVAILABLE
    assert attempt.failed
    assert monitor.get_revalidation_stats()["revalidation_failures"] == 1


def test_monitor_does_not_register_denied_decisions():
    sdk = make_sdk()
    config = MonitoringConfig(enable_periodic_revalidation=False)
    sdk_with_monitor = make_sdk(continuous_auth_config=config)

    cap = sdk_with_monitor.issue(agent="agent-a", capability="read")
    sdk_with_monitor.revoke(cap)

    result = sdk_with_monitor.authorize_continuous(cap, "read", {})

    assert not result.allowed
    assert sdk_with_monitor.continuous_auth_monitor.get_monitored_decisions() == {}
    sdk_with_monitor.close()


# --------------------------------------------------------------------------
# §1 case 12: monitor shutdown
# --------------------------------------------------------------------------


def test_periodic_monitoring_starts_and_stops_cleanly():
    sdk = make_sdk()
    engine = ContinuousAuthorizationEngine(sdk)
    monitor = ContinuousAuthorizationMonitor(
        engine,
        sdk,
        config=MonitoringConfig(
            periodic_interval=0.05,
            enable_periodic_revalidation=True,
            min_revalidation_interval=0.0,
        ),
    )
    cap = sdk.issue(agent="agent-a", capability="read")
    request = {"path": "secret.txt"}

    engine.authorize_with_context(cap, "read", request)
    monitor.monitor_decision(
        capability_fingerprint=capability_fingerprint(cap),
        action="read",
        request=request,
        request_hash=engine.request_hash(request),
        cache_key=engine.cache_key(cap, "read", request),
    )

    monitor.start_periodic_monitoring()
    assert monitor.is_running
    # Idempotent: a second start must not leave a second thread behind.
    monitor.start_periodic_monitoring()

    try:
        deadline = time.time() + 3.0
        while time.time() < deadline:
            if monitor.get_revalidation_stats()["total_revalidations"] > 0:
                break
            time.sleep(0.02)
        assert monitor.get_revalidation_stats()["total_revalidations"] > 0
    finally:
        assert monitor.stop_periodic_monitoring(timeout=5.0)

    assert not monitor.is_running
    stats_after = monitor.get_revalidation_stats()["total_revalidations"]
    time.sleep(0.2)
    assert monitor.get_revalidation_stats()["total_revalidations"] == stats_after


def test_stop_is_safe_when_never_started():
    sdk = make_sdk()
    engine = ContinuousAuthorizationEngine(sdk)
    monitor = ContinuousAuthorizationMonitor(engine, sdk)

    assert monitor.stop_periodic_monitoring()
    assert not monitor.is_running


def test_sdk_close_stops_the_sweep():
    sdk = make_sdk(
        continuous_auth_config=MonitoringConfig(
            periodic_interval=0.05, enable_periodic_revalidation=True
        )
    )
    assert sdk.continuous_auth_monitor.is_running

    sdk.close()

    assert not sdk.continuous_auth_monitor.is_running


# --------------------------------------------------------------------------
# §1 case 13: fail-closed behaviour
# --------------------------------------------------------------------------


def test_unreadable_revocation_state_is_treated_as_revoked():
    sdk = make_sdk()
    engine = ContinuousAuthorizationEngine(sdk)
    cap = sdk.issue(agent="agent-a", capability="read")

    def broken(_capability):
        raise RuntimeError("revocation store unreachable")

    sdk.is_effectively_revoked = broken

    assert engine._capture_snapshot(cap, "read", {}).capability_revoked


def test_unreadable_incident_state_is_treated_as_an_active_incident():
    sdk = make_sdk()

    def broken(_agent_id):
        raise RuntimeError("incident store unreachable")

    engine = ContinuousAuthorizationEngine(sdk, incident_provider=broken)
    cap = sdk.issue(agent="agent-a", capability="read")

    assert engine._capture_snapshot(cap, "read", {}).incident_active


def test_broken_lineage_is_not_reported_as_a_valid_chain():
    sdk = make_sdk()
    engine = ContinuousAuthorizationEngine(sdk)
    cap = sdk.issue(agent="agent-a", capability="read")

    class BrokenLineage:
        def chain(self, _fingerprint):
            raise RuntimeError("lineage corrupt")

    sdk.delegation_lineage = BrokenLineage()

    snapshot = engine._capture_snapshot(cap, "read", {})
    assert not snapshot.delegation_chain_valid
    assert "delegation_lineage" in snapshot.degraded_dependencies


def test_state_hash_ignores_timestamp_only():
    """Every material field must be hashed, and the clock must not be.

    Hashing the timestamp made state_changed unconditionally true and the
    "no material change" path unreachable; excluding a real field would
    make drift in it invisible. Both directions are failures.
    """
    sdk = make_sdk()
    engine = ContinuousAuthorizationEngine(sdk)
    cap = sdk.issue(agent="agent-a", capability="read")

    first = engine._capture_snapshot(cap, "read", {})
    time.sleep(0.01)
    second = engine._capture_snapshot(cap, "read", {})

    assert first.timestamp != second.timestamp
    assert first.state_hash() == second.state_hash()

    from dataclasses import replace

    for field_name in (
        "identity_status",
        "posture",
        "policy_version",
        "provenance_state",
        "environment",
        "risk_level",
    ):
        mutated = replace(first, **{field_name: "moved"})
        assert mutated.state_hash() != first.state_hash(), field_name

    assert (
        replace(first, degraded_dependencies=("identity",)).state_hash()
        != first.state_hash()
    )


def test_revalidate_raises_when_continuous_auth_is_not_configured():
    """Returning None would be indistinguishable from "nothing changed"."""
    sdk = make_sdk()

    with pytest.raises(RuntimeError, match="continuous authorization"):
        sdk.revalidate(sdk.issue(agent="agent-a", capability="read"), "read", {})
