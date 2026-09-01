"""v1.6 developer console (UI) contract.

The console in :mod:`firewall.ui` is a **read-only projection layer**. It
adds no authorization logic, and these tests exist to keep it that way.
Four properties are locked here:

1. **No key material escapes.** ``Capability`` carries ``signature`` and
   ``public_key``. No console payload may contain either *value*, for
   any scenario. (The field *names* do appear, in the ``redacted`` list --
   that is the console disclosing what it withholds, so every assertion
   below checks values, never substrings of the disclosure.)

2. **The pipeline cannot drift.** What the console draws is derived from
   the SDK's real gate tuple, ``_authorization_gate_phases()``. If a gate
   is added, removed, or reordered, the projection follows -- and the
   documented North Star order is pinned so a silent reorder is caught.

3. **Decisions are rendered, never recomputed.** For every demo
   scenario, the console's reported outcome equals what the SDK returns
   for the same request evaluated directly. The console has no second
   authorization system, and an unattributable reason is reported as
   unattributed rather than blamed on a guessed gate.

4. **Reads do not mutate.** Attached to a live SDK the console refuses to
   evaluate anything, because authorizing has real security side effects
   (lifecycle records, risk escalation, refusal memoization, budget and
   replay consumption).

Plus the one security property the server itself implements: static
asset serving must not escape its own directory.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from typing import Any, Optional

import pytest

from firewall.capability import Capability
from firewall.sdk import FirewallSDK
from firewall.ui import introspect
from firewall.ui.demo import SCENARIOS, SCENARIOS_BY_ID
from firewall.ui.server import STATIC_ROOT, build_server
from firewall.ui.service import Console, ConsoleError


ACTION = "payments.send"
REQUEST = {"amount": 10}


# ======================================================================
# Helpers
# ======================================================================


def _sdk() -> FirewallSDK:
    sdk = FirewallSDK()
    sdk.generate_key("ui-test-key")
    return sdk


def _issue(sdk: FirewallSDK, agent: str = "agent-ui") -> Capability:
    return sdk.issue(
        agent=agent,
        capability=ACTION,
        issuer="trusted-issuer",
        constraints={"amount_max": 1000},
    )


def _secret_values(
    capabilities,
) -> list[str]:
    """Collect every real signature and public key as raw strings."""

    secrets: list[str] = []

    for capability in capabilities:
        for field in introspect.REDACTED_CAPABILITY_FIELDS:
            value = getattr(capability, field, None)
            if isinstance(value, str) and value:
                secrets.append(value)
            elif isinstance(value, (bytes, bytearray)) and value:
                secrets.append(value.hex())

    return secrets


def _capabilities_of(prepared) -> list[Capability]:
    found: list[Capability] = []

    if isinstance(prepared.capability, Capability):
        found.append(prepared.capability)

    found.extend(
        item
        for item in prepared.inventory
        if isinstance(item, Capability)
    )

    for capability, _action, _request in prepared.warmup:
        if isinstance(capability, Capability):
            found.append(capability)

    return found


# ======================================================================
# Redaction
# ======================================================================


def test_capability_view_omits_cryptographic_fields():
    sdk = _sdk()

    try:
        capability = _issue(sdk)
        view = introspect.capability_view(
            sdk,
            capability,
        )

        for field in introspect.REDACTED_CAPABILITY_FIELDS:
            assert field not in view

        assert view["redacted"] == list(
            introspect.REDACTED_CAPABILITY_FIELDS
        )
    finally:
        sdk.close()


def test_capability_view_contains_no_key_material():
    sdk = _sdk()

    try:
        capability = _issue(sdk)
        secrets = _secret_values([capability])

        # A signed capability must actually have material to leak,
        # otherwise this test would pass vacuously.
        assert secrets

        serialized = json.dumps(
            introspect.capability_view(
                sdk,
                capability,
            ),
            default=str,
        )

        for secret in secrets:
            assert secret not in serialized
    finally:
        sdk.close()


def test_decision_view_carries_no_key_material():
    sdk = _sdk()

    try:
        capability = _issue(sdk)
        secrets = _secret_values([capability])
        assert secrets

        decision = sdk.authorize_north_star(
            capability,
            ACTION,
            REQUEST,
        )

        serialized = json.dumps(
            introspect.decision_view(decision),
            default=str,
        )

        for secret in secrets:
            assert secret not in serialized
    finally:
        sdk.close()


@pytest.mark.parametrize(
    "scenario",
    SCENARIOS,
    ids=[item.id for item in SCENARIOS],
)
def test_no_scenario_payload_leaks_key_material(scenario):
    """Every scenario payload is checked against its own real secrets."""

    console = Console()
    prepared = scenario.builder()

    secrets = _secret_values(
        _capabilities_of(prepared)
    )

    # Guard against a vacuous pass: whenever a capability is presented,
    # there is real material that could leak.
    if isinstance(prepared.capability, Capability):
        assert secrets

    result = console._evaluate_prepared(
        scenario_id=scenario.id,
        scenario_title=scenario.title,
        expects=scenario.expects,
        prepared=prepared,
    )

    serialized = json.dumps(
        result,
        default=str,
    )

    for secret in secrets:
        assert secret not in serialized

    # The console is still honest about what it withheld.
    for entry in result["inventory"]:
        assert entry["redacted"] == list(
            introspect.REDACTED_CAPABILITY_FIELDS
        )


def test_fingerprints_are_truncated_for_display():
    sdk = _sdk()

    try:
        capability = _issue(sdk)
        view = introspect.capability_view(
            sdk,
            capability,
        )

        full = sdk.fingerprint(capability)

        assert view["fingerprint"] == full
        assert view["fingerprint_short"] == full[
            : introspect.FINGERPRINT_PREFIX
        ]
    finally:
        sdk.close()


def test_short_fingerprint_handles_missing_value():
    assert (
        introspect.short_fingerprint(None) is None
    )
    assert (
        introspect.short_fingerprint(123) is None
    )
    assert (
        introspect.short_fingerprint("abc") == "abc"
    )


# ======================================================================
# Pipeline projection: no drift
# ======================================================================

#: The North Star flow the console is specified to display.
DOCUMENTED_FLOW = (
    "Request",
    "Refusal",
    "Risk",
    "Issuer",
    "Revocation",
    "Time",
    "Delegation",
    "Delegation Monotonicity",
    "Depth Policy",
    "Cryptographic Authority",
    "Security Transaction",
    "Decision",
)


def test_pipeline_is_derived_from_the_real_gate_tuple():
    sdk = _sdk()

    try:
        nodes = introspect.pipeline_phases(sdk)

        gate_ids = [
            node["id"]
            for node in nodes
            if node["kind"] == "gate"
        ]

        real = [
            gate.__name__
            for gate in sdk._authorization_gate_phases()
        ]

        assert gate_ids == real
    finally:
        sdk.close()


def test_pipeline_frames_gates_with_terminals():
    sdk = _sdk()

    try:
        nodes = introspect.pipeline_phases(sdk)

        assert nodes[0]["id"] == "request"
        assert nodes[0]["kind"] == "terminal"
        assert nodes[-1]["id"] == "decision"
        assert nodes[-1]["kind"] == "terminal"

        assert [
            node["index"] for node in nodes
        ] == list(range(len(nodes)))
    finally:
        sdk.close()


def test_pipeline_renders_the_documented_north_star_order():
    sdk = _sdk()

    try:
        labels = tuple(
            node["label"]
            for node in introspect.pipeline_phases(
                sdk
            )
        )

        assert labels == DOCUMENTED_FLOW
    finally:
        sdk.close()


def test_every_real_gate_has_a_curated_label():
    """A new gate should be labelled deliberately, not auto-derived."""

    sdk = _sdk()

    try:
        for gate in sdk._authorization_gate_phases():
            assert (
                gate.__name__
                in introspect.GATE_LABELS
            )
    finally:
        sdk.close()


def test_unlabelled_gate_still_renders():
    """Graceful degradation: an unknown gate is shown, not hidden."""

    assert (
        introspect._derive_label(
            "_gate_future_control"
        )
        == "Future Control"
    )


# ======================================================================
# Reason attribution
# ======================================================================


@pytest.mark.parametrize(
    "reason,expected",
    [
        ("invalid_capability", "request"),
        ("refusal_state", "_gate_refusal"),
        ("risk_state_revoked", "_gate_risk"),
        ("untrusted_issuer", "_gate_issuer"),
        (
            "capability_revoked",
            "_gate_revocation",
        ),
        ("expired", "_gate_time"),
        ("not_yet_valid", "_gate_time"),
        (
            "delegation_depth_exceeded",
            "_gate_delegation_depth",
        ),
        (
            "delegation_widening: constraints widened",
            "_gate_delegation_monotonicity",
        ),
        (
            "constraint_denied",
            "_gate_cryptographic_authority",
        ),
        (
            "tool_binding_denied",
            "_gate_cryptographic_authority",
        ),
        (
            "invalid_signature",
            "_gate_cryptographic_authority",
        ),
        ("replay", "_gate_cryptographic_authority"),
        (
            "semantic_chain_denied",
            "_gate_transaction",
        ),
        (
            "delegation_chain_error: ancestor missing",
            "_gate_delegation_chain",
        ),
        (
            "security_context_error: boom",
            "_gate_transaction",
        ),
        (
            "semantic_context_error: boom",
            "_gate_transaction",
        ),
        (
            "action budget exceeded",
            "_gate_transaction",
        ),
        (
            "some other budget exceeded",
            "_gate_transaction",
        ),
    ],
)
def test_attribute_reason_maps_known_reasons(
    reason,
    expected,
):
    assert (
        introspect.attribute_reason(reason)
        == expected
    )


@pytest.mark.parametrize(
    "reason",
    [
        None,
        123,
        "",
        "a_reason_that_does_not_exist_yet",
    ],
)
def test_attribute_reason_declines_to_guess(reason):
    assert (
        introspect.attribute_reason(reason) is None
    )


def test_phase_trace_marks_every_gate_passed_on_allow():
    sdk = _sdk()

    try:
        nodes = introspect.phase_trace(
            sdk,
            allowed=True,
            reason="authorized",
        )

        assert {
            node["status"] for node in nodes
        } == {"passed"}
    finally:
        sdk.close()


def test_phase_trace_stops_at_the_attributed_gate():
    sdk = _sdk()

    try:
        nodes = introspect.phase_trace(
            sdk,
            allowed=False,
            reason="expired",
        )

        statuses = {
            node["id"]: node["status"]
            for node in nodes
        }

        assert statuses["request"] == "passed"
        assert statuses["_gate_refusal"] == "passed"
        assert statuses["_gate_time"] == "denied"
        assert (
            statuses["_gate_delegation_chain"]
            == "not_reached"
        )
        assert (
            statuses[
                "_gate_cryptographic_authority"
            ]
            == "not_reached"
        )
        assert statuses["decision"] == "denied"
    finally:
        sdk.close()


def test_unattributable_denial_blames_no_gate():
    sdk = _sdk()

    try:
        nodes = introspect.phase_trace(
            sdk,
            allowed=False,
            reason="brand_new_reason",
        )

        gate_statuses = [
            node["status"]
            for node in nodes
            if node["kind"] == "gate"
        ]

        assert set(gate_statuses) == {"unknown"}
        assert "denied" not in gate_statuses
        assert nodes[-1]["status"] == "denied"
    finally:
        sdk.close()


# ======================================================================
# Decisions are rendered, not recomputed
# ======================================================================


def test_decision_view_reports_the_sdk_result_verbatim():
    sdk = _sdk()

    try:
        capability = _issue(sdk)

        decision = sdk.authorize_north_star(
            capability,
            ACTION,
            REQUEST,
        )

        view = introspect.decision_view(decision)

        assert view["allowed"] is bool(
            decision.allowed
        )
        assert view["reason"] == decision.reason
        assert view["agent"] == decision.agent
        assert view["action"] == decision.action
        assert view["tool"] == decision.tool
    finally:
        sdk.close()


@pytest.mark.parametrize(
    "scenario",
    SCENARIOS,
    ids=[item.id for item in SCENARIOS],
)
def test_console_reports_what_the_sdk_decides(
    scenario,
):
    """The console outcome equals a direct SDK evaluation.

    Two identical workspaces are built. One is driven straight through
    ``authorize_north_star``; the other goes through the console. If the
    console were deciding anything itself, these would diverge.
    """

    direct = scenario.builder()

    try:
        for (
            capability,
            action,
            request,
        ) in direct.warmup:
            direct.sdk.authorize_north_star(
                capability,
                action,
                request,
            )

        expected = direct.sdk.authorize_north_star(
            direct.capability,
            direct.action,
            direct.request,
        )
        expected_allowed = bool(expected.allowed)
        expected_reason = expected.reason
    finally:
        direct.sdk.close()

    result = Console()._evaluate_prepared(
        scenario_id=scenario.id,
        scenario_title=scenario.title,
        expects=scenario.expects,
        prepared=scenario.builder(),
    )

    assert (
        result["decision"]["allowed"]
        is expected_allowed
    )
    assert (
        result["decision"]["reason"]
        == expected_reason
    )


@pytest.mark.parametrize(
    "scenario",
    SCENARIOS,
    ids=[item.id for item in SCENARIOS],
)
def test_demo_scenarios_produce_the_reason_they_claim(
    scenario,
):
    """Demo data is genuine: the label matches the real outcome."""

    result = Console()._evaluate_prepared(
        scenario_id=scenario.id,
        scenario_title=scenario.title,
        expects=scenario.expects,
        prepared=scenario.builder(),
    )

    assert result["expectation"]["matches"] is True

    assert result["decision"]["allowed"] is (
        scenario.group == "allow"
    )


def test_denied_scenarios_are_attributed_to_a_gate():
    """No denial in the shipped demo set is left unattributed."""

    for scenario in SCENARIOS:
        if scenario.group != "deny":
            continue

        result = Console()._evaluate_prepared(
            scenario_id=scenario.id,
            scenario_title=scenario.title,
            expects=scenario.expects,
            prepared=scenario.builder(),
        )

        assert (
            result["attributed_phase"] is not None
        ), scenario.id


# ======================================================================
# Delegation authority projection
# ======================================================================


def test_authority_view_reports_lineage_roles():
    sdk = _sdk()

    try:
        root = _issue(sdk, "agent-root")
        child = sdk.delegate(
            root,
            sdk.active_key().private_key,
            delegatee="agent-child",
        ).child
        grandchild = sdk.delegate(
            child,
            sdk.active_key().private_key,
            delegatee="agent-grandchild",
        ).child

        view = introspect.authority_view(
            sdk,
            grandchild,
        )

        assert view["resolved"] is True
        assert view["depth"] == 3
        assert (
            view["requested_agent"]
            == "agent-grandchild"
        )
        assert view["root_agent"] == "agent-root"

        assert [
            link["role"] for link in view["links"]
        ] == ["requested", "ancestor", "root"]
    finally:
        sdk.close()


def test_authority_view_reports_failure_as_an_error():
    """A lineage failure is an error, never an authorization outcome."""

    sdk = _sdk()

    try:
        capability = _issue(sdk)

        object.__setattr__(
            sdk,
            "_resolve_delegation_authority",
            lambda _cap: (_ for _ in ()).throw(
                ValueError("ancestor missing")
            ),
        )

        view = introspect.authority_view(
            sdk,
            capability,
        )

        assert view["resolved"] is False
        assert view["error_type"] == "ValueError"
        assert view["links"] == []
        assert "allowed" not in view
    finally:
        sdk.close()


# ======================================================================
# Modes and side effects
# ======================================================================


def test_demo_mode_can_evaluate():
    console = Console()

    assert console.mode == "demo"
    assert console.can_evaluate is True


def test_attached_mode_refuses_to_evaluate():
    sdk = _sdk()

    try:
        console = Console(sdk=sdk)

        assert console.mode == "attached"
        assert console.can_evaluate is False

        with pytest.raises(ConsoleError):
            console.evaluate("allow_root")

        assert (
            console.scenarios()["can_evaluate"]
            is False
        )
        assert (
            console.system()["can_evaluate"]
            is False
        )
    finally:
        sdk.close()


def test_attached_reads_do_not_mutate_the_live_sdk():
    sdk = _sdk()

    try:
        capability = _issue(sdk)
        sdk.authorize_north_star(
            capability,
            ACTION,
            REQUEST,
        )

        before = len(
            list(sdk.lifecycle_events())
        )

        console = Console(sdk=sdk)
        console.system()
        console.scenarios()
        console.posture()
        console.lifecycle()
        console.history()

        with pytest.raises(ConsoleError):
            console.evaluate("allow_root")

        assert (
            len(list(sdk.lifecycle_events()))
            == before
        )
    finally:
        sdk.close()


def test_attached_mode_reads_live_lifecycle():
    sdk = _sdk()

    try:
        capability = _issue(sdk)
        sdk.authorize_north_star(
            capability,
            ACTION,
            REQUEST,
        )

        console = Console(sdk=sdk)

        events = console.lifecycle()["events"]

        assert events
        assert (
            console.posture()["lifecycle_totals"]
        )
        assert console.posture()["mode"] == "attached"
    finally:
        sdk.close()


def test_console_rejects_a_non_sdk():
    with pytest.raises(TypeError):
        Console(sdk=object())


def test_unknown_scenario_is_a_console_error():
    with pytest.raises(ConsoleError):
        Console().evaluate("no_such_scenario")


def test_history_records_evaluations():
    console = Console()

    console.evaluate("allow_root")
    console.evaluate("revoked")

    history = console.history()["history"]

    assert [
        entry["scenario"] for entry in history
    ] == ["revoked", "allow_root"]
    assert history[0]["allowed"] is False
    assert history[1]["allowed"] is True


def test_scenario_catalog_matches_the_registry():
    catalog = Console().scenarios()["scenarios"]

    assert [
        entry["id"] for entry in catalog
    ] == [scenario.id for scenario in SCENARIOS]

    assert set(SCENARIOS_BY_ID) == {
        scenario.id for scenario in SCENARIOS
    }


def test_system_names_its_decision_source():
    console = Console()

    assert (
        console.system()["decision_source"]
        == "FirewallSDK.authorize_north_star()"
    )


# ======================================================================
# HTTP server
# ======================================================================


@pytest.fixture
def server():
    httpd = build_server(
        host="127.0.0.1",
        port=0,
        quiet=True,
    )

    host, port = httpd.server_address[:2]

    thread = threading.Thread(
        target=httpd.serve_forever,
        daemon=True,
    )
    thread.start()

    try:
        yield f"http://{host}:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def _fetch(
    url: str,
    *,
    method: str = "GET",
    body: Optional[bytes] = None,
    headers: Optional[dict[str, str]] = None,
) -> tuple[int, dict[str, str], bytes]:
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers=headers or {},
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=10,
        ) as response:
            return (
                response.status,
                dict(response.headers),
                response.read(),
            )
    except urllib.error.HTTPError as exc:
        return (
            exc.code,
            dict(exc.headers),
            exc.read(),
        )


def _post_json(
    base: str,
    payload: Any,
) -> tuple[int, dict[str, Any]]:
    status, _headers, body = _fetch(
        f"{base}/api/evaluate",
        method="POST",
        body=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json"
        },
    )

    return status, json.loads(
        body.decode("utf-8")
    )


def test_static_assets_are_present():
    """The console cannot render without these files."""

    for name in (
        "index.html",
        "console.css",
        "console.js",
    ):
        assert (STATIC_ROOT / name).is_file()


def test_server_serves_the_console_shell(server):
    for path in ("/", "/index.html"):
        status, headers, body = _fetch(
            server + path
        )

        assert status == 200
        assert headers[
            "Content-Type"
        ].startswith("text/html")
        assert b"Agent Firewall" in body


@pytest.mark.parametrize(
    "asset,content_type",
    [
        ("console.css", "text/css"),
        ("console.js", "text/javascript"),
    ],
)
def test_server_serves_assets(
    server,
    asset,
    content_type,
):
    status, headers, body = _fetch(
        f"{server}/assets/{asset}"
    )

    assert status == 200
    assert headers["Content-Type"].startswith(
        content_type
    )
    assert body


@pytest.mark.parametrize(
    "path",
    [
        "/assets/../../sdk.py",
        "/assets/../__init__.py",
        "/assets/..%2f..%2fsdk.py",
        "/assets/%2e%2e/%2e%2e/sdk.py",
        "/assets/....//....//sdk.py",
        "/assets//etc/passwd",
    ],
)
def test_server_refuses_to_escape_the_static_root(
    server,
    path,
):
    status, _headers, body = _fetch(server + path)

    assert status in (403, 404), path
    assert b"FirewallSDK" not in body
    assert b"class Console" not in body


@pytest.mark.parametrize(
    "path,keys",
    [
        (
            "/api/system",
            {
                "version",
                "mode",
                "can_evaluate",
                "pipeline",
                "decision_source",
            },
        ),
        (
            "/api/scenarios",
            {"scenarios", "can_evaluate"},
        ),
        (
            "/api/posture",
            {
                "mode",
                "posture",
                "lifecycle_totals",
            },
        ),
        ("/api/lifecycle", {"mode", "events"}),
        ("/api/history", {"history"}),
    ],
)
def test_server_api_reads_return_json(
    server,
    path,
    keys,
):
    status, headers, body = _fetch(server + path)

    assert status == 200
    assert headers["Content-Type"].startswith(
        "application/json"
    )

    payload = json.loads(body.decode("utf-8"))

    assert keys <= set(payload)


def test_server_sets_conservative_headers(server):
    _status, headers, _body = _fetch(server + "/")

    assert (
        headers["X-Content-Type-Options"]
        == "nosniff"
    )
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Cache-Control"] == "no-store"


@pytest.mark.parametrize(
    "path",
    [
        "/api/nope",
        "/nope",
        "/api/system/extra",
    ],
)
def test_server_unknown_routes_are_404(
    server,
    path,
):
    status, _headers, _body = _fetch(server + path)

    assert status == 404


def test_server_evaluates_a_scenario(server):
    status, payload = _post_json(
        server,
        {"scenario": "allow_root"},
    )

    assert status == 200
    assert payload["decision"]["allowed"] is True
    assert (
        payload["decision"]["reason"]
        == "authorized"
    )
    assert (
        len(payload["phases"])
        == len(DOCUMENTED_FLOW)
    )


def test_server_evaluate_reports_a_denial(server):
    status, payload = _post_json(
        server,
        {"scenario": "revoked_ancestor"},
    )

    assert status == 200
    assert payload["decision"]["allowed"] is False
    assert (
        payload["decision"]["reason"]
        == "capability_revoked"
    )
    assert (
        payload["attributed_phase"]
        == "_gate_revocation"
    )


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"scenario": 5},
        {"scenario": None},
        {"scenario": "no_such_scenario"},
        [],
        "nope",
    ],
)
def test_server_validates_the_evaluate_body(
    server,
    payload,
):
    status, body = _post_json(server, payload)

    assert status == 400
    assert "error" in body


def test_server_rejects_an_oversized_body(server):
    oversized = json.dumps(
        {"scenario": "x" * 20_000}
    ).encode("utf-8")

    status, _headers, _body = _fetch(
        f"{server}/api/evaluate",
        method="POST",
        body=oversized,
        headers={
            "Content-Type": "application/json"
        },
    )

    assert status == 413


def test_server_rejects_invalid_json(server):
    status, _headers, body = _fetch(
        f"{server}/api/evaluate",
        method="POST",
        body=b"{not json",
        headers={
            "Content-Type": "application/json"
        },
    )

    assert status == 400
    assert b"invalid JSON body" in body


def test_server_post_to_unknown_route_is_404(server):
    status, _headers, _body = _fetch(
        f"{server}/api/nope",
        method="POST",
        body=b"{}",
    )

    assert status == 404


def test_served_pipeline_matches_the_documented_flow(
    server,
):
    _status, _headers, body = _fetch(
        server + "/api/system"
    )

    payload = json.loads(body.decode("utf-8"))

    assert tuple(
        node["label"]
        for node in payload["pipeline"]
    ) == DOCUMENTED_FLOW
