"""Tests for the console control plane (``firewall/ui/control.py``).

The control plane is the console's only write path. These tests pin the
properties that keep it from becoming a second, weaker authorization
system:

* it does not exist unless explicitly enabled, and is unreachable without
  the startup token;
* every mutation is a call to an existing public ``FirewallSDK`` method,
  observable on the SDK afterwards;
* it cannot widen authority -- revocation stays transitive, depth policy
  stays enforced, constraints stay enforced -- because it never decides
  anything itself;
* every attempt, accepted or rejected, lands in the audit log;
* cryptographic material never reaches a control-plane payload.

No pre-existing test is modified by this file.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

import pytest

from firewall.capability import Capability
from firewall.risk_context import RiskContext
from firewall.sdk import FirewallSDK
from firewall.ui import introspect
from firewall.ui.control import (
    MAX_CONSTRAINT_KEYS,
    MAX_TTL_SECONDS,
    ControlError,
    ControlPlane,
)
from firewall.ui.server import build_server
from firewall.ui.service import Console


# ======================================================================
# Fixtures
# ======================================================================


@pytest.fixture()
def sdk() -> FirewallSDK:
    """A disposable in-memory SDK, as the demo workbench builds."""

    instance = FirewallSDK(risk_context=RiskContext())
    instance.generate_key("test-key")
    return instance


@pytest.fixture()
def plane(sdk: FirewallSDK) -> ControlPlane:
    return ControlPlane(sdk)


def connect(
    plane: ControlPlane,
    *,
    agent: str = "agent-alpha",
    capability: str = "payments.send",
    constraints: dict | None = None,
    **extra,
) -> dict:
    payload = {
        "agent": agent,
        "capability": capability,
        "constraints": (
            {"amount_max": 1000}
            if constraints is None
            else constraints
        ),
    }
    payload.update(extra)
    return plane.connect_agent(payload)


# ======================================================================
# Construction
# ======================================================================


def test_requires_a_real_sdk() -> None:
    with pytest.raises(TypeError):
        ControlPlane("not an sdk")  # type: ignore[arg-type]


def test_reuses_an_existing_signing_key(
    sdk: FirewallSDK,
) -> None:
    before = sdk.active_key().key_id

    ControlPlane(sdk)

    assert sdk.active_key().key_id == before


def test_generates_a_key_when_none_exists() -> None:
    bare = FirewallSDK()

    assert bare.active_key() is None

    ControlPlane(bare)

    assert bare.active_key() is not None


def test_console_does_not_build_a_control_plane_unless_asked() -> None:
    """The read-only console must stay read-only by construction."""

    console = Console()

    assert console._control is None
    assert console._workbench is None


def test_console_control_is_a_single_instance() -> None:
    console = Console()

    assert console.control() is console.control()
    assert console.control().sdk is console.workbench()


def test_attached_console_writes_to_the_attached_sdk(
    sdk: FirewallSDK,
) -> None:
    console = Console(sdk=sdk)

    assert console.control().sdk is sdk


# ======================================================================
# Mutations reach the real SDK
# ======================================================================


def test_connect_agent_issues_through_the_sdk(
    plane: ControlPlane,
    sdk: FirewallSDK,
) -> None:
    view = connect(plane, agent="agent-ops")

    assert view["agent_id"] == "agent-ops"
    assert view["capability"] == "payments.send"
    assert view["constraints"] == {"amount_max": 1000}

    stored = plane._lookup(view["fingerprint"])

    assert isinstance(stored, Capability)
    assert sdk.fingerprint(stored) == view["fingerprint"]
    assert not sdk.is_effectively_revoked(stored)


def test_connect_agent_binds_a_tool_when_asked(
    plane: ControlPlane,
) -> None:
    view = connect(plane, tool="stripe.charge")

    assert view["tool"] == "stripe.charge"


def test_connect_agent_trusts_a_new_issuer_and_says_so(
    plane: ControlPlane,
    sdk: FirewallSDK,
) -> None:
    connect(plane, issuer="platform-issuer")

    assert sdk.is_issuer_trusted("platform-issuer")

    implied = [
        entry
        for entry in plane.audit()
        if entry["action"] == "trust_issuer"
    ]

    assert implied
    assert implied[0]["target"] == "platform-issuer"
    assert (
        implied[0]["detail"]["implied_by"]
        == "connect_agent"
    )


def test_delegation_produces_a_deeper_capability(
    plane: ControlPlane,
    sdk: FirewallSDK,
) -> None:
    root = connect(plane)

    child = plane.delegate(
        {
            "fingerprint": root["fingerprint"],
            "delegatee": "agent-sub",
            "constraints": {"amount_max": 100},
        }
    )

    assert child["agent_id"] == "agent-sub"
    assert child["constraints"] == {"amount_max": 100}

    authority = introspect.authority_view(
        sdk,
        plane._lookup(child["fingerprint"]),
    )

    assert authority["depth"] == 2


def test_attenuation_narrows_in_place(
    plane: ControlPlane,
) -> None:
    root = connect(plane)

    narrowed = plane.attenuate(
        {
            "fingerprint": root["fingerprint"],
            "constraints": {"amount_max": 10},
        }
    )

    assert narrowed["constraints"] == {"amount_max": 10}
    assert narrowed["agent_id"] == root["agent_id"]


def test_attenuation_requires_constraints(
    plane: ControlPlane,
) -> None:
    root = connect(plane)

    with pytest.raises(ControlError):
        plane.attenuate(
            {"fingerprint": root["fingerprint"]}
        )


def test_revocation_stays_transitive(
    plane: ControlPlane,
) -> None:
    """The control plane must not be able to escape revocation."""

    root = connect(plane)

    child = plane.delegate(
        {
            "fingerprint": root["fingerprint"],
            "delegatee": "agent-sub",
        }
    )

    plane.revoke({"fingerprint": root["fingerprint"]})

    after = plane.inventory()
    by_fp = {
        view["fingerprint"]: view for view in after
    }

    assert by_fp[root["fingerprint"]]["revoked"]
    assert by_fp[child["fingerprint"]][
        "effectively_revoked"
    ]

    verdict = plane.check(
        {
            "fingerprint": child["fingerprint"],
            "action": "payments.send",
            "request": {"amount": 1},
        }
    )

    assert verdict["decision"]["allowed"] is False


def test_issuer_trust_can_be_withdrawn(
    plane: ControlPlane,
    sdk: FirewallSDK,
) -> None:
    plane.set_issuer_trust(
        {"issuer": "temp-issuer", "trusted": True}
    )

    assert sdk.is_issuer_trusted("temp-issuer")

    result = plane.set_issuer_trust(
        {"issuer": "temp-issuer", "trusted": False}
    )

    assert result["trusted"] is False
    assert not sdk.is_issuer_trusted("temp-issuer")


def test_depth_policy_reaches_the_sdk(
    plane: ControlPlane,
    sdk: FirewallSDK,
) -> None:
    rules = plane.set_depth_policy(
        {"max_delegation_depth": 2}
    )

    assert rules["max_delegation_depth"] == 2
    assert sdk.max_delegation_depth == 2

    unbounded = plane.set_depth_policy(
        {"max_delegation_depth": None}
    )

    assert unbounded["max_delegation_depth"] is None
    assert sdk.max_delegation_depth is None


def test_depth_policy_is_actually_enforced(
    plane: ControlPlane,
) -> None:
    """A rule authored in the UI must be enforced by the pipeline."""

    plane.set_depth_policy(
        {"max_delegation_depth": 1}
    )

    root = connect(plane)

    child = plane.delegate(
        {
            "fingerprint": root["fingerprint"],
            "delegatee": "agent-sub",
        }
    )

    verdict = plane.check(
        {
            "fingerprint": child["fingerprint"],
            "action": "payments.send",
            "request": {"amount": 1},
        }
    )

    assert verdict["decision"]["allowed"] is False
    assert (
        "depth"
        in verdict["decision"]["reason"].lower()
    )


# ======================================================================
# Validation -- shape only, never a substitute for the real checks
# ======================================================================


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"agent": "", "capability": "x"},
        {"agent": "   ", "capability": "x"},
        {"agent": "a"},
        {"agent": "a", "capability": ""},
        {"agent": 7, "capability": "x"},
        {"agent": "a", "capability": "x", "constraints": []},
        {"agent": "a", "capability": "x", "constraints": "amount"},
        {"agent": "a", "capability": "x", "expires_in": 0},
        {"agent": "a", "capability": "x", "expires_in": -5},
        {"agent": "a", "capability": "x", "expires_in": "soon"},
        {"agent": "a", "capability": "x", "expires_in": True},
        {
            "agent": "a",
            "capability": "x",
            "expires_in": MAX_TTL_SECONDS + 1,
        },
        {"agent": "a" * 5000, "capability": "x"},
    ],
)
def test_connect_rejects_malformed_input(
    plane: ControlPlane,
    payload: dict,
) -> None:
    with pytest.raises(ControlError):
        plane.connect_agent(payload)


def test_constraint_map_is_bounded(
    plane: ControlPlane,
) -> None:
    oversized = {
        f"rule_{index}": index
        for index in range(MAX_CONSTRAINT_KEYS + 1)
    }

    with pytest.raises(ControlError):
        connect(plane, constraints=oversized)


@pytest.mark.parametrize(
    "constraints",
    [
        {"amount_max": {"nested": 1}},
        {"amount_max": float("nan")},
        {"amount_max": float("inf")},
        {"": 1},
        {"tools": [{"nested": True}]},
    ],
)
def test_constraint_values_are_restricted(
    plane: ControlPlane,
    constraints: dict,
) -> None:
    with pytest.raises(ControlError):
        connect(plane, constraints=constraints)


@pytest.mark.parametrize(
    "constraints",
    [
        {"amount_max": 100},
        {"amount_max": 10.5},
        {"require_review": True},
        {"region": "eu"},
        {"tools": ["a", "b"]},
        {"unset": None},
    ],
)
def test_supported_constraint_shapes_pass_through_unchanged(
    plane: ControlPlane,
    constraints: dict,
) -> None:
    view = connect(plane, constraints=constraints)

    assert view["constraints"] == constraints


@pytest.mark.parametrize(
    "value",
    [0, -1, -100, 1.5, "2", True, [2]],
)
def test_depth_policy_rejects_bad_values(
    plane: ControlPlane,
    sdk: FirewallSDK,
    value: object,
) -> None:
    before = sdk.max_delegation_depth

    with pytest.raises(ControlError):
        plane.set_depth_policy(
            {"max_delegation_depth": value}
        )

    assert sdk.max_delegation_depth == before


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"issuer": ""},
        {"issuer": "x"},
        {"issuer": "x", "trusted": "yes"},
        {"issuer": "x", "trusted": 1},
    ],
)
def test_issuer_trust_rejects_bad_values(
    plane: ControlPlane,
    payload: dict,
) -> None:
    with pytest.raises(ControlError):
        plane.set_issuer_trust(payload)


@pytest.mark.parametrize(
    "fingerprint",
    ["", "   ", "not-a-fingerprint", 42, None],
)
def test_unknown_fingerprints_are_refused(
    plane: ControlPlane,
    fingerprint: object,
) -> None:
    with pytest.raises(ControlError):
        plane.revoke({"fingerprint": fingerprint})


def test_fingerprint_prefixes_resolve(
    plane: ControlPlane,
) -> None:
    view = connect(plane)

    resolved = plane._lookup(
        view["fingerprint_short"]
    )

    assert (
        plane.sdk.fingerprint(resolved)
        == view["fingerprint"]
    )


def test_check_requires_an_object_request(
    plane: ControlPlane,
) -> None:
    view = connect(plane)

    with pytest.raises(ControlError):
        plane.check(
            {
                "fingerprint": view["fingerprint"],
                "action": "payments.send",
                "request": ["amount"],
            }
        )


# ======================================================================
# The verdict is the SDK's, verbatim
# ======================================================================


def test_check_reports_what_the_sdk_decides() -> None:
    """Same inputs, two identical workspaces: identical verdicts.

    If the control plane ever formed its own opinion, this would
    diverge.
    """

    def workspace() -> FirewallSDK:
        instance = FirewallSDK(
            risk_context=RiskContext()
        )
        instance.generate_key("twin-key")
        return instance

    via_plane = ControlPlane(workspace())
    direct = workspace()

    root = connect(
        via_plane,
        constraints={"amount_max": 100},
    )

    twin = direct.issue(
        agent="agent-alpha",
        capability="payments.send",
        constraints={"amount_max": 100},
    )

    for request in (
        {"amount": 10},
        {"amount": 10_000},
    ):
        observed = via_plane.check(
            {
                "fingerprint": root["fingerprint"],
                "action": "payments.send",
                "request": request,
            }
        )

        expected = direct.authorize_north_star(
            twin,
            "payments.send",
            request,
        )

        assert (
            observed["decision"]["allowed"]
            == expected.allowed
        )
        assert (
            observed["decision"]["reason"]
            == expected.reason
        )


def test_check_projects_the_full_pipeline(
    plane: ControlPlane,
) -> None:
    view = connect(plane)

    result = plane.check(
        {
            "fingerprint": view["fingerprint"],
            "action": "payments.send",
            "request": {"amount": 1},
        }
    )

    assert result["decision"]["allowed"] is True
    assert result["request"] == {
        "action": "payments.send",
        "payload": {"amount": 1},
    }
    assert len(result["phases"]) == len(
        introspect.pipeline_phases(plane.sdk)
    )
    assert all(
        node["status"] == "passed"
        for node in result["phases"]
    )
    assert result["authority"]["depth"] == 1


def test_denied_check_is_attributed_honestly(
    plane: ControlPlane,
) -> None:
    view = connect(
        plane,
        constraints={"amount_max": 5},
    )

    result = plane.check(
        {
            "fingerprint": view["fingerprint"],
            "action": "payments.send",
            "request": {"amount": 500},
        }
    )

    assert result["decision"]["allowed"] is False
    assert result["attributed_phase"] == (
        introspect.attribute_reason(
            result["decision"]["reason"]
        )
    )


# ======================================================================
# Audit
# ======================================================================


def test_every_mutation_is_audited(
    plane: ControlPlane,
) -> None:
    root = connect(plane)

    plane.delegate(
        {
            "fingerprint": root["fingerprint"],
            "delegatee": "agent-sub",
        }
    )
    plane.set_depth_policy(
        {"max_delegation_depth": 3}
    )
    plane.set_issuer_trust(
        {"issuer": "other", "trusted": True}
    )
    plane.revoke({"fingerprint": root["fingerprint"]})

    actions = [
        entry["action"] for entry in plane.audit()
    ]

    for expected in (
        "connect_agent",
        "delegate",
        "set_depth_policy",
        "set_issuer_trust",
        "revoke",
    ):
        assert expected in actions

    assert all(
        entry["ok"] for entry in plane.audit()
    )


def test_rejections_are_audited_too(
    plane: ControlPlane,
) -> None:
    with pytest.raises(ControlError):
        plane.connect_agent({"agent": ""})

    entries = plane.audit()

    assert len(entries) == 1
    assert entries[0]["action"] == "connect_agent"
    assert entries[0]["ok"] is False
    assert entries[0]["error"]


def test_audit_is_newest_first_and_sequenced(
    plane: ControlPlane,
) -> None:
    connect(plane, agent="one")
    connect(plane, agent="two")

    entries = plane.audit()
    numbers = [entry["seq"] for entry in entries]

    assert numbers == sorted(
        numbers,
        reverse=True,
    )
    assert entries[0]["target"] == "two"


def test_audit_is_bounded(
    plane: ControlPlane,
) -> None:
    from firewall.ui.control import AUDIT_LIMIT

    for index in range(AUDIT_LIMIT + 20):
        plane._record(
            "synthetic",
            ok=True,
            target=str(index),
        )

    assert len(plane.audit()) == AUDIT_LIMIT
    assert plane.audit()[0]["target"] == str(
        AUDIT_LIMIT + 19
    )


def test_state_is_json_serializable(
    plane: ControlPlane,
) -> None:
    root = connect(plane)

    plane.delegate(
        {
            "fingerprint": root["fingerprint"],
            "delegatee": "agent-sub",
        }
    )

    payload = plane.state()

    json.dumps(payload, default=str)

    assert {
        "agents",
        "rules",
        "audit",
        "posture",
        "lifecycle",
    } <= set(payload)

    agents = {
        entry["agent"] for entry in payload["agents"]
    }

    assert agents == {"agent-alpha", "agent-sub"}


def test_agents_report_liveness(
    plane: ControlPlane,
) -> None:
    root = connect(plane)

    assert plane.agents()[0]["live"] is True

    plane.revoke({"fingerprint": root["fingerprint"]})

    assert plane.agents()[0]["live"] is False


# ======================================================================
# No cryptographic material in any control-plane payload
# ======================================================================


def _secret_values(
    sdk: FirewallSDK,
    capability: Capability,
) -> list[str]:
    secrets_found = []

    for field in ("signature", "public_key"):
        value = getattr(capability, field, None)

        if isinstance(value, str) and len(value) > 8:
            secrets_found.append(value)
        elif isinstance(value, bytes):
            secrets_found.append(value.hex())

    key = sdk.active_key()
    material = getattr(key, "public_key", None)

    if isinstance(material, str) and len(material) > 8:
        secrets_found.append(material)

    return secrets_found


def test_control_payloads_withhold_key_material(
    plane: ControlPlane,
) -> None:
    root = connect(plane)

    child = plane.delegate(
        {
            "fingerprint": root["fingerprint"],
            "delegatee": "agent-sub",
        }
    )

    verdict = plane.check(
        {
            "fingerprint": child["fingerprint"],
            "action": "payments.send",
            "request": {"amount": 1},
        }
    )

    blob = json.dumps(
        {
            "state": plane.state(),
            "root": root,
            "child": child,
            "verdict": verdict,
        },
        default=str,
    )

    capability = plane._lookup(root["fingerprint"])
    secrets_found = _secret_values(
        plane.sdk,
        capability,
    )

    assert secrets_found, (
        "no key material found to test against -- "
        "the assertion below would be vacuous"
    )

    for secret in secrets_found:
        assert secret not in blob

    assert root["redacted"] == list(
        introspect.REDACTED_CAPABILITY_FIELDS
    )


# ======================================================================
# HTTP surface
# ======================================================================


class _Client:
    def __init__(self, port: int):
        self.port = port

    def call(
        self,
        path: str,
        body: dict | None = None,
        token: str | None = None,
    ) -> tuple[int, dict]:
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=(
                json.dumps(body).encode("utf-8")
                if body is not None
                else None
            ),
            method=(
                "POST" if body is not None else "GET"
            ),
        )

        if token is not None:
            request.add_header(
                "Authorization",
                f"Bearer {token}",
            )

        try:
            with urllib.request.urlopen(
                request,
                timeout=10,
            ) as response:
                return response.status, json.loads(
                    response.read()
                )
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())


def _serve(**kwargs):
    server = build_server(
        port=0,
        quiet=True,
        **kwargs,
    )

    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
    )
    thread.start()

    return server, _Client(
        server.server_address[1]
    )


@pytest.fixture()
def readonly_server():
    server, client = _serve()
    yield server, client
    server.shutdown()
    server.server_close()


@pytest.fixture()
def control_server():
    server, client = _serve(control=True)
    yield server, client
    server.shutdown()
    server.server_close()


CONTROL_POSTS = (
    "/api/control/connect",
    "/api/control/delegate",
    "/api/control/attenuate",
    "/api/control/revoke",
    "/api/control/trust",
    "/api/control/depth",
    "/api/control/check",
)


def test_control_is_off_by_default(
    readonly_server,
) -> None:
    server, _ = readonly_server
    handler = server.RequestHandlerClass

    assert handler.control_enabled is False
    # No usable token exists on a read-only server, so the auth gate
    # fails closed on two independent conditions.
    assert handler.control_token is None


@pytest.mark.parametrize("path", CONTROL_POSTS)
def test_control_routes_do_not_exist_when_disabled(
    readonly_server,
    path: str,
) -> None:
    _, client = readonly_server

    status, _ = client.call(
        path,
        {"agent": "a", "capability": "b"},
    )

    assert status == 404


def test_control_state_is_hidden_when_disabled(
    readonly_server,
) -> None:
    _, client = readonly_server

    status, _ = client.call("/api/control/state")

    assert status == 404


def test_disabled_control_never_builds_a_plane(
    readonly_server,
) -> None:
    server, client = readonly_server

    client.call(
        "/api/control/connect",
        {"agent": "a", "capability": "b"},
        token="anything",
    )

    console = server.RequestHandlerClass.console

    assert console._control is None


@pytest.mark.parametrize("path", CONTROL_POSTS)
def test_control_requires_a_token(
    control_server,
    path: str,
) -> None:
    _, client = control_server

    status, payload = client.call(
        path,
        {"agent": "a", "capability": "b"},
    )

    assert status == 401
    assert "token" in payload["error"]


@pytest.mark.parametrize(
    "token",
    ["", "   ", "wrong", "Bearer", "x" * 64],
)
def test_control_rejects_a_bad_token(
    control_server,
    token: str,
) -> None:
    _, client = control_server

    status, _ = client.call(
        "/api/control/connect",
        {"agent": "a", "capability": "b"},
        token=token,
    )

    assert status == 401


def test_control_rejects_a_malformed_auth_header(
    control_server,
) -> None:
    server, client = control_server
    token = server.RequestHandlerClass.control_token

    request = urllib.request.Request(
        f"http://127.0.0.1:{client.port}"
        "/api/control/state",
    )
    # Right token, wrong scheme.
    request.add_header(
        "Authorization",
        f"Token {token}",
    )

    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(request, timeout=10)

    assert exc.value.code == 401


def test_control_accepts_the_startup_token(
    control_server,
) -> None:
    server, client = control_server
    token = server.RequestHandlerClass.control_token

    assert token and len(token) >= 32

    status, payload = client.call(
        "/api/control/connect",
        {
            "agent": "agent-ops",
            "capability": "payments.send",
            "constraints": {"amount_max": 10},
        },
        token=token,
    )

    assert status == 200
    assert (
        payload["result"]["agent_id"] == "agent-ops"
    )
    assert payload["state"]["audit"][0][
        "action"
    ] == "connect_agent"


def test_an_explicit_token_is_honoured() -> None:
    server, client = _serve(
        control=True,
        token="fixed-test-token",
    )

    try:
        assert (
            server.RequestHandlerClass.control_token
            == "fixed-test-token"
        )

        status, _ = client.call(
            "/api/control/state",
            token="fixed-test-token",
        )

        assert status == 200
    finally:
        server.shutdown()
        server.server_close()


def test_unknown_control_route_is_not_found(
    control_server,
) -> None:
    server, client = control_server
    token = server.RequestHandlerClass.control_token

    status, _ = client.call(
        "/api/control/escalate",
        {},
        token=token,
    )

    assert status == 404


def test_control_reports_bad_input_as_400(
    control_server,
) -> None:
    server, client = control_server
    token = server.RequestHandlerClass.control_token

    status, payload = client.call(
        "/api/control/connect",
        {"agent": "", "capability": "x"},
        token=token,
    )

    assert status == 400
    assert "empty" in payload["error"]


def test_control_rejects_an_oversized_body(
    control_server,
) -> None:
    server, client = control_server
    token = server.RequestHandlerClass.control_token

    status, _ = client.call(
        "/api/control/connect",
        {
            "agent": "a",
            "capability": "b",
            "padding": "x" * 20_000,
        },
        token=token,
    )

    assert status == 413


def test_system_advertises_whether_control_exists(
    readonly_server,
    control_server,
) -> None:
    _, readonly = readonly_server
    _, controlled = control_server

    assert (
        readonly.call("/api/system")[1][
            "control_enabled"
        ]
        is False
    )
    assert (
        controlled.call("/api/system")[1][
            "control_enabled"
        ]
        is True
    )


def test_read_routes_are_unchanged_by_control(
    control_server,
) -> None:
    """Enabling writes must not alter the read-only surface."""

    _, client = control_server

    for path in (
        "/api/system",
        "/api/scenarios",
        "/api/posture",
        "/api/lifecycle",
        "/api/history",
    ):
        status, _ = client.call(path)

        assert status == 200

    status, _ = client.call(
        "/api/evaluate",
        {"scenario": "allow_root"},
    )

    assert status == 200


def test_end_to_end_over_http(
    control_server,
) -> None:
    server, client = control_server
    token = server.RequestHandlerClass.control_token

    _, connected = client.call(
        "/api/control/connect",
        {
            "agent": "agent-ops",
            "capability": "payments.send",
            "constraints": {"amount_max": 100},
        },
        token=token,
    )

    fingerprint = connected["result"]["fingerprint"]

    _, delegated = client.call(
        "/api/control/delegate",
        {
            "fingerprint": fingerprint,
            "delegatee": "agent-sub",
            "constraints": {"amount_max": 20},
        },
        token=token,
    )

    child = delegated["result"]["fingerprint"]

    status, allowed = client.call(
        "/api/control/check",
        {
            "fingerprint": child,
            "action": "payments.send",
            "request": {"amount": 5},
        },
        token=token,
    )

    assert status == 200
    assert (
        allowed["result"]["decision"]["allowed"]
        is True
    )

    _, denied = client.call(
        "/api/control/check",
        {
            "fingerprint": child,
            "action": "payments.send",
            "request": {"amount": 5_000},
        },
        token=token,
    )

    assert (
        denied["result"]["decision"]["allowed"]
        is False
    )

    _, revoked = client.call(
        "/api/control/revoke",
        {"fingerprint": fingerprint},
        token=token,
    )

    assert all(
        not entry["live"]
        for entry in revoked["state"]["agents"]
    )
