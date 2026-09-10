"""v1.7 tests for the HTTP control-plane endpoints, the ``simulate`` CLI,
and the console UI workflow.

Three surfaces, one workflow -- record traffic, simulate the rule change,
promote only on evidence, roll back exactly:

* **HTTP**: ``/api/control/simulate``, ``/api/control/promote`` and
  ``/api/control/rollback`` inherit the v1.6.1 gates: they do not exist
  when control is disabled, require the startup token, and are audited.
* **CLI**: ``firewall simulate`` is usable as a CI gate -- ``0`` only
  when the change denies nothing that works today and every case was
  verified; ``2`` for unusable inputs.
* **UI**: the console shell ships the control surface (``control.js``)
  and the simulate/promote/rollback workflow is served over HTTP.

No pre-existing test is modified by this file.
"""

from __future__ import annotations

import io
import json
import threading
import urllib.error
import urllib.request

import pytest

from firewall.cli import main
from firewall.sdk import FirewallSDK
from firewall.simulation import (
    CaseRecorder,
    CaseSet,
    RuleSet,
    simulate,
)
from firewall.ui.server import build_server


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


V17_POSTS = (
    "/api/control/simulate",
    "/api/control/promote",
    "/api/control/rollback",
)


@pytest.mark.parametrize("path", V17_POSTS)
def test_v17_routes_do_not_exist_when_control_is_disabled(
    readonly_server,
    path: str,
) -> None:
    _, client = readonly_server

    status, _ = client.call(path, {})

    assert status == 404


@pytest.mark.parametrize("path", V17_POSTS)
def test_v17_routes_require_the_token(
    control_server,
    path: str,
) -> None:
    _, client = control_server

    status, payload = client.call(path, {})

    assert status == 401
    assert "token" in payload["error"]


def test_v17_state_requires_the_token(
    control_server,
) -> None:
    _, client = control_server

    status, _ = client.call("/api/control/state")

    assert status == 401


def _build_traffic(
    server,
    client,
) -> str:
    """Connect an agent, delegate twice, and authorize a request, so the
    console holds one depth-3 case. Returns the control token.
    """

    token = server.RequestHandlerClass.control_token

    status, payload = client.call(
        "/api/control/connect",
        {
            "agent": "agent-a",
            "capability": "payments.send",
            "constraints": {"amount_max": 1000},
        },
        token=token,
    )
    assert status == 200
    root = payload["result"]["fingerprint"]

    status, payload = client.call(
        "/api/control/delegate",
        {
            "fingerprint": root,
            "delegatee": "agent-b",
        },
        token=token,
    )
    assert status == 200
    child = payload["result"]["fingerprint"]

    status, payload = client.call(
        "/api/control/delegate",
        {
            "fingerprint": child,
            "delegatee": "agent-c",
        },
        token=token,
    )
    assert status == 200
    grand = payload["result"]["fingerprint"]

    status, payload = client.call(
        "/api/control/check",
        {
            "fingerprint": grand,
            "action": "payments.send",
            "request": {"amount": 50},
        },
        token=token,
    )
    assert status == 200
    assert payload["result"]["decision"]["allowed"]

    return token


def test_simulate_endpoint_reports_a_change_over_http(
    control_server,
) -> None:
    server, client = control_server
    token = _build_traffic(server, client)

    status, payload = client.call(
        "/api/control/simulate",
        {"max_delegation_depth": 2},
        token=token,
    )

    assert status == 200

    report = payload["result"]["report"]

    assert report["totals"]["newly_denied"] == 1
    assert report["blast_radius"]["agents"] == [
        "agent-c"
    ]
    assert report["summary"] != ""

    # The projection rides along for the UI.
    state = payload["state"]
    assert state["simulation"]["recorded_cases"] >= 1
    assert state["simulation"]["rollout"] is None


def test_promote_refuses_a_denying_change_without_ack_over_http(
    control_server,
) -> None:
    server, client = control_server
    token = _build_traffic(server, client)

    status, payload = client.call(
        "/api/control/promote",
        {"max_delegation_depth": 2},
        token=token,
    )

    assert status == 400
    assert "newly denied" in payload["error"]

    # Still refused: the audit records the attempt.
    state = client.call(
        "/api/control/state",
        token=token,
    )[1]
    refused = [
        entry
        for entry in state["audit"]
        if entry["action"] == "promote"
    ]
    assert refused and refused[0]["ok"] is False


def test_promote_then_rollback_over_http(
    control_server,
) -> None:
    server, client = control_server
    token = _build_traffic(server, client)

    status, payload = client.call(
        "/api/control/promote",
        {
            "max_delegation_depth": 2,
            "acknowledge": True,
        },
        token=token,
    )

    assert status == 200
    assert payload["result"]["rollout"]["stage"] == (
        "enforce"
    )
    assert payload["result"]["rules"][
        "max_delegation_depth"
    ] == 2

    # The UI's rollback button now exists.
    status, payload = client.call(
        "/api/control/rollback",
        {},
        token=token,
    )

    assert status == 200
    assert payload["result"]["rollout"]["stage"] == (
        "reverted"
    )
    assert payload["result"]["rules"][
        "max_delegation_depth"
    ] is None


def test_state_exposes_the_simulation_projection(
    control_server,
) -> None:
    server, client = control_server
    token = server.RequestHandlerClass.control_token

    status, payload = client.call(
        "/api/control/state",
        token=token,
    )

    assert status == 200
    assert "simulation" in payload
    assert payload["simulation"]["recorded_cases"] == 0
    assert payload["simulation"]["rollout"] is None


def test_invalid_proposal_is_rejected_over_http(
    control_server,
) -> None:
    server, client = control_server
    token = server.RequestHandlerClass.control_token

    status, payload = client.call(
        "/api/control/simulate",
        {"max_delegation_depth": "two"},
        token=token,
    )

    assert status == 400
    assert "integer" in payload["error"]


# ======================================================================
# CLI: firewall simulate
# ======================================================================


def _recorded_cases_file(
    tmp_path,
    *chains: tuple[str, ...],
) -> str:
    """Authorize real chains and write their cases to a JSON file."""

    sdk = FirewallSDK(
        trusted_issuers={"trusted-issuer"}
    )
    sdk.generate_key("cli-key")

    recorder = CaseRecorder()
    pk = sdk.active_key().private_key

    for agents in chains:
        root = sdk.issue(
            agent=agents[0],
            capability="pay.send",
            private_key=pk,
            issuer="trusted-issuer",
        )
        members = [root]

        for delegatee in agents[1:]:
            members.append(
                sdk.delegate(
                    members[-1],
                    pk,
                    delegatee=delegatee,
                ).child
            )

        decision = sdk.authorize(
            members[-1],
            "pay.send",
            {},
        )
        recorder.record(
            sdk,
            members[-1],
            "pay.send",
            {},
            decision,
        )

    path = tmp_path / "cases.json"
    path.write_text(
        recorder.cases().to_json(),
        encoding="utf-8",
    )

    return str(path)


def _rules_file(
    tmp_path,
    rules: RuleSet,
) -> str:
    path = tmp_path / "rules.json"
    path.write_text(
        rules.to_json(),
        encoding="utf-8",
    )
    return str(path)


def test_cli_simulate_passes_a_safe_change(
    tmp_path,
    capsys,
) -> None:
    cases = _recorded_cases_file(
        tmp_path,
        ("agent-a",),
    )
    rules = _rules_file(
        tmp_path,
        RuleSet(
            trusted_issuers={
                "trusted-issuer",
                "extra-issuer",
            }
        ),
    )

    result = main(
        [
            "simulate",
            cases,
            "--rules",
            rules,
        ]
    )

    assert result == 0
    output = capsys.readouterr()
    assert "nothing newly denied" in output.out


def test_cli_simulate_fails_a_newly_denying_change(
    tmp_path,
    capsys,
) -> None:
    cases = _recorded_cases_file(
        tmp_path,
        ("agent-a", "agent-b", "agent-c"),
    )
    rules = _rules_file(
        tmp_path,
        RuleSet(max_delegation_depth=2),
    )

    result = main(
        [
            "simulate",
            cases,
            "--rules",
            rules,
        ]
    )

    assert result == 1
    output = capsys.readouterr()
    assert "1 newly denied" in output.out
    assert "agent-c" in output.out


def test_cli_simulate_uses_max_depth_as_the_proposal(
    tmp_path,
    capsys,
) -> None:
    cases = _recorded_cases_file(
        tmp_path,
        ("agent-a", "agent-b", "agent-c"),
    )

    result = main(
        [
            "simulate",
            cases,
            "--max-depth",
            "2",
        ]
    )

    assert result == 1
    output = capsys.readouterr()
    assert "unbounded -> 2" in output.out


def test_cli_simulate_denies_the_baseline_issuers_by_default(
    tmp_path,
    capsys,
) -> None:
    """Without --baseline the 'before' side trusts exactly the issuers
    the cases name, reproducing the world they were recorded in.
    """

    cases = _recorded_cases_file(
        tmp_path,
        ("agent-a",),
    )

    result = main(
        [
            "simulate",
            cases,
            "--max-depth",
            "5",
        ]
    )

    assert result == 0
    output = capsys.readouterr()
    assert "1 of 1 case(s) counted" in output.out


def test_cli_simulate_reports_json(
    tmp_path,
    capsys,
) -> None:
    cases = _recorded_cases_file(
        tmp_path,
        ("agent-a", "agent-b", "agent-c"),
    )
    rules = _rules_file(
        tmp_path,
        RuleSet(max_delegation_depth=2),
    )

    result = main(
        [
            "simulate",
            cases,
            "--rules",
            rules,
            "--json",
        ]
    )

    assert result == 1

    payload = json.loads(
        capsys.readouterr().out
    )

    assert payload["totals"]["newly_denied"] == 1
    assert payload["blast_radius"]["agents"] == [
        "agent-c"
    ]
    assert payload["safe"] is False
    assert payload["caveats"]


def test_cli_simulate_missing_cases_file(
    tmp_path,
    capsys,
) -> None:
    result = main(
        [
            "simulate",
            str(tmp_path / "missing.json"),
        ]
    )

    assert result == 2
    assert "cannot read" in capsys.readouterr().err


def test_cli_simulate_malformed_cases_file(
    tmp_path,
    capsys,
) -> None:
    path = tmp_path / "cases.json"
    path.write_text(
        "{not json",
        encoding="utf-8",
    )

    result = main(
        ["simulate", str(path)]
    )

    assert result == 2
    assert "not valid JSON" in capsys.readouterr().err


def test_cli_simulate_invalid_rules_file(
    tmp_path,
    capsys,
) -> None:
    cases = _recorded_cases_file(
        tmp_path,
        ("agent-a",),
    )
    rules = tmp_path / "rules.json"
    rules.write_text(
        '{"max_delegation_depth": 0}',
        encoding="utf-8",
    )

    result = main(
        [
            "simulate",
            cases,
            "--rules",
            str(rules),
        ]
    )

    assert result == 2
    assert "positive" in capsys.readouterr().err


def test_cli_simulate_unverifiable_cases_are_not_a_pass(
    tmp_path,
    capsys,
) -> None:
    """'We could not tell' must exit non-zero, not silently pass."""

    case_set = CaseSet.from_json(
        json.dumps(
            {
                "version": 1,
                "cases": [
                    {
                        "case_id": "c1",
                        "action": "pay.send",
                        "capability": "pay.send",
                        "root_agent": "agent-a",
                        "baseline_reason": None,
                    }
                ],
            }
        )
    )

    path = tmp_path / "cases.json"
    path.write_text(
        case_set.to_json(),
        encoding="utf-8",
    )

    result = main(
        ["simulate", str(path)]
    )

    assert result == 1
    assert "not counted" in capsys.readouterr().out


def test_cli_unknown_command_is_an_error(
    capsys,
) -> None:
    with pytest.raises(SystemExit):
        main(["not-a-command"])


# ======================================================================
# UI workflow smoke
# ======================================================================


def test_the_console_ships_the_control_script(
    readonly_server,
) -> None:
    server, client = readonly_server
    del server

    request = urllib.request.Request(
        f"http://127.0.0.1:{client.port}"
        "/assets/control.js",
    )

    with urllib.request.urlopen(
        request,
        timeout=10,
    ) as response:
        body = response.read().decode("utf-8")

    assert response.status == 200
    # The workflow hooks are present in the shipped bundle.
    for marker in (
        "/api/control/simulate",
        "/api/control/promote",
        "/api/control/rollback",
        "readProposal",
    ):
        assert marker in body


def test_index_html_contains_the_simulation_workflow() -> None:
    from pathlib import Path

    html = io.open(
        Path(
            "firewall/ui/static/index.html"
        ),
        encoding="utf-8",
    ).read()

    for marker in (
        "control.js",
        "proposeDepth",
        "proposeIssuers",
        "simReport",
        "promoteBtn",
        "rollbackBtn",
        "ackInput",
        "rolloutTable",
    ):
        assert marker in html


def test_system_advertises_control_when_enabled(
    control_server,
) -> None:
    server, client = control_server

    request = urllib.request.Request(
        f"http://127.0.0.1:{client.port}"
        "/api/system",
    )

    with urllib.request.urlopen(
        request,
        timeout=10,
    ) as response:
        payload = json.loads(
            response.read()
        )

    assert payload["control_enabled"] is True


def test_system_does_not_advertise_control_when_disabled(
    readonly_server,
) -> None:
    server, client = readonly_server

    request = urllib.request.Request(
        f"http://127.0.0.1:{client.port}"
        "/api/system",
    )

    with urllib.request.urlopen(
        request,
        timeout=10,
    ) as response:
        payload = json.loads(
            response.read()
        )

    assert payload["control_enabled"] is False
