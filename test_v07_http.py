import pytest

from firewall.capability import (
    generate_capability_key_pair,
)

from firewall.http import (
    HTTPAuthorizationError,
    HTTPDecision,
    HTTPFirewall,
    HTTPFirewallError,
    HTTPRequest,
)

from firewall.sdk import FirewallSDK


def make_sdk():
    return FirewallSDK(
        trusted_issuers={"trusted-issuer"}
    )


def make_capability(
    sdk,
    *,
    agent="finance-agent",
    capability="http.POST.payments",
    constraints=None,
    issued_at=None,
    expires_at=None,
):
    private_key, _ = (
        generate_capability_key_pair()
    )

    kwargs = {}

    if issued_at is not None:
        kwargs["issued_at"] = issued_at

    if expires_at is not None:
        kwargs["expires_at"] = expires_at

    return sdk.issue(
        private_key=private_key,
        agent=agent,
        capability=capability,
        constraints=(
            {}
            if constraints is None
            else constraints
        ),
        **kwargs,
    )


def make_request(
    sdk,
    *,
    agent="finance-agent",
    method="POST",
    path="/payments",
    arguments=None,
    nonce="nonce-1",
    capability_agent=None,
    capability_name="http.POST.payments",
    constraints=None,
):
    capability = make_capability(
        sdk,
        agent=(
            agent
            if capability_agent is None
            else capability_agent
        ),
        capability=capability_name,
        constraints=constraints,
    )

    return HTTPRequest(
        agent=agent,
        method=method,
        path=path,
        arguments=(
            {}
            if arguments is None
            else arguments
        ),
        capability_token=sdk.encode(
            capability
        ),
        nonce=nonce,
    )


def make_adapter():
    return HTTPFirewall(make_sdk())


# ============================================================
# Initialization
# ============================================================


def test_http_initializes():
    adapter = make_adapter()

    assert adapter.sdk is not None
    assert adapter.require_nonce is True


def test_http_rejects_invalid_sdk():
    with pytest.raises(TypeError):
        HTTPFirewall("invalid")


def test_nonce_requirement_can_be_disabled():
    adapter = HTTPFirewall(
        make_sdk(),
        require_nonce=False,
    )

    assert adapter.require_nonce is False


# ============================================================
# Request construction
# ============================================================


def test_request_builder():
    sdk = make_sdk()
    capability = make_capability(sdk)

    request = HTTPFirewall.request(
        agent="finance-agent",
        method="POST",
        path="/payments",
        arguments={"amount": 10},
        capability_token=sdk.encode(
            capability
        ),
        nonce="nonce-1",
    )

    assert isinstance(
        request,
        HTTPRequest,
    )


def test_request_defaults_arguments():
    sdk = make_sdk()
    capability = make_capability(sdk)

    request = HTTPFirewall.request(
        agent="finance-agent",
        method="POST",
        path="/payments",
        capability_token=sdk.encode(
            capability
        ),
        nonce="nonce-1",
    )

    assert request.arguments == {}


def test_request_copies_arguments():
    sdk = make_sdk()
    capability = make_capability(sdk)

    arguments = {"amount": 10}

    request = HTTPFirewall.request(
        agent="finance-agent",
        method="POST",
        path="/payments",
        arguments=arguments,
        capability_token=sdk.encode(
            capability
        ),
        nonce="nonce-1",
    )

    arguments["amount"] = 999

    assert request.arguments["amount"] == 10


def test_request_rejects_non_dict_arguments():
    sdk = make_sdk()
    capability = make_capability(sdk)

    with pytest.raises(TypeError):
        HTTPFirewall.request(
            agent="finance-agent",
            method="POST",
            path="/payments",
            arguments=[],
            capability_token=sdk.encode(
                capability
            ),
            nonce="nonce-1",
        )


# ============================================================
# Action mapping
# ============================================================


@pytest.mark.parametrize(
    "method,path,expected",
    [
        (
            "GET",
            "/payments",
            "http.GET.payments",
        ),
        (
            "POST",
            "/payments",
            "http.POST.payments",
        ),
        (
            "PUT",
            "/payments/1",
            "http.PUT.payments.1",
        ),
        (
            "PATCH",
            "/payments/1",
            "http.PATCH.payments.1",
        ),
        (
            "DELETE",
            "/payments/1",
            "http.DELETE.payments.1",
        ),
    ],
)
def test_action_mapping(
    method,
    path,
    expected,
):
    assert (
        HTTPFirewall.action_for(
            method,
            path,
        )
        == expected
    )


def test_action_mapping_normalizes_method():
    assert (
        HTTPFirewall.action_for(
            "post",
            "/payments",
        )
        == "http.POST.payments"
    )


def test_action_mapping_strips_method():
    assert (
        HTTPFirewall.action_for(
            " POST ",
            "/payments",
        )
        == "http.POST.payments"
    )


def test_action_mapping_strips_path():
    assert (
        HTTPFirewall.action_for(
            "POST",
            " /payments ",
        )
        == "http.POST.payments"
    )


def test_root_path_mapping():
    assert (
        HTTPFirewall.action_for(
            "GET",
            "/",
        )
        == "http.GET.root"
    )


def test_action_mapping_rejects_empty_method():
    with pytest.raises(ValueError):
        HTTPFirewall.action_for(
            "",
            "/payments",
        )


def test_action_mapping_rejects_empty_path():
    with pytest.raises(ValueError):
        HTTPFirewall.action_for(
            "POST",
            "",
        )


def test_action_mapping_rejects_non_string_method():
    with pytest.raises(TypeError):
        HTTPFirewall.action_for(
            None,
            "/payments",
        )


def test_action_mapping_rejects_non_string_path():
    with pytest.raises(TypeError):
        HTTPFirewall.action_for(
            "POST",
            None,
        )


def test_action_mapping_requires_leading_slash():
    with pytest.raises(ValueError):
        HTTPFirewall.action_for(
            "POST",
            "payments",
        )


def test_action_mapping_rejects_empty_segment():
    with pytest.raises(ValueError):
        HTTPFirewall.action_for(
            "POST",
            "/payments//refund",
        )


def test_action_mapping_rejects_invalid_segment():
    with pytest.raises(ValueError):
        HTTPFirewall.action_for(
            "POST",
            "/payments/$admin",
        )


def test_action_mapping_rejects_dot_segments():
    with pytest.raises(ValueError):
        HTTPFirewall.action_for(
            "POST",
            "/payments/../admin",
        )


# ============================================================
# Decode
# ============================================================


def test_decode_valid_capability():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    capability = make_capability(sdk)

    restored = adapter.decode_capability(
        sdk.encode(capability)
    )

    assert (
        restored.to_dict()
        == capability.to_dict()
    )


def test_decode_invalid_token_rejected():
    adapter = make_adapter()

    with pytest.raises(Exception):
        adapter.decode_capability(
            "garbage"
        )


# ============================================================
# Basic authorization
# ============================================================


def test_authorize_valid_request():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    request = make_request(sdk)

    decision = adapter.authorize(
        request
    )

    assert isinstance(
        decision,
        HTTPDecision,
    )

    assert decision.allowed is True
    assert decision.status_code == 200


def test_decision_contains_agent():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    request = make_request(sdk)

    decision = adapter.authorize(
        request
    )

    assert (
        decision.agent
        == "finance-agent"
    )


def test_decision_contains_method():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    request = make_request(
        sdk,
        method="POST",
    )

    decision = adapter.authorize(
        request
    )

    assert decision.method == "POST"


def test_decision_contains_path():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    request = make_request(
        sdk,
        path="/payments",
    )

    decision = adapter.authorize(
        request
    )

    assert (
        decision.path
        == "/payments"
    )


# ============================================================
# Agent binding
# ============================================================


def test_wrong_agent_denied():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    request = make_request(
        sdk,
        agent="agent-b",
        capability_agent="agent-a",
    )

    decision = adapter.authorize(
        request
    )

    assert decision.allowed is False
    assert decision.status_code == 403


def test_cross_agent_substitution_denied():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    capability = make_capability(
        sdk,
        agent="agent-a",
    )

    request = HTTPRequest(
        agent="agent-b",
        method="POST",
        path="/payments",
        arguments={},
        capability_token=sdk.encode(
            capability
        ),
        nonce="cross-agent",
    )

    called = []

    def handler(request):
        called.append(True)

    decision = adapter.authorize(
        request
    )

    assert decision.allowed is False

    with pytest.raises(
        HTTPAuthorizationError
    ):
        adapter.execute(
            request,
            handler,
        )

    assert called == []


# ============================================================
# Capability scope
# ============================================================


def test_correct_scope_allowed():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    request = make_request(
        sdk,
        capability_name="http.POST.payments",
    )

    assert (
        adapter.authorize(
            request
        ).allowed
        is True
    )


def test_wrong_scope_denied():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    request = make_request(
        sdk,
        capability_name="http.GET.payments",
        method="POST",
        path="/payments",
    )

    decision = adapter.authorize(
        request
    )

    assert decision.allowed is False
    assert decision.status_code == 403


def test_wrong_path_denied():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    request = make_request(
        sdk,
        capability_name="http.POST.payments",
        path="/admin",
    )

    assert (
        adapter.authorize(
            request
        ).allowed
        is False
    )


def test_wrong_method_denied():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    request = make_request(
        sdk,
        capability_name="http.POST.payments",
        method="GET",
    )

    assert (
        adapter.authorize(
            request
        ).allowed
        is False
    )


def test_nested_path_scope():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    request = make_request(
        sdk,
        capability_name="http.POST.payments.refund",
        method="POST",
        path="/payments/refund",
    )

    assert (
        adapter.authorize(
            request
        ).allowed
        is True
    )


# ============================================================
# Wildcards
# ============================================================


def test_namespace_wildcard_allows_child():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    request = make_request(
        sdk,
        capability_name="http.POST.payments.*",
        method="POST",
        path="/payments/refund",
    )

    assert (
        adapter.authorize(
            request
        ).allowed
        is True
    )


def test_namespace_wildcard_denies_other_root():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    request = make_request(
        sdk,
        capability_name="http.POST.payments.*",
        method="POST",
        path="/accounts/read",
    )

    assert (
        adapter.authorize(
            request
        ).allowed
        is False
    )


def test_unrelated_namespace_denied():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    request = make_request(
        sdk,
        capability_name="payments.*",
    )

    assert (
        adapter.authorize(
            request
        ).allowed
        is False
    )


# ============================================================
# Constraints
# ============================================================


def test_constraint_allowed():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    request = make_request(
        sdk,
        arguments={"amount": 50},
        constraints={
            "amount_max": 100
        },
    )

    assert (
        adapter.authorize(
            request
        ).allowed
        is True
    )


def test_constraint_denied():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    request = make_request(
        sdk,
        arguments={"amount": 101},
        constraints={
            "amount_max": 100
        },
    )

    assert (
        adapter.authorize(
            request
        ).allowed
        is False
    )


def test_constraint_boundary_allowed():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    request = make_request(
        sdk,
        arguments={"amount": 100},
        constraints={
            "amount_max": 100
        },
    )

    assert (
        adapter.authorize(
            request
        ).allowed
        is True
    )


# ============================================================
# Replay
# ============================================================


def test_first_nonce_allowed():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    request = make_request(
        sdk,
        nonce="nonce-1",
    )

    assert (
        adapter.authorize(
            request
        ).allowed
        is True
    )


def test_replay_denied():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    request = make_request(
        sdk,
        nonce="nonce-1",
    )

    first = adapter.authorize(request)
    second = adapter.authorize(request)

    assert first.allowed is True
    assert second.allowed is False
    assert second.status_code == 409


def test_different_nonce_allowed():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    first = make_request(
        sdk,
        nonce="nonce-1",
    )

    second = make_request(
        sdk,
        nonce="nonce-2",
    )

    assert (
        adapter.authorize(first).allowed
        is True
    )

    assert (
        adapter.authorize(second).allowed
        is True
    )


def test_missing_nonce_denied():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    request = make_request(
        sdk,
        nonce="",
    )

    decision = adapter.authorize(request)

    assert decision.allowed is False
    assert decision.status_code == 400


def test_nonce_can_be_disabled():
    sdk = make_sdk()

    adapter = HTTPFirewall(
        sdk,
        require_nonce=False,
    )

    request = make_request(
        sdk,
        nonce="",
    )

    assert (
        adapter.authorize(request).allowed
        is True
    )


def test_denied_request_does_not_consume_nonce():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    capability = make_capability(
        sdk,
        capability="http.GET.payments",
    )

    request = HTTPRequest(
        agent="finance-agent",
        method="POST",
        path="/payments",
        arguments={},
        capability_token=sdk.encode(
            capability
        ),
        nonce="denied-nonce",
    )

    first = adapter.authorize(request)

    assert first.allowed is False

    valid_request = HTTPRequest(
        agent="finance-agent",
        method="GET",
        path="/payments",
        arguments={},
        capability_token=sdk.encode(
            capability
        ),
        nonce="denied-nonce",
    )

    second = adapter.authorize(
        valid_request
    )

    assert second.allowed is True


# ============================================================
# Token tampering
# ============================================================


def test_tampered_token_denied():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    capability = make_capability(sdk)

    token = sdk.encode(
        capability
    )

    tampered = (
        token[:-1]
        + (
            "A"
            if token[-1] != "A"
            else "B"
        )
    )

    request = HTTPRequest(
        agent="finance-agent",
        method="POST",
        path="/payments",
        arguments={},
        capability_token=tampered,
        nonce="tamper-1",
    )

    assert (
        adapter.authorize(request).allowed
        is False
    )


def test_garbage_token_denied():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    request = HTTPRequest(
        agent="finance-agent",
        method="POST",
        path="/payments",
        arguments={},
        capability_token="garbage",
        nonce="garbage-1",
    )

    decision = adapter.authorize(request)

    assert decision.allowed is False
    assert decision.status_code == 401


# ============================================================
# Expiration
# ============================================================


def test_expired_capability_denied():
    now = [1000.0]

    sdk = FirewallSDK(
        trusted_issuers={
            "trusted-issuer"
        },
        clock=lambda: now[0],
    )

    adapter = HTTPFirewall(sdk)

    private_key, _ = (
        generate_capability_key_pair()
    )

    capability = sdk.issue(
        private_key=private_key,
        agent="finance-agent",
        capability="http.POST.payments",
        issued_at=900,
        expires_at=1100,
    )

    request = HTTPRequest(
        agent="finance-agent",
        method="POST",
        path="/payments",
        arguments={},
        capability_token=sdk.encode(
            capability
        ),
        nonce="expired-1",
    )

    now[0] = 1200.0

    decision = adapter.authorize(request)

    assert decision.allowed is False


# ============================================================
# Header parsing
# ============================================================


def test_from_http_bearer_header():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    capability = make_capability(sdk)

    request = adapter.from_http(
        agent="finance-agent",
        method="POST",
        path="/payments",
        arguments={"amount": 10},
        headers={
            "Authorization": (
                "Bearer "
                + sdk.encode(capability)
            ),
            "X-Agent-Nonce": "header-1",
        },
    )

    assert isinstance(
        request,
        HTTPRequest,
    )

    assert (
        request.capability_token
        == sdk.encode(capability)
    )


def test_from_http_raw_authorization_header():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    capability = make_capability(sdk)

    request = adapter.from_http(
        agent="finance-agent",
        method="POST",
        path="/payments",
        arguments={},
        headers={
            "Authorization": sdk.encode(
                capability
            ),
            "X-Agent-Nonce": "header-2",
        },
    )

    assert (
        request.capability_token
        == sdk.encode(capability)
    )


def test_from_http_missing_capability_header():
    adapter = make_adapter()

    with pytest.raises(
        HTTPFirewallError
    ):
        adapter.from_http(
            agent="finance-agent",
            method="POST",
            path="/payments",
            arguments={},
            headers={
                "X-Agent-Nonce": "missing-1"
            },
        )


def test_from_http_reads_nonce():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    capability = make_capability(sdk)

    request = adapter.from_http(
        agent="finance-agent",
        method="POST",
        path="/payments",
        arguments={},
        headers={
            "Authorization": sdk.encode(
                capability
            ),
            "X-Agent-Nonce": "nonce-header",
        },
    )

    assert (
        request.nonce
        == "nonce-header"
    )


def test_from_http_custom_headers():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    capability = make_capability(sdk)

    request = adapter.from_http(
        agent="finance-agent",
        method="POST",
        path="/payments",
        arguments={},
        headers={
            "X-Capability": sdk.encode(
                capability
            ),
            "X-Nonce": "custom-1",
        },
        capability_header="X-Capability",
        nonce_header="X-Nonce",
    )

    assert (
        request.nonce
        == "custom-1"
    )


def test_from_http_rejects_invalid_headers():
    adapter = make_adapter()

    with pytest.raises(TypeError):
        adapter.from_http(
            agent="finance-agent",
            method="POST",
            path="/payments",
            arguments={},
            headers=[],
        )


def test_from_http_rejects_non_string_token():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    with pytest.raises(
        HTTPFirewallError
    ):
        adapter.from_http(
            agent="finance-agent",
            method="POST",
            path="/payments",
            arguments={},
            headers={
                "Authorization": 123,
                "X-Agent-Nonce": "x",
            },
        )


# ============================================================
# Enforcement
# ============================================================


def test_enforce_allows_valid_request():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    request = make_request(sdk)

    decision = adapter.enforce(request)

    assert decision.allowed is True


def test_enforce_rejects_denied_request():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    request = make_request(
        sdk,
        capability_name="http.GET.payments",
        method="POST",
    )

    with pytest.raises(
        HTTPAuthorizationError
    ):
        adapter.enforce(request)


def test_enforce_replay_rejected():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    request = make_request(
        sdk,
        nonce="enforce-replay",
    )

    adapter.enforce(request)

    with pytest.raises(
        HTTPAuthorizationError
    ):
        adapter.enforce(request)


# ============================================================
# Execution
# ============================================================


def test_execute_calls_handler():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    request = make_request(
        sdk,
        arguments={"amount": 50},
    )

    seen = []

    def handler(request):
        seen.append(request)
        return "ok"

    result = adapter.execute(
        request,
        handler,
    )

    assert result == "ok"
    assert seen == [request]


def test_execute_does_not_call_denied_handler():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    request = make_request(
        sdk,
        capability_name="http.GET.payments",
        method="POST",
    )

    called = []

    def handler(request):
        called.append(True)

    with pytest.raises(
        HTTPAuthorizationError
    ):
        adapter.execute(
            request,
            handler,
        )

    assert called == []


def test_execute_rejects_non_callable():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    request = make_request(sdk)

    with pytest.raises(TypeError):
        adapter.execute(
            request,
            "invalid",
        )


def test_execute_passes_original_request():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    request = make_request(
        sdk,
        arguments={
            "amount": 25,
            "currency": "USD",
        },
    )

    def handler(received):
        return received

    assert (
        adapter.execute(
            request,
            handler,
        )
        == request
    )


# ============================================================
# Security boundary
# ============================================================


def test_denied_request_never_reaches_handler():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    request = make_request(
        sdk,
        capability_name="http.GET.admin",
        method="POST",
        path="/admin",
    )

    executed = []

    def handler(request):
        executed.append(True)

    with pytest.raises(
        HTTPAuthorizationError
    ):
        adapter.execute(
            request,
            handler,
        )

    assert executed == []


def test_wrong_capability_cannot_authorize_endpoint():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    request = make_request(
        sdk,
        capability_name="http.POST.payments",
        method="POST",
        path="/admin",
    )

    assert (
        adapter.authorize(
            request
        ).allowed
        is False
    )


def test_same_nonce_same_capability_replay():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    request = make_request(
        sdk,
        nonce="same-http-nonce",
    )

    first = adapter.authorize(request)
    second = adapter.authorize(request)

    assert first.allowed is True
    assert second.allowed is False


def test_same_nonce_different_capabilities_allowed():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    first = make_request(
        sdk,
        capability_name="http.POST.payments",
        method="POST",
        path="/payments",
        nonce="shared-http-nonce",
    )

    second = make_request(
        sdk,
        capability_name="http.GET.accounts",
        method="GET",
        path="/accounts",
        nonce="shared-http-nonce",
    )

    assert (
        adapter.authorize(first).allowed
        is True
    )

    assert (
        adapter.authorize(second).allowed
        is True
    )


def test_malformed_request_type_rejected():
    adapter = make_adapter()

    with pytest.raises(TypeError):
        adapter.authorize("invalid")


# ============================================================
# Complete flows
# ============================================================


def test_complete_http_flow():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    capability = make_capability(
        sdk,
        capability="http.POST.payments",
        constraints={
            "amount_max": 100
        },
    )

    request = HTTPRequest(
        agent="finance-agent",
        method="POST",
        path="/payments",
        arguments={"amount": 75},
        capability_token=sdk.encode(
            capability
        ),
        nonce="complete-1",
    )

    result = adapter.execute(
        request,
        lambda req: {
            "status": "sent",
            "amount": req.arguments[
                "amount"
            ],
        },
    )

    assert result == {
        "status": "sent",
        "amount": 75,
    }


def test_complete_denied_flow():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    capability = make_capability(
        sdk,
        capability="http.POST.payments",
        constraints={
            "amount_max": 100
        },
    )

    request = HTTPRequest(
        agent="finance-agent",
        method="POST",
        path="/payments",
        arguments={"amount": 101},
        capability_token=sdk.encode(
            capability
        ),
        nonce="denied-1",
    )

    with pytest.raises(
        HTTPAuthorizationError
    ):
        adapter.execute(
            request,
            lambda req: "should-not-run",
        )


def test_complete_bearer_flow():
    sdk = make_sdk()
    adapter = HTTPFirewall(sdk)

    capability = make_capability(
        sdk,
        capability="http.POST.payments",
    )

    request = adapter.from_http(
        agent="finance-agent",
        method="POST",
        path="/payments",
        arguments={"amount": 10},
        headers={
            "Authorization": (
                "Bearer "
                + sdk.encode(capability)
            ),
            "X-Agent-Nonce": "bearer-1",
        },
    )

    assert (
        adapter.authorize(
            request
        ).allowed
        is True
    )