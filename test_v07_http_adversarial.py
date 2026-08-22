import pytest

from firewall.capability import (
    generate_capability_key_pair,
)
from firewall.http import (
    HTTPAuthorizationError,
    HTTPFirewall,
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
    agent="agent-a",
    capability="http.POST.payments",
    constraints=None,
):
    private_key, _ = (
        generate_capability_key_pair()
    )

    return sdk.issue(
        private_key=private_key,
        agent=agent,
        capability=capability,
        constraints=(
            {}
            if constraints is None
            else constraints
        ),
    )


def make_request(
    sdk,
    *,
    capability=None,
    agent="agent-a",
    method="POST",
    path="/payments",
    arguments=None,
    nonce="nonce-1",
):
    if capability is None:
        capability = make_capability(
            sdk,
            agent=agent,
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


# ============================================================
# Cross-agent attacks
# ============================================================


def test_cross_agent_substitution_denied():
    sdk = make_sdk()
    firewall = HTTPFirewall(sdk)

    capability = make_capability(
        sdk,
        agent="agent-a",
    )

    request = make_request(
        sdk,
        capability=capability,
        agent="agent-b",
    )

    decision = firewall.authorize(request)

    assert decision.allowed is False
    assert decision.status_code == 403


def test_cross_agent_execution_blocked():
    sdk = make_sdk()
    firewall = HTTPFirewall(sdk)

    capability = make_capability(
        sdk,
        agent="agent-a",
    )

    request = make_request(
        sdk,
        capability=capability,
        agent="agent-b",
    )

    called = []

    def handler(request):
        called.append(True)

    with pytest.raises(
        HTTPAuthorizationError
    ):
        firewall.execute(
            request,
            handler,
        )

    assert called == []


# ============================================================
# Token tampering
# ============================================================


def test_token_bit_tampering_denied():
    sdk = make_sdk()
    firewall = HTTPFirewall(sdk)

    capability = make_capability(sdk)
    token = sdk.encode(capability)

    tampered = (
        token[:-1]
        + (
            "A"
            if token[-1] != "A"
            else "B"
        )
    )

    request = HTTPRequest(
        agent="agent-a",
        method="POST",
        path="/payments",
        arguments={},
        capability_token=tampered,
        nonce="tamper-1",
    )

    decision = firewall.authorize(request)

    assert decision.allowed is False
    assert decision.status_code == 401


def test_signature_replacement_denied():
    sdk = make_sdk()
    firewall = HTTPFirewall(sdk)

    capability = make_capability(sdk)
    token = sdk.encode(capability)

    # Mutate the transport token itself.
    # Do not assume an internal JSON field layout.
    tampered = (
        token[:-1]
        + (
            "A"
            if token[-1] != "A"
            else "B"
        )
    )

    request = HTTPRequest(
        agent="agent-a",
        method="POST",
        path="/payments",
        arguments={},
        capability_token=tampered,
        nonce="signature-1",
    )

    decision = firewall.authorize(request)

    assert decision.allowed is False
    assert decision.status_code == 401


def test_garbage_token_denied():
    sdk = make_sdk()
    firewall = HTTPFirewall(sdk)

    request = HTTPRequest(
        agent="agent-a",
        method="POST",
        path="/payments",
        arguments={},
        capability_token="garbage",
        nonce="garbage-1",
    )

    decision = firewall.authorize(request)

    assert decision.allowed is False
    assert decision.status_code == 401


def test_empty_token_denied():
    sdk = make_sdk()
    firewall = HTTPFirewall(sdk)

    request = HTTPRequest(
        agent="agent-a",
        method="POST",
        path="/payments",
        arguments={},
        capability_token="",
        nonce="empty-token",
    )

    decision = firewall.authorize(request)

    assert decision.allowed is False
    assert decision.status_code == 401


# ============================================================
# Replay
# ============================================================


def test_replay_is_denied():
    sdk = make_sdk()
    firewall = HTTPFirewall(sdk)

    request = make_request(
        sdk,
        nonce="replay-1",
    )

    first = firewall.authorize(request)
    second = firewall.authorize(request)

    assert first.allowed is True
    assert second.allowed is False
    assert second.status_code == 409


def test_replay_cannot_execute_handler():
    sdk = make_sdk()
    firewall = HTTPFirewall(sdk)

    request = make_request(
        sdk,
        nonce="replay-exec",
    )

    called = []

    def handler(request):
        called.append(True)

    firewall.execute(
        request,
        handler,
    )

    with pytest.raises(
        HTTPAuthorizationError
    ):
        firewall.execute(
            request,
            handler,
        )

    assert called == [True]


def test_different_nonce_is_not_replay():
    sdk = make_sdk()
    firewall = HTTPFirewall(sdk)

    first = make_request(
        sdk,
        nonce="nonce-a",
    )

    second = make_request(
        sdk,
        nonce="nonce-b",
    )

    assert (
        firewall.authorize(first).allowed
        is True
    )

    assert (
        firewall.authorize(second).allowed
        is True
    )


def test_same_nonce_different_agent_allowed():
    sdk = make_sdk()
    firewall = HTTPFirewall(sdk)

    cap_a = make_capability(
        sdk,
        agent="agent-a",
    )

    cap_b = make_capability(
        sdk,
        agent="agent-b",
    )

    first = make_request(
        sdk,
        capability=cap_a,
        agent="agent-a",
        nonce="shared",
    )

    second = make_request(
        sdk,
        capability=cap_b,
        agent="agent-b",
        nonce="shared",
    )

    assert (
        firewall.authorize(first).allowed
        is True
    )

    assert (
        firewall.authorize(second).allowed
        is True
    )


def test_same_nonce_different_capability_allowed():
    sdk = make_sdk()
    firewall = HTTPFirewall(sdk)

    cap_a = make_capability(
        sdk,
        capability="http.POST.payments",
    )

    cap_b = make_capability(
        sdk,
        capability="http.GET.accounts",
    )

    first = make_request(
        sdk,
        capability=cap_a,
        method="POST",
        path="/payments",
        nonce="shared",
    )

    second = make_request(
        sdk,
        capability=cap_b,
        method="GET",
        path="/accounts",
        nonce="shared",
    )

    assert (
        firewall.authorize(first).allowed
        is True
    )

    assert (
        firewall.authorize(second).allowed
        is True
    )


# ============================================================
# Nonce burning
# ============================================================


def test_denied_scope_does_not_consume_nonce():
    sdk = make_sdk()
    firewall = HTTPFirewall(sdk)

    capability = make_capability(
        sdk,
        capability="http.GET.payments",
    )

    denied = make_request(
        sdk,
        capability=capability,
        method="POST",
        path="/payments",
        nonce="reusable",
    )

    assert (
        firewall.authorize(denied).allowed
        is False
    )

    allowed = make_request(
        sdk,
        capability=capability,
        method="GET",
        path="/payments",
        nonce="reusable",
    )

    assert (
        firewall.authorize(allowed).allowed
        is True
    )


def test_denied_constraint_does_not_consume_nonce():
    sdk = make_sdk()
    firewall = HTTPFirewall(sdk)

    capability = make_capability(
        sdk,
        constraints={
            "amount_max": 100
        },
    )

    denied = make_request(
        sdk,
        capability=capability,
        arguments={"amount": 101},
        nonce="constraint-reuse",
    )

    assert (
        firewall.authorize(denied).allowed
        is False
    )

    allowed = make_request(
        sdk,
        capability=capability,
        arguments={"amount": 50},
        nonce="constraint-reuse",
    )

    assert (
        firewall.authorize(allowed).allowed
        is True
    )


def test_missing_nonce_denied():
    sdk = make_sdk()
    firewall = HTTPFirewall(sdk)

    request = make_request(
        sdk,
        nonce="",
    )

    decision = firewall.authorize(request)

    assert decision.allowed is False
    assert decision.status_code == 400


# ============================================================
# Scope escalation
# ============================================================


@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/admin"),
        ("POST", "/admin"),
        ("DELETE", "/payments"),
        ("PUT", "/accounts"),
    ],
)
def test_scope_escalation_denied(
    method,
    path,
):
    sdk = make_sdk()
    firewall = HTTPFirewall(sdk)

    capability = make_capability(
        sdk,
        capability="http.POST.payments",
    )

    request = make_request(
        sdk,
        capability=capability,
        method=method,
        path=path,
    )

    assert (
        firewall.authorize(request).allowed
        is False
    )


def test_wildcard_cannot_cross_root():
    sdk = make_sdk()
    firewall = HTTPFirewall(sdk)

    capability = make_capability(
        sdk,
        capability="http.POST.payments.*",
    )

    request = make_request(
        sdk,
        capability=capability,
        method="POST",
        path="/admin/delete",
    )

    assert (
        firewall.authorize(request).allowed
        is False
    )


def test_wildcard_child_allowed():
    sdk = make_sdk()
    firewall = HTTPFirewall(sdk)

    capability = make_capability(
        sdk,
        capability="http.POST.payments.*",
    )

    request = make_request(
        sdk,
        capability=capability,
        method="POST",
        path="/payments/refund",
    )

    assert (
        firewall.authorize(request).allowed
        is True
    )


def test_exact_scope_cannot_authorize_child():
    sdk = make_sdk()
    firewall = HTTPFirewall(sdk)

    capability = make_capability(
        sdk,
        capability="http.POST.payments",
    )

    request = make_request(
        sdk,
        capability=capability,
        method="POST",
        path="/payments/refund",
    )

    assert (
        firewall.authorize(request).allowed
        is False
    )


# ============================================================
# Path confusion
# ============================================================


@pytest.mark.parametrize(
    "path",
    [
        "/payments/../admin",
        "/payments//admin",
        "/payments/$admin",
        "/payments/%2e%2e/admin",
        "/payments/%2Fadmin",
        "/payments/ admin",
        "/payments/",
    ],
)
def test_path_confusion_rejected(path):
    sdk = make_sdk()
    firewall = HTTPFirewall(sdk)

    request = make_request(
        sdk,
        path=path,
    )

    assert (
        firewall.authorize(request).allowed
        is False
    )


def test_missing_leading_slash_rejected():
    sdk = make_sdk()
    firewall = HTTPFirewall(sdk)

    request = make_request(
        sdk,
        path="payments",
    )

    assert (
        firewall.authorize(request).allowed
        is False
    )


# ============================================================
# Method confusion
# ============================================================


@pytest.mark.parametrize(
    "method",
    [
        "",
        " ",
        "TRACE",
        "CONNECT",
        "OPTIONS",
        "POST/../GET",
        "POST GET",
    ],
)
def test_method_confusion_rejected(method):
    sdk = make_sdk()
    firewall = HTTPFirewall(sdk)

    request = make_request(
        sdk,
        method=method,
    )

    assert (
        firewall.authorize(request).allowed
        is False
    )


def test_method_case_normalization():
    sdk = make_sdk()
    firewall = HTTPFirewall(sdk)

    request = make_request(
        sdk,
        method="post",
    )

    assert (
        firewall.authorize(request).allowed
        is True
    )


# ============================================================
# Constraint bypass
# ============================================================


@pytest.mark.parametrize(
    "amount",
    [
        101,
        1000,
        999999,
    ],
)
def test_amount_limit_cannot_be_bypassed(
    amount,
):
    sdk = make_sdk()
    firewall = HTTPFirewall(sdk)

    capability = make_capability(
        sdk,
        constraints={
            "amount_max": 100
        },
    )

    request = make_request(
        sdk,
        capability=capability,
        arguments={
            "amount": amount
        },
    )

    assert (
        firewall.authorize(request).allowed
        is False
    )


def test_nested_constraint_cannot_be_bypassed():
    sdk = make_sdk()
    firewall = HTTPFirewall(sdk)

    capability = make_capability(
        sdk,
        constraints={
            "payment": {
                "amount_max": 100
            }
        },
    )

    request = make_request(
        sdk,
        capability=capability,
        arguments={
            "payment": {
                "amount": 101
            }
        },
    )

    assert (
        firewall.authorize(request).allowed
        is False
    )


def test_constraint_boundary_is_allowed():
    sdk = make_sdk()
    firewall = HTTPFirewall(sdk)

    capability = make_capability(
        sdk,
        constraints={
            "amount_max": 100
        },
    )

    request = make_request(
        sdk,
        capability=capability,
        arguments={
            "amount": 100
        },
    )

    assert (
        firewall.authorize(request).allowed
        is True
    )


# ============================================================
# Expiration
# ============================================================


def test_expired_capability_cannot_execute():
    now = [1000.0]

    sdk = FirewallSDK(
        trusted_issuers={
            "trusted-issuer"
        },
        clock=lambda: now[0],
    )

    firewall = HTTPFirewall(sdk)

    private_key, _ = (
        generate_capability_key_pair()
    )

    capability = sdk.issue(
        private_key=private_key,
        agent="agent-a",
        capability="http.POST.payments",
        issued_at=900,
        expires_at=1100,
    )

    request = make_request(
        sdk,
        capability=capability,
    )

    now[0] = 1200.0

    called = []

    def handler(request):
        called.append(True)

    with pytest.raises(
        HTTPAuthorizationError
    ):
        firewall.execute(
            request,
            handler,
        )

    assert called == []


# ============================================================
# Handler boundary
# ============================================================


def test_invalid_capability_never_reaches_handler():
    sdk = make_sdk()
    firewall = HTTPFirewall(sdk)

    request = HTTPRequest(
        agent="agent-a",
        method="POST",
        path="/payments",
        arguments={},
        capability_token="invalid",
        nonce="handler-boundary",
    )

    called = []

    def handler(request):
        called.append(True)

    with pytest.raises(
        HTTPAuthorizationError
    ):
        firewall.execute(
            request,
            handler,
        )

    assert called == []


def test_constraint_denial_never_reaches_handler():
    sdk = make_sdk()
    firewall = HTTPFirewall(sdk)

    capability = make_capability(
        sdk,
        constraints={
            "amount_max": 10
        },
    )

    request = make_request(
        sdk,
        capability=capability,
        arguments={
            "amount": 11
        },
    )

    called = []

    def handler(request):
        called.append(True)

    with pytest.raises(
        HTTPAuthorizationError
    ):
        firewall.execute(
            request,
            handler,
        )

    assert called == []


# ============================================================
# Header attacks
# ============================================================


def test_missing_authorization_rejected():
    firewall = HTTPFirewall(
        make_sdk()
    )

    with pytest.raises(Exception):
        firewall.from_http(
            agent="agent-a",
            method="POST",
            path="/payments",
            arguments={},
            headers={
                "X-Agent-Nonce": "x"
            },
        )


def test_invalid_bearer_token_rejected():
    firewall = HTTPFirewall(
        make_sdk()
    )

    request = firewall.from_http(
        agent="agent-a",
        method="POST",
        path="/payments",
        arguments={},
        headers={
            "Authorization": "Bearer garbage",
            "X-Agent-Nonce": "x",
        },
    )

    assert (
        firewall.authorize(request).allowed
        is False
    )


def test_empty_bearer_token_rejected():
    firewall = HTTPFirewall(
        make_sdk()
    )

    request = firewall.from_http(
        agent="agent-a",
        method="POST",
        path="/payments",
        arguments={},
        headers={
            "Authorization": "Bearer ",
            "X-Agent-Nonce": "x",
        },
    )

    assert (
        firewall.authorize(request).allowed
        is False
    )


# ============================================================
# Complete adversarial flow
# ============================================================


def test_valid_request_executes_once():
    sdk = make_sdk()
    firewall = HTTPFirewall(sdk)

    request = make_request(
        sdk,
        nonce="once-only",
    )

    calls = []

    def handler(request):
        calls.append(request)
        return "executed"

    assert (
        firewall.execute(
            request,
            handler,
        )
        == "executed"
    )

    with pytest.raises(
        HTTPAuthorizationError
    ):
        firewall.execute(
            request,
            handler,
        )

    assert len(calls) == 1