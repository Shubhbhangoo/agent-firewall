"""v2.4 §15: every integration surface reaches the canonical boundary.

§15 forbids one specific shape of failure: an integration that becomes
``adapter -> local allow`` instead of ``adapter -> canonical
authorization``. Testing that by driving a surface and checking the
verdict is not enough, because a surface that computed the verdict itself
would agree with the pipeline right up until the moment they disagree ---
which is exactly the moment that matters. So these tests attack the
question from three sides:

* **A spy on the boundary.** :class:`_Boundary` wraps
  ``FirewallSDK.authorize`` without changing any decision, so a test can
  assert that a surface's allow was accompanied by exactly one canonical
  call, carrying the action and request that surface claims to be
  authorizing. A surface that decided locally would allow with zero
  calls.
* **A narrowing applied behind the surface's back.** An Aegis constraint
  is installed *after* every wrapper has been constructed, from code the
  wrappers cannot see. Every surface must start denying. A cached or
  locally recomputed allow would survive this and nothing else in the
  suite would notice.
* **A boundary that fails.** With ``authorize`` replaced by something
  that raises, no surface may produce an allow.

The one surface that does not reach the boundary is
:meth:`firewall.a2a.auth.AgentToAgent.authorize` with no ``sdk_provider``
attached, which is how every non-test construction site in the repository
builds it. That is not fixed by making the provider mandatory --- the
class is also a useful relationship registry, and the CLI has no
capability to present --- so it is fixed by making the distinction
impossible to miss: such a decision reports
``basis == BASIS_RELATIONSHIP_ONLY`` and ``is_canonical is False``, and
the CLI that prints it says so in words.

Two further classes pin things §15 turned up on the way. The refusal
*shape* differs per surface --- a decision object from MCP and HTTP, a
``PermissionError`` from every tool wrapper --- and that divergence is
asserted rather than unified, because a caller handling the wrong shape
handles no denial at all. And every wrapper must tag its handler's return
value identically: three adapters authorized correctly and then returned
untagged output, so one handler carried a weaker guarantee behind
``openai_tool`` than behind ``protect_tool``.
"""

from __future__ import annotations

import contextlib
import json
import pathlib
import subprocess
import sys
import time

import pytest

from firewall.a2a import (
    BASIS_CANONICAL,
    BASIS_RELATIONSHIP_ONLY,
    BASIS_UNAVAILABLE,
    AgentToAgent,
)
from firewall.adapters import (
    anthropic_tool,
    generic_tool,
    normalize_tool_call,
    openai_tool,
)
from firewall.agents import PythonAgentAdapter
from firewall.http import HTTPAuthorizationError, HTTPFirewall
from firewall.ident import IdentityRegistry
from firewall.mcp import MCPAuthorizationError, MCPFirewall
from firewall.sdk import FirewallSDK
from firewall.tools import UntrustedString, protect_tool

PY = sys.executable

KEY_ID = "s15-key"
ACTION = "payments.send"
HTTP_METHOD = "POST"
HTTP_PATH = "/payments/send"
HTTP_ACTION = "http.POST.payments.send"
WITHIN = {"amount": 10}
CEILING = {"amount_max": 500}


class _Boundary:
    """Records canonical calls without altering a single decision.

    Installed as an instance attribute, so it shadows the bound method
    for this SDK only and every gate still runs for real. The point is
    not to stub the boundary -- a stubbed boundary would prove nothing
    about whether the real one is reachable -- but to count it.
    """

    def __init__(self, sdk: FirewallSDK) -> None:
        self.sdk = sdk
        self.calls: list[dict] = []
        self._original = sdk.authorize

    def __enter__(self) -> "_Boundary":
        self.sdk.authorize = self  # type: ignore[method-assign]
        return self

    def __exit__(self, *exc_info) -> None:
        try:
            del self.sdk.authorize  # type: ignore[attr-defined]
        except AttributeError:  # pragma: no cover - defensive
            self.sdk.authorize = self._original  # type: ignore[method-assign]

    def __call__(self, capability, action, request=None, **kwargs):
        self.calls.append(
            {
                "action": action,
                "request": dict(request or {}),
                "kwargs": dict(kwargs),
            }
        )
        return self._original(capability, action, request, **kwargs)

    @property
    def actions(self) -> list[str]:
        return [call["action"] for call in self.calls]


class _Broken:
    """A boundary that cannot answer. Nothing may read this as an allow."""

    def __init__(self, sdk: FirewallSDK) -> None:
        self.sdk = sdk
        self._original = sdk.authorize
        self.calls = 0

    def __enter__(self) -> "_Broken":
        self.sdk.authorize = self  # type: ignore[method-assign]
        return self

    def __exit__(self, *exc_info) -> None:
        try:
            del self.sdk.authorize  # type: ignore[attr-defined]
        except AttributeError:  # pragma: no cover - defensive
            self.sdk.authorize = self._original  # type: ignore[method-assign]

    def __call__(self, *args, **kwargs):
        self.calls += 1
        raise RuntimeError("the authorization pipeline is unavailable")


class _Estate:
    """One SDK, one tracked capability, and the handler call log."""

    def __init__(self, action: str = ACTION, *, aegis: bool = True) -> None:
        self.action = action
        self.sdk = FirewallSDK(aegis_enabled=aegis)
        self.private_key = self.sdk.generate_key(KEY_ID).private_key
        self.capability = self.sdk.issue(
            agent="agent-a",
            capability=action,
            private_key=self.private_key,
            constraints=dict(CEILING),
        )
        self.fingerprint = self.sdk.fingerprint(self.capability)
        if aegis:
            self.sdk.aegis.register(
                self.fingerprint, agent_id="agent-a", capability=action
            )
        self.token = self.sdk.encode(self.capability)
        self.log: list[dict] = []
        self._nonce = 0

    def handler(self, **kwargs) -> str:
        self.log.append(dict(kwargs))
        return "handler output"

    def nonce(self) -> str:
        self._nonce += 1
        return f"nonce-{self._nonce}"

    def narrow(self) -> None:
        """Install a ceiling no in-range request can satisfy.

        Applied through the controller, not through any surface: this is
        the change the surfaces are not told about.
        """

        self.sdk.aegis.narrow(
            self.fingerprint,
            key="aegis:s15",
            reason="section 15 probe",
            constraints={"amount_max": 1},
        )

    def close(self) -> None:
        self.sdk.close()


@pytest.fixture()
def estate():
    item = _Estate()
    try:
        yield item
    finally:
        item.close()


@pytest.fixture()
def http_estate():
    item = _Estate(action=HTTP_ACTION)
    try:
        yield item
    finally:
        item.close()


# ======================================================================
# Surface drivers
#
# Each returns a zero-argument callable producing ``(allowed, reason)``,
# so one loop can drive seven surfaces that report a refusal in three
# different ways: MCP and HTTP return a decision object, every tool
# wrapper raises ``PermissionError``. Normalizing that here is what makes
# the cross-surface assertions readable; the surface-specific shape of a
# refusal is pinned separately below.
# ======================================================================


def _outcome(call):
    def run():
        try:
            call()
        except PermissionError as exc:
            return False, str(exc)
        return True, "allowed"

    # The unnormalized call, for the tests whose subject is the shape of
    # the refusal or the tag on the return value rather than the verdict.
    run.raw = call
    return run


def _mcp_surface(estate: _Estate):
    firewall = MCPFirewall(estate.sdk)

    def run():
        decision = firewall.authorize(
            MCPFirewall.request(
                agent="agent-a",
                tool=estate.action,
                arguments=dict(WITHIN),
                capability_token=estate.token,
                nonce=estate.nonce(),
            )
        )
        return decision.allowed, decision.reason

    return run


def _http_surface(estate: _Estate):
    firewall = HTTPFirewall(estate.sdk)

    def run():
        decision = firewall.authorize(
            HTTPFirewall.request(
                agent="agent-a",
                method=HTTP_METHOD,
                path=HTTP_PATH,
                arguments=dict(WITHIN),
                capability_token=estate.token,
                nonce=estate.nonce(),
            )
        )
        return decision.allowed, decision.reason

    return run


def _generic_surface(estate: _Estate):
    adapter = generic_tool(
        sdk=estate.sdk,
        capability=estate.capability,
        handler=estate.handler,
        name=estate.action,
        request_builder=lambda arguments: dict(arguments),
    )
    return _outcome(
        lambda: adapter.execute(
            normalize_tool_call(name=estate.action, arguments=dict(WITHIN))
        )
    )


def _openai_surface(estate: _Estate):
    adapter = openai_tool(
        sdk=estate.sdk,
        capability=estate.capability,
        handler=estate.handler,
        name=estate.action,
        # OpenAI expands the arguments as keywords, where the generic and
        # Anthropic adapters pass one dict. Three wrappers, three calling
        # conventions for one parameter name -- pinned here rather than
        # unified, because unifying it would change every existing caller.
        request_builder=lambda **arguments: dict(arguments),
    )
    return _outcome(lambda: adapter.execute(dict(WITHIN)))


def _anthropic_surface(estate: _Estate):
    adapter = anthropic_tool(
        sdk=estate.sdk,
        capability=estate.capability,
        handler=estate.handler,
        name=estate.action,
        request_builder=lambda arguments: dict(arguments),
    )
    return _outcome(
        lambda: adapter.execute(
            {"name": estate.action, "input": dict(WITHIN)}
        )
    )


def _protect_surface(estate: _Estate):
    tool = protect_tool(
        sdk=estate.sdk,
        capability=estate.capability,
        handler=estate.handler,
        action=estate.action,
        request_builder=lambda **kwargs: dict(kwargs),
    )
    return _outcome(lambda: tool(**WITHIN))


def _agents_surface(estate: _Estate):
    adapter = PythonAgentAdapter(sdk=estate.sdk, agent_id="agent-a")
    protected = adapter.protect(
        estate.handler,
        name=estate.action,
        capability=estate.capability,
        request_builder=lambda arguments: dict(arguments),
    )
    return _outcome(
        lambda: protected(
            normalize_tool_call(name=estate.action, arguments=dict(WITHIN))
        )
    )


#: Surface name -> (action the estate must be issued for, driver).
SURFACES = {
    "mcp": (ACTION, _mcp_surface),
    "http": (HTTP_ACTION, _http_surface),
    "generic_tool": (ACTION, _generic_surface),
    "openai_tool": (ACTION, _openai_surface),
    "anthropic_tool": (ACTION, _anthropic_surface),
    "protect_tool": (ACTION, _protect_surface),
    "agents.protect": (ACTION, _agents_surface),
}

#: The surfaces that own a handler and return its output. These refuse by
#: raising ``PermissionError`` and are the only ones that can be asked
#: what the handler's return value carries.
WRAPPERS = sorted(name for name in SURFACES if name not in {"mcp", "http"})


@contextlib.contextmanager
def _surface(name: str):
    action, build = SURFACES[name]
    item = _Estate(action=action)
    try:
        yield item, build(item)
    finally:
        item.close()


class TestEverySurfaceReachesTheCanonicalBoundary:
    """An allow is accompanied by exactly one canonical call."""

    @pytest.mark.parametrize("name", sorted(SURFACES))
    def test_an_allow_came_from_the_pipeline(self, name):
        with _surface(name) as (estate, run):
            with _Boundary(estate.sdk) as boundary:
                allowed, reason = run()

            assert allowed is True, reason
            assert len(boundary.calls) == 1, boundary.calls
            assert boundary.actions == [estate.action]

    @pytest.mark.parametrize("name", sorted(SURFACES))
    def test_the_authorized_request_is_the_one_that_ran(self, name):
        """The surface must not authorize A and then execute B.

        Every wrapper here is bound to a single action at construction,
        so the interesting failure is not tool substitution but a request
        body that differs between the check and the call -- authorizing an
        empty request and then passing the real arguments through.
        """

        with _surface(name) as (estate, run):
            with _Boundary(estate.sdk) as boundary:
                allowed, reason = run()

            assert allowed is True, reason
            assert boundary.calls[0]["request"]["amount"] == WITHIN["amount"]

    def test_the_console_decision_path_reaches_the_same_boundary(self, estate):
        """The developer console's only decision path is North Star.

        ``firewall.ui`` renders; where it decides, it decides through
        ``authorize_north_star``, which is a wrapper and not a second
        engine -- so it must show up on the same counter.
        """

        with _Boundary(estate.sdk) as boundary:
            decision = estate.sdk.authorize_north_star(
                estate.capability, estate.action, dict(WITHIN)
            )

        assert decision.allowed is True, decision.reason
        assert len(boundary.calls) == 1, boundary.calls
        assert boundary.actions == [estate.action]


class TestNoSurfaceComputesItsOwnAllow:
    """A narrowing installed behind the surface's back must land.

    This is the test that a locally computed allow cannot pass. Nothing
    about the request changes, nothing about the capability changes, and
    the wrapper object is the same one that just allowed. The only thing
    that changed is Aegis state, reached through the controller --- a
    module none of these surfaces imports.
    """

    @pytest.mark.parametrize("name", sorted(SURFACES))
    def test_an_aegis_narrowing_denies_through_the_surface(self, name):
        with _surface(name) as (estate, run):
            allowed, reason = run()
            assert allowed is True, reason

            estate.narrow()

            allowed, reason = run()
            assert allowed is False, "the surface kept allowing after a narrowing"
            assert "aegis_constraint_denied" in reason, reason

    @pytest.mark.parametrize("name", sorted(SURFACES))
    def test_a_revocation_denies_through_the_surface(self, name):
        """Revocation is the other direction the surfaces must inherit."""

        with _surface(name) as (estate, run):
            allowed, reason = run()
            assert allowed is True, reason

            estate.sdk.revoke(estate.capability, reason="section 15")

            allowed, reason = run()
            assert allowed is False, "the surface kept allowing after revocation"

    @pytest.mark.parametrize("name", WRAPPERS)
    def test_a_denied_call_never_enters_the_handler(self, name):
        """Only the wrappers that own a handler can be asked this."""

        with _surface(name) as (estate, run):
            estate.narrow()

            allowed, reason = run()

            assert allowed is False, reason
            assert estate.log == [], "the handler ran under a denial"


class TestAnUnreachableBoundaryIsNotAnAllow:
    """With ``authorize`` raising, no surface may report an allow.

    The surfaces disagree about *how* they refuse and that disagreement
    is pinned rather than smoothed over: MCP catches the exception and
    returns a denial, everything else lets it propagate. Both are
    fail-closed, because neither produces an allow and neither reaches a
    handler. What would not be fail-closed is a surface that treated an
    unreachable pipeline as an absent objection.
    """

    @pytest.mark.parametrize("name", sorted(SURFACES))
    def test_no_allow_survives_a_broken_boundary(self, name):
        with _surface(name) as (estate, run):
            with _Broken(estate.sdk) as broken:
                try:
                    allowed, reason = run()
                except Exception as exc:  # noqa: BLE001 - shape is the subject
                    allowed, reason = False, f"raised {type(exc).__name__}"

            assert allowed is False, reason
            assert broken.calls >= 1, "the surface never asked"
            assert estate.log == [], "the handler ran without a decision"

    def test_mcp_converts_an_unreachable_boundary_into_a_denial(self, estate):
        firewall = MCPFirewall(estate.sdk)
        request = MCPFirewall.request(
            agent="agent-a",
            tool=estate.action,
            arguments=dict(WITHIN),
            capability_token=estate.token,
            nonce=estate.nonce(),
        )

        with _Broken(estate.sdk):
            decision = firewall.authorize(request)

        assert decision.allowed is False
        assert decision.reason == "authorization error"

    def test_http_lets_an_unreachable_boundary_propagate(self, http_estate):
        """Documented divergence from MCP, not a defect in either.

        A raised exception becomes a 5xx in any HTTP framework, which is
        a refusal; converting it to a 403 here would relabel "the
        firewall broke" as "the request was not permitted".
        """

        firewall = HTTPFirewall(http_estate.sdk)
        request = HTTPFirewall.request(
            agent="agent-a",
            method=HTTP_METHOD,
            path=HTTP_PATH,
            arguments=dict(WITHIN),
            capability_token=http_estate.token,
            nonce=http_estate.nonce(),
        )

        with _Broken(http_estate.sdk):
            with pytest.raises(RuntimeError):
                firewall.authorize(request)


class TestTheShapeOfARefusalIsSurfaceSpecific:
    """Seven surfaces, three refusal shapes --- pinned, not unified.

    A caller who handles the wrong shape handles no denial at all: code
    that expects a falsy return from ``protect_tool`` never sees the
    ``PermissionError``, and code that expects a raise from
    ``MCPFirewall.authorize`` reads a denial object as a success. So each
    shape is asserted rather than smoothed over, and a refactor cannot
    quietly move a surface from one shape to another.

    ``§15`` is satisfied by every one of these: a refusal in any shape is
    a refusal. What ``§15`` forbids is an *allow* the pipeline did not
    make, which is what the three classes above are about.
    """

    @pytest.mark.parametrize("name", WRAPPERS)
    def test_a_tool_wrapper_raises_permission_error(self, name):
        with _surface(name) as (estate, run):
            estate.narrow()

            with pytest.raises(PermissionError) as caught:
                run.raw()

            assert "aegis_constraint_denied" in str(caught.value)

    def test_mcp_authorize_returns_a_denial_and_enforce_raises(self, estate):
        firewall = MCPFirewall(estate.sdk)
        estate.narrow()

        def request():
            return MCPFirewall.request(
                agent="agent-a",
                tool=estate.action,
                arguments=dict(WITHIN),
                capability_token=estate.token,
                nonce=estate.nonce(),
            )

        decision = firewall.authorize(request())
        assert decision.allowed is False
        assert "aegis_constraint_denied" in decision.reason

        with pytest.raises(MCPAuthorizationError):
            firewall.enforce(request())

    def test_http_maps_an_aegis_denial_to_403(self, http_estate):
        """403, not 401: the credential is fine, the authority is not.

        The distinction is load-bearing for any client that retries on
        401 --- re-presenting the same token would not help here, and a
        401 would tell it to try.
        """

        firewall = HTTPFirewall(http_estate.sdk)
        http_estate.narrow()

        decision = firewall.authorize(
            HTTPFirewall.request(
                agent="agent-a",
                method=HTTP_METHOD,
                path=HTTP_PATH,
                arguments=dict(WITHIN),
                capability_token=http_estate.token,
                nonce=http_estate.nonce(),
            )
        )

        assert decision.allowed is False
        assert decision.status_code == 403
        assert "aegis_constraint_denied" in decision.reason

    def test_http_refuses_an_expired_token_before_the_boundary(self):
        """401, and the pipeline is never consulted --- both are correct.

        ``§15`` is asymmetric, and this is the test that says so. A
        surface is free to refuse on its own: ``decode_verified`` rejects
        an expired capability outright, so the request is answered 401
        with ``boundary.calls == []``. What a surface may never do is
        *allow* on its own. Local deny plus canonical allow is the shape
        the section requires; the reverse would be the violation.

        A consequence worth pinning: because the decode step refuses
        first, an expired token cannot reach ``_gate_time`` through HTTP
        at all. ``sdk.authorize()`` on the same capability object still
        answers ``"expired"``, which is where the reason-to-401 mapping
        at :mod:`firewall.http` gets its input --- reachable only if a
        capability decodes and then expires before the time gate runs.
        """

        estate = _Estate(action=HTTP_ACTION)
        try:
            expired = estate.sdk.issue(
                agent="agent-a",
                capability=HTTP_ACTION,
                private_key=estate.private_key,
                constraints=dict(CEILING),
                issued_at=time.time() - 120,
                expires_at=time.time() - 60,
            )
            firewall = HTTPFirewall(estate.sdk)
            request = HTTPFirewall.request(
                agent="agent-a",
                method=HTTP_METHOD,
                path=HTTP_PATH,
                arguments=dict(WITHIN),
                capability_token=estate.sdk.encode(expired),
                nonce=estate.nonce(),
            )

            with _Boundary(estate.sdk) as boundary:
                decision = firewall.authorize(request)

            assert decision.allowed is False
            assert decision.status_code == 401
            assert "invalid capability" in decision.reason
            assert boundary.calls == [], "a dead token reached the pipeline"

            # The same capability, asked directly: the time gate is what
            # would have refused it, had decode let it through.
            direct = estate.sdk.authorize(expired, HTTP_ACTION, dict(WITHIN))
            assert direct.allowed is False
            assert direct.reason == "expired"
        finally:
            estate.close()

    def test_http_enforce_raises(self, http_estate):
        firewall = HTTPFirewall(http_estate.sdk)
        http_estate.narrow()

        with pytest.raises(HTTPAuthorizationError):
            firewall.enforce(
                HTTPFirewall.request(
                    agent="agent-a",
                    method=HTTP_METHOD,
                    path=HTTP_PATH,
                    arguments=dict(WITHIN),
                    capability_token=http_estate.token,
                    nonce=http_estate.nonce(),
                )
            )


class TestAdapterOutputIsUntrustedEverywhere:
    """Five wrappers, one taint guarantee. Regression for a real gap.

    All three vendor adapters built a :class:`ProtectedTool` and then
    called ``self.tool.handler(...)`` directly, stepping around the
    ``mark_untrusted`` that ``ProtectedTool.__call__`` applies. The
    result was that one handler returned an ``UntrustedString`` behind
    ``protect_tool`` and a bare ``str`` behind ``openai_tool`` --- one
    name, two guarantees, which is the defect class this release keeps
    finding. Tool output is untrusted data whichever wrapper authorized
    it, so the tag is asserted for all five together rather than per
    adapter.
    """

    @pytest.mark.parametrize("name", WRAPPERS)
    def test_the_handler_return_value_is_tagged(self, name):
        with _surface(name) as (estate, run):
            output = run.raw()

            assert isinstance(output, UntrustedString), type(output)
            assert output == "handler output"
            assert output.tool == estate.action

    def test_every_wrapper_tags_it_the_same_way(self):
        """The point is the absence of variation, so compare directly."""

        seen = {}
        for name in WRAPPERS:
            with _surface(name) as (estate, run):
                output = run.raw()
                seen[name] = (type(output).__name__, output.tool, str(output))

        assert len(set(seen.values())) == 1, seen


# ======================================================================
# The one surface that does not reach the boundary
# ======================================================================


@contextlib.contextmanager
def _mesh(sdk_provider=None):
    """A two-agent mesh with an active relationship covering ``ACTION``.

    Built the way :func:`firewall.cli_v21._a2a` builds it when
    ``sdk_provider`` is left ``None`` --- which is every non-test
    construction site in the repository.
    """

    identities = IdentityRegistry()
    for agent in ("agent-a", "agent-b"):
        identities.create(agent)

    item = AgentToAgent(identities, sdk_provider=sdk_provider)
    try:
        item.establish(
            initiator="agent-a",
            responder="agent-b",
            permissions={"allowed_actions": [ACTION]},
        )
        yield item
    finally:
        item.close()
        identities.close()


def _ask(mesh):
    return mesh.authorize(actor="agent-a", target="agent-b", action=ACTION)


class TestTheMeshAllowSaysWhatEstablishedIt:
    """Regression for the §15 finding. An allow must name its basis.

    ``AgentToAgent.authorize`` can allow without consulting the
    pipeline, because the class is also a relationship registry and the
    provider is optional. That is defensible; what was not defensible was
    that both kinds of allow were byte-identical --- ``basis`` existed and
    was never varied, so no caller could tell a relayed
    ``FirewallSDK.authorize()`` decision from local bookkeeping. The fix
    is not to forbid the unwired allow but to make it impossible to
    mistake for the other one.
    """

    def test_an_unwired_allow_is_not_canonical(self):
        with _mesh() as mesh:
            decision = _ask(mesh)

        assert decision.allowed is True
        assert decision.is_canonical is False
        assert decision.basis == BASIS_RELATIONSHIP_ONLY
        assert "no authorization pipeline was consulted" in decision.reason

    def test_a_wired_allow_is_canonical(self):
        calls = []

        def provider(actor, target, action, request):
            calls.append((actor, target, action, dict(request)))
            return True, "pipeline allowed"

        with _mesh(sdk_provider=provider) as mesh:
            decision = _ask(mesh)

        assert decision.allowed is True
        assert decision.is_canonical is True
        assert decision.basis == BASIS_CANONICAL
        assert calls == [("agent-a", "agent-b", ACTION, {})]

    def test_a_wired_denial_is_canonical_too(self):
        """A relayed deny is as canonical as a relayed allow.

        Only the *allow* is dangerous to mislabel, but labelling the deny
        ``relationship_only`` would be equally untrue and would make the
        field mean "allow provenance" rather than "decision provenance".
        """

        with _mesh(sdk_provider=lambda *a: (False, "pipeline denied")) as mesh:
            decision = _ask(mesh)

        assert decision.allowed is False
        assert decision.is_canonical is True
        assert decision.basis == BASIS_CANONICAL
        assert decision.reason == "pipeline denied"

    def test_a_provider_that_raises_denies_and_claims_nothing(self):
        """Fail closed, and do not claim a basis nothing produced.

        ``BASIS_UNAVAILABLE`` is the honest third answer: the pipeline was
        asked and did not answer, so the decision is a denial that must
        not describe itself as canonical.
        """

        def provider(*args):
            raise RuntimeError("boom")

        with _mesh(sdk_provider=provider) as mesh:
            decision = _ask(mesh)

        assert decision.allowed is False
        assert decision.is_canonical is False
        assert decision.basis == BASIS_UNAVAILABLE
        assert "authorization provider error" in decision.reason
        assert "RuntimeError" in decision.reason

    def test_a_local_denial_never_claims_a_canonical_basis(self):
        """Steps 1--3 can only deny, and they say so.

        An unrelated action is refused by the local permission check
        without the provider ever running, so the basis must stay
        ``relationship_only`` even when a provider is attached.
        """

        calls = []

        def provider(*args):
            calls.append(args)
            return True, "pipeline allowed"

        with _mesh(sdk_provider=provider) as mesh:
            decision = mesh.authorize(
                actor="agent-a", target="agent-b", action="unrelated.action"
            )

        assert decision.allowed is False
        assert decision.basis == BASIS_RELATIONSHIP_ONLY
        assert decision.is_canonical is False
        assert calls == [], "a locally refused action reached the provider"

    def test_the_distinction_survives_serialization(self):
        """``to_dict`` is how the CLI and any transport see a decision.

        A distinction that exists only on the Python object is a
        distinction no JSON consumer can act on.
        """

        with _mesh() as mesh:
            unwired = _ask(mesh).to_dict()
        with _mesh(sdk_provider=lambda *a: (True, "ok")) as mesh:
            wired = _ask(mesh).to_dict()

        assert unwired["allowed"] is True and wired["allowed"] is True
        assert unwired["basis"] == BASIS_RELATIONSHIP_ONLY
        assert unwired["is_canonical"] is False
        assert wired["basis"] == BASIS_CANONICAL
        assert wired["is_canonical"] is True

        # The failure this guards: two allows that serialize identically.
        assert unwired != wired
        assert json.loads(json.dumps(unwired))["is_canonical"] is False


class TestTheMeshCLIDoesNotPrintABareAllow:
    """The shipped command was the reason the finding mattered.

    ``firewall delegate authorize`` builds its mesh at
    :func:`firewall.cli_v21._a2a` with no ``sdk_provider``, so it printed
    ``ALLOWED`` and exited 0 for a decision the pipeline never made. The
    field on the dataclass is only half a fix; a human reading a terminal
    and a script reading ``--json`` both have to be told.

    Exit status is deliberately still 0. The question the command asks is
    "does the relationship permit this", and the answer really is yes ---
    what changed is that the answer stops overstating itself. Turning it
    into a nonzero exit would break
    ``test_v2_1_integration.py::TestDelegateCLI`` for no security gain,
    and §25/§28 rule that out.
    """

    @staticmethod
    def _cli(*args, cwd):
        return subprocess.run(
            [PY, "-m", "firewall.cli", *args],
            capture_output=True,
            text=True,
            cwd=cwd,
        )

    @pytest.fixture()
    def session(self, tmp_path):
        """Identities plus one established relationship, via the CLI only.

        Driving setup through the CLI rather than the library is the
        point: the subject is what the shipped command prints, so the
        state it prints about has to come from the shipped command too.
        """

        root = str(pathlib.Path(__file__).resolve().parents[1])
        registry = str(tmp_path / "identities.json")
        state = str(tmp_path / "a2a.json")

        for agent in ("alice", "bob"):
            result = self._cli(
                "identity", "create", agent, "--registry", registry, cwd=root
            )
            assert result.returncode == 0, result.stderr

        established = self._cli(
            "delegate", "establish",
            "--registry", registry, "--state", state,
            "--initiator", "alice", "--responder", "bob",
            "--permissions", json.dumps({"allowed_actions": ["read"]}),
            cwd=root,
        )
        assert established.returncode == 0, established.stderr

        def run(*args):
            return self._cli(
                "delegate", "authorize",
                "--registry", registry, "--state", state,
                "--actor", "alice", "--target", "bob",
                *args,
                cwd=root,
            )

        return run

    def test_the_allow_is_qualified_in_words(self, session):
        result = session("--action", "read")
        # The advisory wraps across two printed lines; the sentence is
        # the subject, not the line breaks.
        flat = " ".join(result.stdout.split())

        assert result.returncode == 0, result.stderr
        assert "ALLOWED (relationship only)" in result.stdout
        assert "basis: relationship_only" in flat
        assert "this is a relationship check, not an authorization." in flat
        assert "do not enforce on this result" in flat
        assert "No FirewallSDK.authorize() decision was made" in flat

    def test_the_json_output_carries_the_distinction(self, session):
        result = session("--action", "read", "--json")

        assert result.returncode == 0, result.stderr
        payload = json.loads(result.stdout)
        assert payload["allowed"] is True
        assert payload["is_canonical"] is False
        assert payload["basis"] == BASIS_RELATIONSHIP_ONLY

    def test_a_denial_is_unqualified_and_exits_nonzero(self, session):
        """No qualifier on a deny: there is nothing to overstate.

        This also pins the exit-code contract the existing v2.1 suite
        depends on --- 1 for a refusal, 0 for an allow of either basis.
        """

        result = session("--action", "admin")

        assert result.returncode == 1
        assert "DENIED" in result.stdout
        assert "relationship only" not in result.stdout
        assert "basis:" not in result.stdout

    def test_the_v2_1_contract_still_holds(self, session):
        """Verbatim the assertions ``test_v2_1_integration`` makes.

        Restated here so that anyone tempted to change the exit status or
        drop the word ``ALLOWED`` sees both constraints in one place.
        """

        allow = session("--action", "read")
        assert allow.returncode == 0
        assert "ALLOWED" in allow.stdout

        deny = session("--action", "admin")
        assert deny.returncode == 1
