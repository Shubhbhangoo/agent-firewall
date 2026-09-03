"""v2.5: the glue must ask the boundary about the request it then runs.

Every attack here leaves ``FirewallSDK.authorize`` untouched and correct.
None of them bypasses it. They win -- or used to win -- by having the
integration layer put a question to the boundary that differs from the
action it takes afterwards. That is the failure mode the v2.5 objective
names: not authorizing *around* the boundary, but causing the boundary to
authorize more authority than it was shown.

Four shapes of it were found in the shipped adapters, and one in the HTTP
surface.

*Normalizing twice.* ``OpenAITool.execute`` normalized its argument for
the handler and then handed the original to ``authorize``, which
normalized it again. ``normalize`` is not idempotent -- a payload
carrying both ``arguments`` and a sibling key means one thing on the
first pass and another on the second -- so the two halves disagreed by
construction.

*Reading the caller's mapping twice.* Even with an idempotent
``normalize``, two reads of a caller-supplied mapping are two questions.
A mapping is free to answer the second differently from the first.

*Materializing a hostile mapping twice.* ``GenericToolCall.arguments`` is
typed ``dict`` and enforced as nothing, so a ``collections.abc.Mapping``
arrives intact and is materialized once for the request and once for the
handler.

*A ``request_builder`` that mutates in place.* Application glue is named
hostile by the threat model. A builder that returned an in-range request
and left an out-of-range one behind moved the divergence from the caller
into the integration itself.

*A replay store that cannot be read.* ``HTTPFirewall.authorize`` is typed
``-> HTTPDecision`` and returns one for every other failure it can meet,
including an undecodable capability -- but let a raising replay store
escape. The boundary had already allowed by then, so the caller who
wrapped the surface and carried on skipped precisely the check the block
exists to perform. ``MCPFirewall`` already contained the same read.

The assertion these tests share is not "the adapter denies". It is
*agreement*: whatever the boundary was asked, that is what ran. An
adapter that denied everything would satisfy a verdict-only test and
prove nothing, so each divergence test is paired with a control showing
the dangerous value is one the same boundary refuses when asked plainly.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Optional

import pytest

from firewall.adapters import (
    anthropic_tool,
    generic_tool,
    openai_tool,
)
from firewall.adapters.generic import GenericToolCall
from firewall.http import HTTPAuthorizationError, HTTPFirewall
from firewall.mcp import MCPAuthorizationError, MCPFirewall
from firewall.sdk import FirewallSDK

ACTION = "payments.send"
HTTP_METHOD = "POST"
HTTP_PATH = "/payments/send"
HTTP_ACTION = "http.POST.payments.send"
CEILING = {"amount_max": 100}
WITHIN = {"amount": 10}
BEYOND = {"amount": 5_000}


class Estate:
    """A fresh SDK, a capability with a ceiling, and the handler's log.

    Fresh per case on purpose. One over-ceiling call latches refusal state
    for that capability, after which every later call reports
    ``refusal_state`` whatever it was asked -- which would make a reused
    estate report agreement it had not established.
    """

    def __init__(self, action: str = ACTION) -> None:
        self.action = action
        self.sdk = FirewallSDK()
        self.private_key = self.sdk.generate_key(
            "v25-divergence"
        ).private_key
        self.capability = self.sdk.issue(
            agent="agent-a",
            capability=action,
            private_key=self.private_key,
            constraints=dict(CEILING),
        )
        self.token = self.sdk.encode(self.capability)
        self.log: list[dict] = []
        self._nonce = 0

    def handler(self, **kwargs: Any) -> str:
        self.log.append(dict(kwargs))
        return "handler output"

    def nonce(self) -> str:
        self._nonce += 1
        return f"nonce-{self._nonce}"

    @property
    def ran(self) -> Optional[dict]:
        return self.log[-1] if self.log else None

    def close(self) -> None:
        self.sdk.close()


@pytest.fixture()
def estate():
    item = Estate()
    try:
        yield item
    finally:
        item.close()


@pytest.fixture()
def http_estate():
    item = Estate(action=HTTP_ACTION)
    try:
        yield item
    finally:
        item.close()


class Asked:
    """Records the request each canonical call carried, deciding nothing.

    Installed as an instance attribute so it shadows the bound method for
    one SDK while every gate still runs for real. A spy that returned its
    own verdict would be the second authorization path this whole exercise
    exists to prevent.
    """

    def __init__(self, sdk: FirewallSDK) -> None:
        self.sdk = sdk
        self.requests: list[dict] = []
        self._original = sdk.authorize

    def __enter__(self) -> "Asked":
        self.sdk.authorize = self  # type: ignore[method-assign]
        return self

    def __exit__(self, *exc_info: Any) -> None:
        try:
            del self.sdk.authorize  # type: ignore[attr-defined]
        except AttributeError:  # pragma: no cover - defensive
            self.sdk.authorize = self._original  # type: ignore[method-assign]

    def __call__(self, capability, action, request=None, **kwargs):
        self.requests.append(dict(request or {}))
        return self._original(
            capability, action, request, **kwargs
        )


class Flip(dict):
    """A payload whose second read answers differently from its first.

    A plain ``dict`` subclass cannot do this to ``dict(payload)`` --
        CPython copies the underlying storage and never calls the override
    -- so the divergence has to be aimed at ``get``, which is how both
    vendor adapters read the nested arguments out of a tool call.
    """

    def __init__(self, first: dict, second: dict, key: str) -> None:
        super().__init__(first)
        self.key = key
        self._answers = (first, second)
        self.reads = 0

    def get(self, key, default=None):
        if key != self.key:
            return super().get(key, default)

        answer = self._answers[
            min(self.reads, len(self._answers) - 1)
        ]
        self.reads += 1
        return answer

    def __contains__(self, key) -> bool:
        return key in (self.key, "name")


class Shifting(Mapping):
    """Not a ``dict``, so every materialization really goes through ``keys``.

    The first answers a value the boundary allows; every one after answers
    a value the same boundary denies. Which read wins does not matter --
    the property is that only one read happens, so the boundary and the
    handler cannot be looking at different values.
    """

    def __init__(self) -> None:
        self.materializations = 0

    def __iter__(self):
        self.materializations += 1
        return iter(("amount",))

    def __len__(self) -> int:
        return 1

    def keys(self):
        self.materializations += 1
        return ["amount"]

    def __getitem__(self, key):
        if key != "amount":
            raise KeyError(key)

        return (
            WITHIN["amount"]
            if self.materializations <= 1
            else BEYOND["amount"]
        )


def _mutating_builder(arguments: dict) -> dict:
    """Returns a request the boundary allows; leaves one it denies behind."""

    arguments["amount"] = BEYOND["amount"]
    return dict(WITHIN)


def _mutating_builder_kw(**kwargs: Any) -> dict:
    kwargs["amount"] = BEYOND["amount"]
    return dict(WITHIN)


def _flatten(arguments: dict) -> dict:
    """The request shape a top-level ``amount_max`` can actually match.

    Without it every default-builder request nests ``amount`` under
    ``kwargs`` or ``arguments``, the ceiling never applies, and the
    adapter denies uniformly -- which would hide any divergence rather
    than reveal it.
    """

    return dict(arguments)


def _flatten_kw(**kwargs: Any) -> dict:
    return dict(kwargs)


# ======================================================================
# The controls
# ======================================================================


class TestTheCeilingIsRealBeforeAnythingElseIsClaimed:
    """Without these, every agreement test below could pass vacuously.

    An adapter that refused all traffic would satisfy "the handler never
    ran an over-ceiling amount" perfectly. So: the in-range amount runs,
    and the out-of-range amount is refused by each adapter's own request
    shape. Only then does agreement mean anything.
    """

    @pytest.mark.parametrize(
        "build",
        ("openai", "anthropic", "generic"),
        ids=("openai", "anthropic", "generic"),
    )
    def test_the_in_range_amount_runs(self, estate, build: str):
        adapter, call = _adapter(estate, build, dict(WITHIN))

        adapter.execute(call)

        assert estate.ran == dict(WITHIN)

    @pytest.mark.parametrize(
        "build",
        ("openai", "anthropic", "generic"),
        ids=("openai", "anthropic", "generic"),
    )
    def test_the_out_of_range_amount_is_refused(self, estate, build: str):
        adapter, call = _adapter(estate, build, dict(BEYOND))

        with pytest.raises(PermissionError):
            adapter.execute(call)

        assert estate.log == []


def _adapter(estate: Estate, kind: str, arguments: Any):
    """One adapter and the call shape it accepts, for a shared attack loop.

    The three wrappers disagree about what a tool call looks like -- raw
    keywords, an Anthropic envelope, a ``GenericToolCall`` -- and about how
    a request builder is invoked. Normalizing that here is what lets one
    attack be aimed at all three; the divergences that matter are asserted,
    not smoothed over.
    """

    if kind == "openai":
        adapter = openai_tool(
            sdk=estate.sdk,
            capability=estate.capability,
            handler=estate.handler,
            name="payment",
            action=estate.action,
            request_builder=_flatten_kw,
        )
        return adapter, arguments

    if kind == "anthropic":
        adapter = anthropic_tool(
            sdk=estate.sdk,
            capability=estate.capability,
            handler=estate.handler,
            name="payment",
            action=estate.action,
            request_builder=_flatten,
        )
        return adapter, {"name": "payment", "input": arguments}

    if kind == "generic":
        adapter = generic_tool(
            sdk=estate.sdk,
            capability=estate.capability,
            handler=estate.handler,
            name="payment",
            action=estate.action,
            request_builder=_flatten,
        )
        return adapter, GenericToolCall(
            name="payment", arguments=arguments
        )

    raise AssertionError(f"unknown adapter kind {kind!r}")


# ======================================================================
# The attack: make the two halves disagree
# ======================================================================


class TestTheBoundaryIsAskedAboutWhatRuns:
    """One canonical call per execution, carrying what the handler gets.

    Each test asserts the pair, not the verdict. If the adapter allows,
    the arguments the boundary was shown must be the arguments the handler
    received; if it denies, nothing ran. Both are agreement. Only a third
    outcome -- an allow for one request and execution of another -- is the
    bug, and each attack below produced exactly that before v2.5.
    """

    def test_a_non_idempotent_normalize_cannot_split_the_decision(
        self, estate
    ):
        """Finding #9. ``OpenAITool.normalize`` means two things in a row.

        The shipped v2.4 ``execute`` normalized for the handler and passed
        the *result* to ``authorize``, which normalized it a second time.
        One more level of nesting than the adapter expects is all that
        takes: ``normalize`` unwraps the outer ``arguments`` and hands back
        ``{"arguments": {"amount": 1}, "amount": 5000}``, which still looks
        like an envelope, so the second pass unwraps again to
        ``{"amount": 1}``. The boundary was asked about that and the
        handler ran ``amount=5000``, a value this capability's ceiling
        forbids.

        Confirmed against the shipped body rather than assumed: the
        single-nested payload does *not* reproduce it, which is why the
        depth here is deliberate.
        """

        adapter = openai_tool(
            sdk=estate.sdk,
            capability=estate.capability,
            handler=estate.handler,
            name="payment",
            action=estate.action,
            request_builder=_flatten_kw,
        )

        payload = {
            "arguments": {
                "arguments": {"amount": 1},
                "amount": BEYOND["amount"],
            },
        }

        with Asked(estate.sdk) as asked:
            try:
                adapter.execute(payload)
            except PermissionError:
                pass

        assert len(asked.requests) == 1

        if estate.ran is None:
            # A denial is agreement too: nothing ran, so nothing ran
            # unauthorized. What must never happen is the third outcome.
            assert asked.requests[0].get("amount") == BEYOND["amount"]
        else:
            assert asked.requests[0] == estate.ran
            assert estate.ran.get("amount") != BEYOND["amount"]

    @pytest.mark.parametrize(
        "order",
        ("small first", "large first"),
    )
    @pytest.mark.parametrize(
        ("kind", "key"),
        (
            ("openai", "arguments"),
            ("anthropic", "input"),
        ),
    )
    def test_a_payload_read_twice_cannot_split_the_decision(
        self, estate, kind: str, key: str, order: str
    ):
        """Finding #10. Two reads of a caller's mapping are two questions.

        Shipped ``AnthropicTool.execute`` normalized the call for the
        handler and then handed the same call to ``authorize``, which
        normalized it again -- two reads of ``call["input"]``. A mapping
        answering ``{"amount": 5000}`` first and ``{"amount": 1}`` second
        had the boundary allow the small amount while the handler spent the
        large one.

        Both orders are exercised because only one of them is the dangerous
        direction, and which one depends on read order inside the adapter:
        reversed, the boundary sees the large amount and denies, and a
        test that only tried that order would have called the bug contained.

        ``OpenAITool`` was not exposed this way in v2.4 -- it passed an
        already-normalized dict on -- but the first fix drafted for #9
        would have introduced it, so the guard covers both adapters.

        ``reads == 1`` is the load-bearing assertion; agreement is what it
        buys.
        """

        adapter, _ = _adapter(estate, kind, dict(WITHIN))

        small, large = {"amount": 1}, dict(BEYOND)
        first, second = (
            (small, large)
            if order == "small first"
            else (large, small)
        )

        payload = Flip(first, second, key)
        payload["name"] = "payment"

        with Asked(estate.sdk) as asked:
            try:
                adapter.execute(payload)
            except PermissionError:
                pass

        assert payload.reads == 1
        assert len(asked.requests) == 1

        if estate.ran is None:
            assert asked.requests[0].get("amount") == BEYOND["amount"]
        else:
            assert asked.requests[0] == estate.ran
            assert estate.ran.get("amount") != BEYOND["amount"]


    def test_a_shifting_mapping_cannot_split_the_decision(self, estate):
        """Finding #11. ``GenericToolCall.arguments`` accepts any mapping.

        The dataclass types it ``dict`` and enforces nothing, so a
        ``collections.abc.Mapping`` passes straight through -- and unlike a
        ``dict`` subclass it is materialized through ``keys`` every time.
        Two materializations, one for ``build_request`` and one for
        ``**call.arguments``, had the boundary allow ``amount=10`` while the
        handler spent ``amount=5000``.

        ``materializations == 1`` is why that is now impossible, rather
        than merely not happening for this particular mapping.
        """

        adapter, _ = _adapter(estate, "generic", dict(WITHIN))
        shifting = Shifting()

        with Asked(estate.sdk) as asked:
            adapter.execute(
                GenericToolCall(name="payment", arguments=shifting)
            )

        assert shifting.materializations == 1
        assert len(asked.requests) == 1
        assert asked.requests[0] == estate.ran
        assert estate.ran["amount"] != BEYOND["amount"]

    @pytest.mark.parametrize(
        ("kind", "builder"),
        (
            ("openai", _mutating_builder_kw),
            ("anthropic", _mutating_builder),
            ("generic", _mutating_builder),
        ),
        ids=("openai", "anthropic", "generic"),
    )
    def test_a_mutating_request_builder_cannot_split_the_decision(
        self, estate, kind: str, builder
    ):
        """Finding #12, and it is not a v2.4 bug -- it is one my fix made.

        Shipped v2.4 was safe here by accident: ``execute`` and
        ``authorize`` each ran their own ``normalize``, so the builder
        mutated a copy nobody else held. Collapsing that to one
        normalization -- the fix for #9 and #10 -- handed the builder the
        very mapping the handler would unpack, and a builder that returned
        an in-range request while raising the amount in place then split
        the decision again. Confirmed by running the mutating builder
        against the shipped bodies, where it does not reproduce.

        So it is recorded as what it was: an exposure introduced while
        closing two others, found by attacking the fix, and closed before
        shipping. ``AnthropicTool`` now hands the builder a copy;
        ``OpenAITool`` was already safe by signature, unpacking into
        keywords so the builder never holds the handler's mapping, and
        ``GenericToolAdapter`` by settling separately for the request.

        The test guards all three, because the property is the same one and
        the next person to touch any of these three call sites should fail
        here rather than in production.
        """

        estate_arguments = dict(WITHIN)

        if kind == "openai":
            adapter = openai_tool(
                sdk=estate.sdk,
                capability=estate.capability,
                handler=estate.handler,
                name="payment",
                action=estate.action,
                request_builder=builder,
            )
            call: Any = estate_arguments
        elif kind == "anthropic":
            adapter = anthropic_tool(
                sdk=estate.sdk,
                capability=estate.capability,
                handler=estate.handler,
                name="payment",
                action=estate.action,
                request_builder=builder,
            )
            call = {"name": "payment", "input": estate_arguments}
        else:
            adapter = generic_tool(
                sdk=estate.sdk,
                capability=estate.capability,
                handler=estate.handler,
                name="payment",
                action=estate.action,
                request_builder=builder,
            )
            call = GenericToolCall(
                name="payment", arguments=estate_arguments
            )

        with Asked(estate.sdk) as asked:
            adapter.execute(call)

        assert len(asked.requests) == 1
        assert asked.requests[0] == estate.ran
        assert estate.ran["amount"] != BEYOND["amount"]


# ======================================================================
# The surfaces: a dependency that cannot answer is not an exemption
# ======================================================================


class Unreadable:
    """One named read raises; everything else forwards to the real object.

    Replacing the whole replay store with a stub would prove much less --
    its every behaviour differs, so a refusal afterwards could have any
    cause. Here exactly one question becomes unanswerable.
    """

    def __init__(self, wrapped: Any, *failing: str) -> None:
        object.__setattr__(self, "_wrapped", wrapped)
        object.__setattr__(self, "_failing", frozenset(failing))

    def __getattr__(self, name: str) -> Any:
        if name in object.__getattribute__(self, "_failing"):

            def unreachable(*args: Any, **kwargs: Any) -> Any:
                raise RuntimeError(f"{name} is unreachable")

            return unreachable

        return getattr(
            object.__getattribute__(self, "_wrapped"),
            name,
        )

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(
            object.__getattribute__(self, "_wrapped"),
            name,
            value,
        )


class TestAnUnreadableReplayStoreCannotBeSkipped:
    """Finding #8. ``HTTPFirewall.authorize`` let one exception escape.

    It is typed ``-> HTTPDecision`` and returns one for every other failure
    it can meet, including a capability it cannot decode. The replay store
    was the exception: ``consume_nonce`` reads persistence, persistence
    fails, and the ``RuntimeError`` went straight past the return type.

    That matters because of *where* in the method it happens. The canonical
    boundary has already allowed by that point; the only thing left is
    replay protection. So the caller who wrapped the surface in
    ``except Exception`` and carried on skipped exactly the check the block
    exists to perform, and skipped it silently. ``MCPFirewall`` already
    contained the same read, which is what made this a divergence between
    two surfaces rather than a uniform limitation.
    """

    @staticmethod
    def _http(estate: Estate) -> HTTPFirewall:
        return HTTPFirewall(estate.sdk)

    @staticmethod
    def _request(estate: Estate):
        return HTTPFirewall.request(
            agent="agent-a",
            method=HTTP_METHOD,
            path=HTTP_PATH,
            arguments=dict(WITHIN),
            capability_token=estate.token,
            nonce=estate.nonce(),
        )

    def test_the_healthy_surface_allows(self, http_estate):
        """The control. Without it the refusals below prove nothing."""

        decision = self._http(http_estate).authorize(
            self._request(http_estate)
        )

        assert decision.allowed is True
        assert decision.status_code == 200

    def test_the_unreadable_store_becomes_a_decision(self, http_estate):
        """A decision, not an escape -- and a refusal, not an allow."""

        http_estate.sdk.replay = Unreadable(
            http_estate.sdk.replay, "check_and_consume"
        )

        decision = self._http(http_estate).authorize(
            self._request(http_estate)
        )

        assert decision.allowed is False
        assert decision.status_code == 503
        assert decision.reason == (
            "replay protection error: RuntimeError"
        )

    def test_enforce_and_execute_refuse_and_the_handler_never_runs(
        self, http_estate
    ):
        """The refusal has to survive the two callers that act on it.

        A contained ``authorize`` that ``execute`` then ignored would leave
        the hole open one layer up.
        """

        firewall = self._http(http_estate)
        http_estate.sdk.replay = Unreadable(
            http_estate.sdk.replay, "check_and_consume"
        )

        with pytest.raises(HTTPAuthorizationError):
            firewall.enforce(self._request(http_estate))

        with pytest.raises(HTTPAuthorizationError):
            firewall.execute(
                self._request(http_estate),
                lambda request: http_estate.log.append({"ran": True}),
            )

        assert http_estate.log == []

    def test_both_surfaces_refuse_rather_than_one(self, estate):
        """The point of the fix: MCP and HTTP now agree about this failure.

        They still differ about *when* the nonce is consumed, deliberately
        -- see :class:`TestTheNonceOrderingDivergenceIsDeliberate` -- but
        an unreadable store is a refusal on both.
        """

        mcp = MCPFirewall(estate.sdk)
        estate.sdk.replay = Unreadable(
            estate.sdk.replay, "check_and_consume"
        )

        decision = mcp.authorize(
            MCPFirewall.request(
                agent="agent-a",
                tool=estate.action,
                arguments=dict(WITHIN),
                capability_token=estate.token,
                nonce=estate.nonce(),
            )
        )

        assert decision.allowed is False
        assert decision.reason == "replay protection error"

        with pytest.raises(MCPAuthorizationError):
            mcp.enforce(
                MCPFirewall.request(
                    agent="agent-a",
                    tool=estate.action,
                    arguments=dict(WITHIN),
                    capability_token=estate.token,
                    nonce=estate.nonce(),
                )
            )


# ======================================================================
# Divergences that stay, and the limits that come with them
# ======================================================================


class TestTheNonceOrderingDivergenceIsDeliberate:
    """MCP consumes the nonce before ``authorize``; HTTP consumes after.

    Asserted rather than unified. Neither ordering creates authority --
    both surfaces reach the same canonical boundary and neither allows
    without it -- and each is defensible on its own terms: MCP spends the
    nonce on presentation, HTTP declines to let a denied request burn one.
    Phase 4 asks for semantic divergence to be documented when it is real,
    not smoothed away for symmetry.

    The observable consequence is the point of pinning it: on MCP a denied
    request has spent its nonce, so re-presenting it reports replay; on
    HTTP the same nonce is still good. An operator reading a replay
    counter across both surfaces is not reading one quantity.
    """

    def test_mcp_spends_the_nonce_on_a_denied_request(self, estate):
        firewall = MCPFirewall(estate.sdk)
        nonce = estate.nonce()

        def attempt(arguments: dict):
            return firewall.authorize(
                MCPFirewall.request(
                    agent="agent-a",
                    tool=estate.action,
                    arguments=arguments,
                    capability_token=estate.token,
                    nonce=nonce,
                )
            )

        denied = attempt(dict(BEYOND))
        assert denied.allowed is False

        again = attempt(dict(WITHIN))
        assert again.allowed is False
        assert again.reason == "replay detected"

    def test_http_keeps_the_nonce_on_a_denied_request(self, http_estate):
        firewall = HTTPFirewall(http_estate.sdk)
        nonce = http_estate.nonce()

        def attempt(arguments: dict):
            return firewall.authorize(
                HTTPFirewall.request(
                    agent="agent-a",
                    method=HTTP_METHOD,
                    path=HTTP_PATH,
                    arguments=arguments,
                    capability_token=http_estate.token,
                    nonce=nonce,
                )
            )

        denied = attempt(dict(BEYOND))
        assert denied.allowed is False
        assert denied.reason == "constraint_denied"

        # The same nonce is still spendable. Asserting the allow, not
        # merely the absence of ``replay detected``: on this surface a
        # latched refusal would also deny before the replay check is
        # reached, so "not a replay" alone would prove nothing about the
        # nonce.
        again = attempt(dict(WITHIN))
        assert again.allowed is True
        assert again.status_code == 200

    def test_the_refusal_scope_divergence_that_comes_with_it(
        self, estate, http_estate
    ):
        """A second deliberate difference, found while pinning the first.

        HTTP passes ``refusal_scope="request"`` to the boundary; MCP passes
        nothing and takes the default, which latches the *action*. So one
        over-ceiling request wedges the MCP tool for that capability until
        the refusal clears, while on HTTP the next well-formed request to
        the same endpoint is authorized.

        Both are the same ``authorize`` call with different arguments --
        no second authorization path, and the latching direction is
        fail-closed in both cases. It is recorded because an operator
        reading "denied" from the two surfaces is not reading the same
        durability, and because a later change that quietly unified the
        scope would change how long a denial lasts.
        """

        mcp = MCPFirewall(estate.sdk)
        http = HTTPFirewall(http_estate.sdk)

        def mcp_attempt(arguments: dict):
            return mcp.authorize(
                MCPFirewall.request(
                    agent="agent-a",
                    tool=estate.action,
                    arguments=arguments,
                    capability_token=estate.token,
                    nonce=estate.nonce(),
                )
            )

        def http_attempt(arguments: dict):
            return http.authorize(
                HTTPFirewall.request(
                    agent="agent-a",
                    method=HTTP_METHOD,
                    path=HTTP_PATH,
                    arguments=arguments,
                    capability_token=http_estate.token,
                    nonce=http_estate.nonce(),
                )
            )

        assert mcp_attempt(dict(BEYOND)).reason == "constraint_denied"
        assert http_attempt(dict(BEYOND)).reason == "constraint_denied"

        latched = mcp_attempt(dict(WITHIN))
        assert latched.allowed is False
        assert latched.reason == "refusal_state"

        unlatched = http_attempt(dict(WITHIN))
        assert unlatched.allowed is True



class TestWhatTheAdaptersStillDoNotGuarantee:
    """Stated because the fixes above could be read as promising more.

    ``FirewallSDK.authorize`` is the method documented as total. An adapter
    is not: it validates its input and raises ``TypeError`` or
    ``ValueError`` on a shape it cannot read, and it propagates whatever a
    caller's own object raises. That is the safe direction -- nothing is
    authorized and nothing runs -- but it is not a verdict, and a caller
    catching only ``PermissionError`` will see these escape.
    """

    def test_a_mapping_that_cannot_be_materialized_escapes(self, estate):
        """And the handler does not run, which is the part that matters."""

        class Unmaterializable(Mapping):
            def __iter__(self):
                raise RuntimeError("keys are unreachable")

            def __len__(self) -> int:
                return 1

            def keys(self):
                raise RuntimeError("keys are unreachable")

            def __getitem__(self, key):
                return WITHIN["amount"]

        adapter, _ = _adapter(estate, "generic", dict(WITHIN))

        with pytest.raises(RuntimeError):
            adapter.execute(
                GenericToolCall(
                    name="payment", arguments=Unmaterializable()
                )
            )

        assert estate.log == []

    @pytest.mark.parametrize(
        "kind",
        ("openai", "anthropic", "generic"),
    )
    def test_a_shape_the_adapter_cannot_read_is_refused_not_decided(
        self, estate, kind: str
    ):
        """A ``TypeError``, deliberately -- not a denial dressed as one.

        An adapter that answered ``allowed=False`` for a malformed call
        would be reporting a security verdict it never obtained. Refusing
        to normalize is the honest outcome; a caller who wants a verdict
        must present something the adapter can read.
        """

        adapter, _ = _adapter(estate, kind, dict(WITHIN))

        with pytest.raises((TypeError, ValueError)):
            adapter.execute("not a call")  # type: ignore[arg-type]

        assert estate.log == []






