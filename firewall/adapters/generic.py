from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from firewall.capability import Capability
from firewall.sdk import FirewallSDK
from firewall.tools import ProtectedTool, mark_untrusted


@dataclass(frozen=True)
class GenericToolCall:
    """
    Vendor-neutral representation of a tool call.
    """

    name: str
    arguments: dict[str, Any]


class GenericToolAdapter:
    """
    Vendor-neutral tool adapter.

    Any agent framework can translate its tool-call format
    into GenericToolCall and use this adapter.

    Authorization remains inside FirewallSDK.
    """

    def __init__(
        self,
        *,
        sdk: FirewallSDK,
        capability: Capability,
        handler: Callable[..., Any],
        name: Optional[str] = None,
        action: Optional[str] = None,
        request_builder: Optional[
            Callable[[dict[str, Any]], dict[str, Any]]
        ] = None,
        chain_id: Optional[str] = None,
    ):
        if not isinstance(
            sdk,
            FirewallSDK,
        ):
            raise TypeError(
                "sdk must be a FirewallSDK"
            )

        if not isinstance(
            capability,
            Capability,
        ):
            raise TypeError(
                "capability must be a Capability"
            )

        if not callable(handler):
            raise TypeError(
                "handler must be callable"
            )

        if name is None:
            name = getattr(
                handler,
                "__name__",
                None,
            )

        if not isinstance(
            name,
            str,
        ):
            raise TypeError(
                "name must be a string"
            )

        name = name.strip()

        if not name:
            raise ValueError(
                "name cannot be empty"
            )

        if (
            action is not None
            and not isinstance(
                action,
                str,
            )
        ):
            raise TypeError(
                "action must be a string"
            )

        if (
            action is not None
            and not action.strip()
        ):
            raise ValueError(
                "action cannot be empty"
            )

        if (
            request_builder is not None
            and not callable(request_builder)
        ):
            raise TypeError(
                "request_builder must be callable"
            )

        self.sdk = sdk
        self.capability = capability
        self.name = name
        self.action = action
        self.request_builder = (
            request_builder
        )
        self.chain_id = chain_id

        self.tool = ProtectedTool(
            sdk=sdk,
            capability=capability,
            handler=handler,
            action=action,
            chain_id=chain_id,
        )

    def build_request(
        self,
        call: GenericToolCall,
    ) -> dict[str, Any]:
        if not isinstance(
            call,
            GenericToolCall,
        ):
            raise TypeError(
                "call must be a GenericToolCall"
            )

        if (
            call.name
            != self.name
        ):
            raise ValueError(
                "tool call name does not match adapter"
            )

        if self.request_builder is not None:
            # ``call.arguments`` here is already a settled copy made for
            # the request alone -- see ``authorize``, which settles a
            # second time so that the object handed to this builder is
            # never the object ``execute`` will unpack into the handler.
            # A builder that mutates its argument in place therefore
            # cannot change what runs after the boundary has answered.
            request = self.request_builder(
                call.arguments
            )

            if not isinstance(
                request,
                dict,
            ):
                raise TypeError(
                    "request_builder must return a dictionary"
                )

            return request

        return {
            "tool": call.name,
            "arguments": dict(
                call.arguments
            ),
        }

    def _settled(
        self,
        call: GenericToolCall,
    ) -> GenericToolCall:
        """Materialize ``arguments`` once, into a mapping that cannot change.

        ``GenericToolCall.arguments`` is typed ``dict`` but the dataclass
        does not enforce it, so any mapping arrives. ``execute`` used to
        read the caller's mapping twice -- once through ``build_request``
        for the boundary, once as ``**call.arguments`` for the handler --
        and a mapping is free to answer the second read differently from
        the first. A ``collections.abc.Mapping`` yielding ``amount=10``
        and then ``amount=5000`` had the boundary allow 10 while the
        handler spent 5000, a value the same boundary denies when asked.

        Settling first means every later read is of a plain ``dict``, so
        the boundary is asked about exactly the keywords the handler
        receives. ``OpenAITool`` and ``AnthropicTool`` reach the same
        property by normalizing once; they are safe already because their
        ``normalize`` rejects a non-``dict`` outright.
        """

        if not isinstance(
            call,
            GenericToolCall,
        ):
            raise TypeError(
                "call must be a GenericToolCall"
            )

        return GenericToolCall(
            name=call.name,
            arguments=dict(
                call.arguments
            ),
        )

    def authorize(
        self,
        call: GenericToolCall,
        *,
        chain_id: Optional[str] = None,
    ):
        request = self.build_request(
            self._settled(call)
        )

        action = (
            self.action
            or self.capability.capability
        )

        return self.sdk.authorize(
            self.capability,
            action,
            request,
            chain_id=(
                chain_id
                if chain_id is not None
                else self.chain_id
            ),
        )

    def execute(
        self,
        call: GenericToolCall,
    ):
        # Settled once, then used for both halves of the decision: the
        # boundary is asked about the same mapping the handler receives.
        settled = self._settled(
            call
        )

        result = self.authorize(
            settled
        )

        if not result.allowed:
            raise PermissionError(
                result.reason
            )

        output = self.tool.handler(
            **settled.arguments
        )

        # Marked for the same reason ``ProtectedTool.__call__`` marks:
        # what a tool returns is data the tool chose, so it must not be
        # able to pass for a decision or a capability further up. An
        # adapter that authorized correctly and then returned a bare
        # string would give the same handler a weaker guarantee than
        # ``protect_tool`` gives it.
        return mark_untrusted(
            output,
            tool=(
                self.action
                or self.capability.capability
            ),
        )

    def __call__(
        self,
        call: GenericToolCall,
    ):
        return self.execute(
            call
        )


def generic_tool(
    *,
    sdk: FirewallSDK,
    capability: Capability,
    handler: Callable[..., Any],
    name: Optional[str] = None,
    action: Optional[str] = None,
    request_builder: Optional[
        Callable[[dict[str, Any]], dict[str, Any]]
    ] = None,
    chain_id: Optional[str] = None,
) -> GenericToolAdapter:
    """
    Create a vendor-neutral protected tool adapter.
    """

    return GenericToolAdapter(
        sdk=sdk,
        capability=capability,
        handler=handler,
        name=name,
        action=action,
        request_builder=request_builder,
        chain_id=chain_id,
    )
