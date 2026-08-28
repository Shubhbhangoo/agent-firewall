"""Active containment (v1.8).

Explicit-state containment (``active -> restricted -> suspended ->
quarantined -> recovered``) that is authorized, authenticated, audited,
explainable, reversible where appropriate, and fail-closed. Enforcement
is routed through the SDK's own revocation and risk mechanisms, never
around the authorization pipeline.
"""

from firewall.containment.controller import (
    ContainmentAction,
    ContainmentController,
    ContainmentError,
    ContainmentEvent,
    ContainmentState,
)

__all__ = [
    "ContainmentAction",
    "ContainmentController",
    "ContainmentError",
    "ContainmentEvent",
    "ContainmentState",
]
