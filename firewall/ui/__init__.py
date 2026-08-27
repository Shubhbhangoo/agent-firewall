"""Agent Firewall developer console (UI).

A visualization layer over the existing Agent Firewall security
implementation, plus an optional audited control plane.

This package adds **no authorization logic**. It does not decide, alter,
re-check, or re-implement anything. When a decision is needed it calls
the established ``FirewallSDK`` pipeline and displays the result
verbatim, and it withholds all cryptographic material.

The control plane (opt-in, token-authenticated) can create and revoke
authority, but only by calling the same public ``FirewallSDK`` methods a
Python caller would use. Every attempt is audited.

Run it with::

    python -m firewall.ui                # read-only inspection
    python -m firewall.ui --control      # + audited control plane
"""

from firewall.ui.control import ControlError, ControlPlane
from firewall.ui.service import Console, ConsoleError
from firewall.ui.server import build_server, serve

__all__ = [
    "Console",
    "ConsoleError",
    "ControlError",
    "ControlPlane",
    "build_server",
    "serve",
]
