"""Agent Firewall developer console (UI).

A read-only visualization layer over the existing Agent Firewall
security implementation.

This package adds **no authorization logic**. It does not decide, alter,
re-check, or re-implement anything. When a decision is needed it calls
the established ``FirewallSDK`` pipeline and displays the result
verbatim, and it withholds all cryptographic material.

Run it with::

    python -m firewall.ui
"""

from firewall.ui.service import Console, ConsoleError
from firewall.ui.server import build_server, serve

__all__ = [
    "Console",
    "ConsoleError",
    "build_server",
    "serve",
]
