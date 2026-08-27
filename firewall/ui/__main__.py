"""Console entry point: ``python -m firewall.ui``."""

from __future__ import annotations

import argparse

from firewall.ui.server import serve


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m firewall.ui",
        description=(
            "Local developer console for Agent Firewall. Read-only "
            "unless --control is passed; bind to loopback only."
        ),
    )

    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="interface to bind (default: 127.0.0.1)",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=8787,
        help="port to bind (default: 8787)",
    )

    parser.add_argument(
        "--control",
        action="store_true",
        help=(
            "enable the audited control plane "
            "(issue, delegate, revoke, rules). "
            "Prints a bearer token required by every "
            "write request."
        ),
    )

    parser.add_argument(
        "--token",
        default=None,
        help=(
            "use this control-plane token instead of "
            "generating one (implies --control)"
        ),
    )

    args = parser.parse_args()

    serve(
        host=args.host,
        port=args.port,
        control=args.control or bool(args.token),
        token=args.token,
    )


if __name__ == "__main__":
    main()
