"""Console entry point: ``python -m firewall.ui``."""

from __future__ import annotations

import argparse

from firewall.ui.server import serve


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m firewall.ui",
        description=(
            "Local read-only developer console for Agent Firewall. "
            "No authentication; bind to loopback only."
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

    args = parser.parse_args()

    serve(
        host=args.host,
        port=args.port,
    )


if __name__ == "__main__":
    main()
