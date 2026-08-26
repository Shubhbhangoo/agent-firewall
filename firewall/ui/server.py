"""Local HTTP server for the Agent Firewall console.

Built on the standard library only -- no web framework, no build step,
no new dependencies.

Scope and honesty about it: this is a **local developer inspection
console**. It binds to the loopback interface by default and has no
authentication, no authorization, and no transport security of its own.
It is a debugging tool, not a hardened control plane, and it should not
be exposed to a network. The one security property this module does
implement is protection against path traversal when serving its own
static assets, which is covered by tests.
"""

from __future__ import annotations

import json
from http import HTTPStatus
from http.server import (
    BaseHTTPRequestHandler,
    ThreadingHTTPServer,
)
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from firewall.sdk import FirewallSDK
from firewall.ui.service import Console, ConsoleError


STATIC_ROOT = (
    Path(__file__).resolve().parent / "static"
)

#: Maximum accepted request body. The only POST endpoint takes a tiny
#: JSON object, so anything larger is rejected outright.
MAX_BODY_BYTES = 8 * 1024

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".json": "application/json; charset=utf-8",
    ".woff2": "font/woff2",
}


class ConsoleRequestHandler(BaseHTTPRequestHandler):
    """Routes console API reads and static assets."""

    server_version = "AgentFirewallConsole"
    sys_version = ""

    # Injected by ``build_server``.
    console: Console
    quiet: bool = False

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def log_message(
        self,
        format: str,
        *args: Any,
    ) -> None:
        if self.quiet:
            return

        super().log_message(
            format,
            *args,
        )

    # ------------------------------------------------------------------
    # Response helpers
    # ------------------------------------------------------------------

    def _send_bytes(
        self,
        status: int,
        body: bytes,
        content_type: str,
    ) -> None:
        self.send_response(status)
        self.send_header(
            "Content-Type",
            content_type,
        )
        self.send_header(
            "Content-Length",
            str(len(body)),
        )
        # The console renders only its own data, but these are cheap
        # and keep a stray asset from being framed or sniffed.
        self.send_header(
            "X-Content-Type-Options",
            "nosniff",
        )
        self.send_header(
            "X-Frame-Options",
            "DENY",
        )
        self.send_header(
            "Cache-Control",
            "no-store",
        )
        self.end_headers()

        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_json(
        self,
        payload: dict[str, Any],
        status: int = HTTPStatus.OK,
    ) -> None:
        body = json.dumps(
            payload,
            default=str,
        ).encode("utf-8")

        self._send_bytes(
            status,
            body,
            "application/json; charset=utf-8",
        )

    def _send_error_json(
        self,
        status: int,
        message: str,
    ) -> None:
        self._send_json(
            {"error": message},
            status=status,
        )

    # ------------------------------------------------------------------
    # Static assets
    # ------------------------------------------------------------------

    def _serve_static(
        self,
        relative: str,
    ) -> None:
        """Serve a file from the console's own static directory.

        Path traversal is blocked by resolving the candidate and
        confirming it stays inside ``STATIC_ROOT``. Symlinks are
        resolved before the check, so a link pointing outside the root
        is rejected too.
        """

        candidate = (
            STATIC_ROOT / relative.lstrip("/")
        ).resolve()

        if not candidate.is_relative_to(
            STATIC_ROOT
        ):
            self._send_error_json(
                HTTPStatus.FORBIDDEN,
                "path outside static root",
            )
            return

        if (
            not candidate.exists()
            or not candidate.is_file()
        ):
            self._send_error_json(
                HTTPStatus.NOT_FOUND,
                "not found",
            )
            return

        content_type = CONTENT_TYPES.get(
            candidate.suffix,
            "application/octet-stream",
        )

        self._send_bytes(
            HTTPStatus.OK,
            candidate.read_bytes(),
            content_type,
        )

    # ------------------------------------------------------------------
    # GET
    # ------------------------------------------------------------------

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        path = urlparse(self.path).path

        if path in ("/", "/index.html"):
            self._serve_static("index.html")
            return

        if path.startswith("/assets/"):
            self._serve_static(
                path[len("/assets/") :]
            )
            return

        if path == "/api/system":
            self._send_json(
                self.console.system()
            )
            return

        if path == "/api/scenarios":
            self._send_json(
                self.console.scenarios()
            )
            return

        if path == "/api/posture":
            self._send_json(
                self.console.posture()
            )
            return

        if path == "/api/lifecycle":
            self._send_json(
                self.console.lifecycle()
            )
            return

        if path == "/api/history":
            self._send_json(
                self.console.history()
            )
            return

        self._send_error_json(
            HTTPStatus.NOT_FOUND,
            "not found",
        )

    # ------------------------------------------------------------------
    # POST
    # ------------------------------------------------------------------

    def do_POST(self) -> None:
        path = urlparse(self.path).path

        if path != "/api/evaluate":
            self._send_error_json(
                HTTPStatus.NOT_FOUND,
                "not found",
            )
            return

        try:
            length = int(
                self.headers.get(
                    "Content-Length",
                    "0",
                )
            )
        except (TypeError, ValueError):
            self._send_error_json(
                HTTPStatus.BAD_REQUEST,
                "invalid Content-Length",
            )
            return

        if length > MAX_BODY_BYTES:
            self._send_error_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "request body too large",
            )
            return

        raw = (
            self.rfile.read(length)
            if length > 0
            else b"{}"
        )

        try:
            payload = json.loads(
                raw.decode("utf-8")
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
        ):
            self._send_error_json(
                HTTPStatus.BAD_REQUEST,
                "invalid JSON body",
            )
            return

        if not isinstance(payload, dict):
            self._send_error_json(
                HTTPStatus.BAD_REQUEST,
                "body must be a JSON object",
            )
            return

        scenario = payload.get("scenario")

        if not isinstance(scenario, str):
            self._send_error_json(
                HTTPStatus.BAD_REQUEST,
                "scenario must be a string",
            )
            return

        try:
            result = self.console.evaluate(
                scenario
            )
        except ConsoleError as exc:
            self._send_error_json(
                HTTPStatus.BAD_REQUEST,
                str(exc),
            )
            return

        self._send_json(result)


def build_server(
    *,
    host: str = "127.0.0.1",
    port: int = 8787,
    sdk: Optional[FirewallSDK] = None,
    quiet: bool = False,
) -> ThreadingHTTPServer:
    """Create the console HTTP server.

    Binds to loopback by default. Pass an ``sdk`` to inspect a live
    instance read-only; scenario evaluation is disabled in that mode.
    """

    console = Console(sdk=sdk)

    handler = type(
        "BoundConsoleRequestHandler",
        (ConsoleRequestHandler,),
        {
            "console": console,
            "quiet": quiet,
        },
    )

    return ThreadingHTTPServer(
        (host, port),
        handler,
    )


def serve(
    *,
    host: str = "127.0.0.1",
    port: int = 8787,
    sdk: Optional[FirewallSDK] = None,
) -> None:
    """Run the console until interrupted."""

    httpd = build_server(
        host=host,
        port=port,
        sdk=sdk,
    )

    bound_host, bound_port = httpd.server_address[
        :2
    ]

    print(
        "Agent Firewall console"
        f"\n  http://{bound_host}:{bound_port}"
        "\n  mode: "
        f"{httpd.RequestHandlerClass.console.mode}"
        "\n  local inspection console -- no auth, do not expose"
        "\n  Ctrl+C to stop"
    )

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
        httpd.server_close()
