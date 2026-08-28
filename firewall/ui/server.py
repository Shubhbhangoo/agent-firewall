"""Local HTTP server for the Agent Firewall console.

Built on the standard library only -- no web framework, no build step,
no new dependencies.

Scope and honesty about it: the default configuration is a **local
developer inspection console**. It binds to the loopback interface, has
no authentication, and reads only. It is a debugging tool, not a hardened
control plane, and it should not be exposed to a network.

The optional control plane (``build_server(control=True)``) adds a write
surface: connecting agents, issuing and delegating capabilities,
revoking, and authoring rules. That surface can mint authority, so it is
off unless explicitly enabled, every request to it must carry a bearer
token generated at startup, and every mutation is audited. When control
is disabled those routes do not exist at all -- they return 404, the same
as any other unknown path.

The one security property this module implements for itself is
protection against path traversal when serving its own static assets,
which is covered by tests.
"""

from __future__ import annotations

import json
import secrets
from http import HTTPStatus
from http.server import (
    BaseHTTPRequestHandler,
    ThreadingHTTPServer,
)
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urlparse

from firewall.sdk import FirewallSDK
from firewall.ui.control import ControlError
from firewall.ui.service import Console, ConsoleError


STATIC_ROOT = (
    Path(__file__).resolve().parent / "static"
)

#: Maximum accepted request body. The only POST endpoint takes a tiny
#: JSON object, so anything larger is rejected outright.
MAX_BODY_BYTES = 8 * 1024

#: Upper bound on bytes discarded when rejecting a request before its
#: body is read. Beyond this the connection is closed instead.
DRAIN_LIMIT = 1024 * 1024

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
    control_enabled: bool = False
    control_token: Optional[str] = None

    #: Whether this request's body has already been consumed. One handler
    #: instance serves a whole keep-alive connection, so this is reset per
    #: request rather than set once.
    _body_read: bool = False

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
        # A POST that is rejected before its body is read leaves unread
        # bytes in the socket; closing on top of those surfaces to the
        # client as a connection reset instead of the status code. Drain
        # first so the rejection is actually delivered.
        self._drain_body()

        self._send_json(
            {"error": message},
            status=status,
        )

    # ------------------------------------------------------------------
    # Request bodies
    # ------------------------------------------------------------------

    def _content_length(self) -> int:
        try:
            length = int(
                self.headers.get(
                    "Content-Length",
                    "0",
                )
            )
        except (TypeError, ValueError):
            return -1

        return length if length >= 0 else -1

    def _drain_body(self) -> None:
        """Discard a pending request body.

        The bytes are read and thrown away -- never decoded, never
        parsed, never handed to the control plane -- so draining an
        unauthenticated request cannot reach any application code. An
        implausibly large body is not drained at all; the connection is
        closed instead.
        """

        if self.command != "POST" or self._body_read:
            return

        self._body_read = True

        length = self._content_length()

        if length <= 0:
            return

        if length > DRAIN_LIMIT:
            self.close_connection = True
            return

        remaining = length

        while remaining > 0:
            chunk = self.rfile.read(
                min(remaining, 65536)
            )

            if not chunk:
                break

            remaining -= len(chunk)

    # ------------------------------------------------------------------
    # Control-plane authentication
    # ------------------------------------------------------------------

    def _control_authorized(self) -> bool:
        """Gate every control-plane request on the startup token.

        Fails closed: a missing token attribute, a missing header, a
        malformed header, or any mismatch is a rejection. The comparison
        is constant-time so the token cannot be recovered by timing.
        """

        expected = self.control_token

        if not self.control_enabled or not expected:
            return False

        header = self.headers.get(
            "Authorization",
            "",
        )

        prefix = "Bearer "

        if not header.startswith(prefix):
            return False

        presented = header[len(prefix) :].strip()

        if not presented:
            return False

        return secrets.compare_digest(
            presented,
            expected,
        )

    def _reject_unauthorized(self) -> None:
        self._drain_body()

        self.send_response(
            HTTPStatus.UNAUTHORIZED
        )
        self.send_header(
            "WWW-Authenticate",
            'Bearer realm="agent-firewall-console"',
        )
        body = json.dumps(
            {
                "error": (
                    "control plane requires the "
                    "bearer token printed at startup"
                )
            }
        ).encode("utf-8")
        self.send_header(
            "Content-Type",
            "application/json; charset=utf-8",
        )
        self.send_header(
            "Content-Length",
            str(len(body)),
        )
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

    # ------------------------------------------------------------------
    # Request bodies
    # ------------------------------------------------------------------

    def _read_json_body(
        self,
    ) -> Optional[dict[str, Any]]:
        """Read and validate a small JSON object body.

        Returns ``None`` after sending an error response, so callers can
        simply bail out.
        """

        length = self._content_length()

        if length < 0:
            self._send_error_json(
                HTTPStatus.BAD_REQUEST,
                "invalid Content-Length",
            )
            return None

        if length > MAX_BODY_BYTES:
            self._send_error_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "request body too large",
            )
            return None

        raw = (
            self.rfile.read(length)
            if length > 0
            else b"{}"
        )

        self._body_read = True

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
            return None

        if not isinstance(payload, dict):
            self._send_error_json(
                HTTPStatus.BAD_REQUEST,
                "body must be a JSON object",
            )
            return None

        return payload

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
            payload = self.console.system()
            # The browser needs to know whether to render the control
            # panel at all. This says the surface exists, never whether
            # the caller is allowed to use it.
            payload["control_enabled"] = (
                self.control_enabled
            )
            self._send_json(payload)
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

        if path == "/api/recorder":
            self._send_json(
                self.console.recorder_view()
            )
            return

        if path == "/api/soc":
            self._send_json(
                self.console.soc_overview()
            )
            return

        if path == "/api/control/state":
            if not self.control_enabled:
                self._send_error_json(
                    HTTPStatus.NOT_FOUND,
                    "not found",
                )
                return

            if not self._control_authorized():
                self._reject_unauthorized()
                return

            self._send_json(
                self.console.control().state()
            )
            return

        self._send_error_json(
            HTTPStatus.NOT_FOUND,
            "not found",
        )

    # ------------------------------------------------------------------
    # POST
    # ------------------------------------------------------------------

    def _control_routes(
        self,
    ) -> dict[str, Callable[[dict[str, Any]], Any]]:
        """The complete set of writable endpoints.

        A whitelist, deliberately: each entry maps to one control-plane
        method, which in turn maps to one existing public SDK call.
        """

        control = self.console.control()

        return {
            "/api/control/connect": control.connect_agent,
            "/api/control/delegate": control.delegate,
            "/api/control/attenuate": control.attenuate,
            "/api/control/revoke": control.revoke,
            "/api/control/trust": control.set_issuer_trust,
            "/api/control/depth": control.set_depth_policy,
            "/api/control/check": control.check,
            "/api/control/simulate": control.simulate,
            "/api/control/promote": control.promote,
            "/api/control/rollback": control.rollback,
            "/api/control/containment": self.console.apply_containment,
            "/api/control/respond": self.console.soc_respond,
        }

    def do_POST(self) -> None:
        self._body_read = False
        path = urlparse(self.path).path

        if path.startswith("/api/control/"):
            # Always consume the request body before responding.
            # HTTP/1.1 keep-alive requires the body to be drained
            # before the response is sent, otherwise the unread
            # payload desynchronizes the connection and the client
            # sees a transport-level abort instead of the 404/401
            # we want to send back.
            payload = self._read_json_body()

            if payload is None:
                return

            self._handle_control_post(path, payload)
            return

        if path == "/api/replay":
            # v1.8 read-only replay laboratory. Analysis only: the
            # replay runs in throwaway workspaces and never touches
            # the live SDK, so it does not require the control token.
            payload = self._read_json_body()

            if payload is None:
                return

            try:
                result = self.console.replay(payload)
            except ConsoleError as exc:
                self._send_error_json(
                    HTTPStatus.BAD_REQUEST,
                    str(exc),
                )
                return

            self._send_json(result)
            return

        if path in (
            "/api/soc/attack-paths",
            "/api/soc/simulate",
        ):
            # v1.9 read-only SOC analysis (attack paths, scenario
            # simulation). Both run in isolated workspaces over
            # verified evidence; no control token needed.
            payload = self._read_json_body()

            if payload is None:
                return

            try:
                if path == "/api/soc/attack-paths":
                    result = self.console.soc_attack_paths(payload)
                else:
                    result = self.console.soc_simulate(payload)
            except (ConsoleError, ValueError) as exc:
                self._send_error_json(
                    HTTPStatus.BAD_REQUEST,
                    str(exc),
                )
                return

            self._send_json(result)
            return

        if path != "/api/evaluate":
            self._send_error_json(
                HTTPStatus.NOT_FOUND,
                "not found",
            )
            return

        payload = self._read_json_body()

        if payload is None:
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

    def _handle_control_post(
        self,
        path: str,
        payload: dict[str, Any],
    ) -> None:
        # Order matters. Existence is checked before authentication so a
        # disabled control plane is indistinguishable from an unknown
        # route, and authentication is checked before the body is read so
        # an unauthenticated caller cannot reach any parsing or SDK code.
        if not self.control_enabled:
            self._send_error_json(
                HTTPStatus.NOT_FOUND,
                "not found",
            )
            return

        if not self._control_authorized():
            self._reject_unauthorized()
            return

        routes = self._control_routes()
        handler = routes.get(path)

        if handler is None:
            self._send_error_json(
                HTTPStatus.NOT_FOUND,
                "not found",
            )
            return

        try:
            result = handler(payload)
        except (ControlError, ConsoleError) as exc:
            self._send_error_json(
                HTTPStatus.BAD_REQUEST,
                str(exc),
            )
            return
        except Exception as exc:
            # Fail closed and stay quiet about internals: report the
            # exception type, never a traceback or key material.
            self._send_error_json(
                HTTPStatus.BAD_REQUEST,
                f"rejected ({type(exc).__name__})",
            )
            return

        self._send_json(
            {
                "result": result,
                "state": self.console.control().state(),
            }
        )


def build_server(
    *,
    host: str = "127.0.0.1",
    port: int = 8787,
    sdk: Optional[FirewallSDK] = None,
    quiet: bool = False,
    control: bool = False,
    token: Optional[str] = None,
) -> ThreadingHTTPServer:
    """Create the console HTTP server.

    Binds to loopback by default. Pass an ``sdk`` to inspect a live
    instance read-only; scenario evaluation is disabled in that mode.

    Set ``control=True`` to enable the audited write surface. A bearer
    token is generated unless one is supplied, and is readable as
    ``server.RequestHandlerClass.control_token``. With ``control=False``
    (the default) the control routes 404 and no control plane is ever
    constructed.
    """

    console = Console(sdk=sdk)

    if control:
        control_token = token or secrets.token_urlsafe(
            32
        )
    else:
        # Never carry a usable token on a server that has no write
        # surface -- the auth gate then fails closed on two conditions
        # instead of one.
        control_token = None

    handler = type(
        "BoundConsoleRequestHandler",
        (ConsoleRequestHandler,),
        {
            "console": console,
            "quiet": quiet,
            "control_enabled": bool(control),
            "control_token": control_token,
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
    control: bool = False,
    token: Optional[str] = None,
) -> None:
    """Run the console until interrupted."""

    httpd = build_server(
        host=host,
        port=port,
        sdk=sdk,
        control=control,
        token=token,
    )

    bound_host, bound_port = httpd.server_address[
        :2
    ]

    handler = httpd.RequestHandlerClass

    banner = (
        "Agent Firewall console"
        f"\n  http://{bound_host}:{bound_port}"
        f"\n  mode: {handler.console.mode}"
    )

    if handler.control_enabled:
        banner += (
            "\n  control plane: ENABLED"
            "\n  token: "
            f"{handler.control_token}"
            "\n  this token can issue and delegate "
            "capabilities -- keep it local"
        )
    else:
        banner += (
            "\n  control plane: disabled"
            " (start with --control to enable)"
            "\n  local inspection console -- no auth,"
            " do not expose"
        )

    print(banner + "\n  Ctrl+C to stop")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
        httpd.server_close()
