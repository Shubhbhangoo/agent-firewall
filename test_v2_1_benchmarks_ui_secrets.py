"""v2.1 benchmarks, CLI, UI/API, and secrets-scanning tests."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading

import pytest

PY = sys.executable

# ======================================================================
# Benchmarks
# ======================================================================


class TestBenchmarks:
    def test_all_benchmarks_run(self):
        from firewall.benchmarks import BENCHMARKS, GROUPS, run_benchmarks

        report = run_benchmarks()
        results = report["benchmarks"]
        # Compared against the registry rather than a literal count: the
        # v2.4 authority-control-plane benchmarks were added to the same
        # registry, and a hardcoded census breaks on every future addition
        # while proving nothing extra. The v2.1 set is still pinned by name
        # below, which is what this test was actually protecting.
        assert len(results) == len(BENCHMARKS)
        assert set(GROUPS["v21"]) <= set(results)
        for name, result in results.items():
            assert "error" not in result, result
            assert "name" in result

    def test_individual_benchmark(self):
        from firewall.benchmarks import run_benchmarks

        report = run_benchmarks(["evidence_append"])
        assert report["benchmarks"]["evidence_append"]["events"] == 200

    def test_group_expands(self):
        from firewall.benchmarks import GROUPS, run_benchmarks

        report = run_benchmarks(["v21"])
        assert set(report["benchmarks"]) == set(GROUPS["v21"])

    def test_unknown_benchmark_reported(self):
        from firewall.benchmarks import run_benchmarks

        report = run_benchmarks(["bogus"])
        assert "error" in report["benchmarks"]["bogus"]

    def test_benchmark_cli(self):
        result = subprocess.run(
            [PY, "-m", "firewall.benchmarks", "capability2"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        payload = json.loads(result.stdout)
        assert "capability2" in payload["benchmarks"]


# ======================================================================
# CLI surface
# ======================================================================


class TestCLISurface:
    def test_help_lists_all_v21_commands(self):
        result = subprocess.run(
            [PY, "-m", "firewall.cli", "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        for command in (
            "defense",
            "delegate",
            "capability",
            "attack-graph",
            "twin",
            "evidence",
            "immune",
            "research",
            "recover",
        ):
            assert command in result.stdout

    def test_v20_commands_still_work(self, tmp_path):
        reg = tmp_path / "id.json"
        result = subprocess.run(
            [PY, "-m", "firewall.cli", "identity", "create", "alice",
             "--registry", str(reg)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "created identity alice" in result.stdout

    def test_v19_commands_still_work(self, tmp_path):
        artifact = tmp_path / "demo.afw"
        result = subprocess.run(
            [PY, "-m", "firewall.cli", "record", "--out", str(artifact)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        verify = subprocess.run(
            [PY, "-m", "firewall.cli", "verify", str(artifact)],
            capture_output=True,
            text=True,
        )
        assert "verified" in verify.stdout


# ======================================================================
# UI / API smoke
# ======================================================================


class TestUISmoke:
    def _server(self):
        from firewall.ui import build_server

        server = build_server(host="127.0.0.1", port=0, quiet=True)
        thread = threading.Thread(
            target=server.serve_forever, daemon=True
        )
        thread.start()
        port = server.server_address[1]
        return server, port

    def _get(self, port, path):
        import urllib.request

        with urllib.request.urlopen(
            f"http://127.0.0.1:{port}{path}"
        ) as response:
            return response.status, response.read()

    def _post(self, port, path, payload):
        import urllib.request

        request = urllib.request.Request(
            f"http://127.0.0.1:{port}{path}",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request) as response:
            return response.status, response.read()

    def test_v21_api_endpoints(self):
        server, port = self._server()
        try:
            _, system = self._get(port, "/api/system")
            assert json.loads(system)["v21_available"] is True

            for path in (
                "/api/v21/mesh",
                "/api/v21/a2a",
                "/api/v21/attack-graph",
                "/api/v21/evidence",
                "/api/v21/immune",
            ):
                status, body = self._get(port, path)
                assert status == 200
                assert json.loads(body) is not None

            status, body = self._post(
                port, "/api/v21/twin", {"agent": "agent-orchestrator"}
            )
            assert status == 200
            twin = json.loads(body)
            assert twin["basis"] == "simulated"

            status, body = self._post(port, "/api/v21/immune/cycle", {})
            assert status == 200
        finally:
            server.shutdown()
            server.server_close()

    def test_v21_static_assets(self):
        server, port = self._server()
        try:
            for path in ("/assets/v21.js", "/assets/v21.css"):
                status, body = self._get(port, path)
                assert status == 200
                assert len(body) > 500
            status, html = self._get(port, "/")
            assert status == 200
            assert b"v21.js" in html
            assert b"v2.1 Autonomous Defense" in html
        finally:
            server.shutdown()
            server.server_close()

    def test_control_routes_still_gated(self):
        from firewall.ui import build_server

        server = build_server(host="127.0.0.1", port=0, quiet=True,
                              control=True, token="tok-123")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        try:
            import urllib.request
            import urllib.error

            # Unauthorized control request is 401.
            request = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/control/state",
            )
            with pytest.raises(urllib.error.HTTPError) as excinfo:
                urllib.request.urlopen(request)
            assert excinfo.value.code == 401

            # Authorized works.
            request = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/control/state",
                headers={"Authorization": "Bearer tok-123"},
            )
            with urllib.request.urlopen(request) as response:
                assert response.status == 200
        finally:
            server.shutdown()
            server.server_close()


# ======================================================================
# Secrets scanning
# ======================================================================


class TestSecretsScanning:
    @pytest.fixture()
    def repo_files(self):
        """All tracked source files (firewall/, test_v2_1_*.py, docs/)."""

        root = os.path.dirname(os.path.abspath(__file__))
        files = []
        for directory, _, filenames in os.walk(os.path.join(root, "firewall")):
            for name in filenames:
                if name.endswith(".py"):
                    files.append(os.path.join(directory, name))
        for name in os.listdir(root):
            if name.startswith("test_v2_1_") and name.endswith(".py"):
                files.append(os.path.join(root, name))
        return files

    def test_no_private_key_material_in_sources(self, repo_files):
        """No PEM-encoded private keys or obvious key material."""

        # The patterns below appear verbatim in this test file, so the
        # file itself is excluded (it is the scanner, not a target).
        patterns = [
            r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
            r"-----BEGIN ENCRYPTED PRIVATE KEY-----",
            r"sk-[A-Za-z0-9]{20,}",
        ]
        for path in repo_files:
            if path.endswith("test_v2_1_benchmarks_ui_secrets.py"):
                continue
            text = open(path, encoding="utf-8").read()
            for pattern in patterns:
                match = re.search(pattern, text)
                assert match is None, (
                    f"secret-shaped content in {path}: {pattern}"
                )

    def test_no_hardcoded_credentials(self, repo_files):
        """No hardcoded bearer tokens or passwords in v2.1 sources."""

        patterns = [
            r"Bearer [A-Za-z0-9_-]{16,}",
            r"password\s*=\s*['\"][^'\"]+['\"]",
            r"api[_-]?key\s*=\s*['\"][A-Za-z0-9]{16,}['\"]",
        ]
        for path in repo_files:
            if "test" in path:
                continue
            text = open(path, encoding="utf-8").read()
            for pattern in patterns:
                assert re.search(pattern, text) is None, (
                    f"credential-shaped content in {path}: {pattern}"
                )

    def test_no_tokens_in_artifacts(self):
        """The recorder redacts credential-shaped values before hashing
        (existing v1.8 guarantee, spot-checked here)."""

        from firewall.recorder import FlightRecorder

        recorder = FlightRecorder(session_id="scan", agent="agent-x")
        recorder.record(
            __import__("firewall.recorder", fromlist=["EventType"]).EventType.AUTHORIZATION,
            {"request": {"password": "abc123secret456"}},
            agent="agent-x",
        )
        artifact = recorder.artifact()
        text = json.dumps(artifact)
        assert "abc123secret456" not in text
