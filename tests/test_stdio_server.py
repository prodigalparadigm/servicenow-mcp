"""A real MCP handshake over stdio, in a subprocess.

Everything else in the suite drives the server in-process. This test starts the
actual console-script entry point, speaks JSON-RPC over its stdin/stdout, and
checks that initialize + tools/list + tools/call work end to end -- including
the property that nothing but protocol frames reaches stdout.

The subprocess talks to a stub instance served by ``http.server`` on localhost,
so it still needs no network and no credentials.
"""

from __future__ import annotations

import json
import os
import queue
import socketserver
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

INCIDENTS = [
    {
        "sys_id": "sys-1",
        "number": "INC0000001",
        "short_description": "Stub incident one",
        "state": "New",
        "priority": "3",
        "assignment_group": "Network Support",
        "opened_at": "2026-08-01 09:00:00",
        "sys_updated_on": "2026-08-01 10:00:00",
    },
    {
        "sys_id": "sys-2",
        "number": "INC0000002",
        "short_description": "Stub incident two",
        "state": "In Progress",
        "priority": "2",
        "assignment_group": "Database Ops",
        "opened_at": "2026-08-02 09:00:00",
        "sys_updated_on": "2026-08-02 10:00:00",
    },
]


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        fields = (params.get("sysparm_fields", [""])[0]).split(",")
        limit = int(params.get("sysparm_limit", ["10"])[0])
        offset = int(params.get("sysparm_offset", ["0"])[0])

        window = INCIDENTS[offset : offset + limit]
        result = [
            {f: record.get(f, "") for f in fields if f} or record for record in window
        ]
        body = json.dumps({"result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Total-Count", str(len(INCIDENTS)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:
        return


class _StubServer(ThreadingHTTPServer):
    """Binds without the DNS round trip stdlib's HTTPServer does.

    ``HTTPServer.server_bind`` calls ``socket.getfqdn()``, which blocks for
    tens of seconds on a machine with no working resolver -- exactly the
    offline environment this suite is meant to run in.
    """

    daemon_threads = True

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = str(host)
        self.server_port = int(port)


@pytest.fixture(scope="module")
def stub_instance():
    server = _StubServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


class StdioClient:
    """A minimal JSON-RPC-over-stdio client, enough to drive the handshake.

    stdout is drained on a background thread so a server that never answers
    fails the test with a timeout instead of hanging the suite.
    """

    def __init__(self, process: subprocess.Popen, *, timeout: float = 30.0) -> None:
        self._process = process
        self._next_id = 0
        self._timeout = timeout
        self._lines: queue.Queue[str | None] = queue.Queue()
        self._reader = threading.Thread(target=self._drain, daemon=True)
        self._reader.start()

    def _drain(self) -> None:
        assert self._process.stdout is not None
        for line in self._process.stdout:
            self._lines.put(line)
        self._lines.put(None)

    def _send(self, message: dict) -> None:
        assert self._process.stdin is not None
        self._process.stdin.write(json.dumps(message) + "\n")
        self._process.stdin.flush()

    def _read(self) -> dict:
        try:
            line = self._lines.get(timeout=self._timeout)
        except queue.Empty:
            raise AssertionError(
                f"no reply within {self._timeout}s; stderr:\n{self.stderr()}"
            ) from None
        if line is None:
            raise AssertionError(f"server closed stdout; stderr:\n{self.stderr()}")
        # Any non-JSON line on stdout is itself the failure: stdout is the
        # protocol channel and must carry nothing else.
        return json.loads(line)

    def stderr(self) -> str:
        assert self._process.stderr is not None
        self._process.terminate()
        try:
            return self._process.stderr.read() or ""
        except (OSError, ValueError):  # pragma: no cover - best-effort diagnostics
            return "<unavailable>"

    def request(self, method: str, params: dict | None = None) -> dict:
        self._next_id += 1
        self._send(
            {
                "jsonrpc": "2.0",
                "id": self._next_id,
                "method": method,
                "params": params or {},
            }
        )
        while True:
            message = self._read()
            if message.get("id") == self._next_id:
                return message

    def notify(self, method: str, params: dict | None = None) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def initialize(self) -> dict:
        response = self.request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "pytest", "version": "1.0"},
            },
        )
        self.notify("notifications/initialized")
        return response


@pytest.fixture
def stdio_server(stub_instance):
    env = {
        **os.environ,
        "SERVICENOW_INSTANCE_URL": stub_instance,
        "SERVICENOW_AUTH_MODE": "basic",
        "SERVICENOW_USERNAME": "stub",
        "SERVICENOW_PASSWORD": "stub",
        "SERVICENOW_READ_ONLY": "true",
        "SERVICENOW_RATE_LIMIT_PER_MINUTE": "0",
        "PYTHONUNBUFFERED": "1",
    }
    process = subprocess.Popen(
        [sys.executable, "-m", "servicenow_mcp"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    try:
        yield StdioClient(process)
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover
            process.kill()


def test_full_stdio_session(stdio_server: StdioClient):
    initialize = stdio_server.initialize()
    assert "result" in initialize, initialize
    assert initialize["result"]["serverInfo"]["name"] == "servicenow"

    listed = stdio_server.request("tools/list")
    names = {tool["name"] for tool in listed["result"]["tools"]}
    assert {
        "server_info",
        "search_incidents",
        "get_incident",
        "list_assignment_groups",
        "lookup_ci_owner",
    } <= names
    # Read-only: the mutating tools must not be advertised.
    assert not ({"create_incident", "update_incident"} & names)

    info = stdio_server.request("tools/call", {"name": "server_info", "arguments": {}})
    body = json.loads(info["result"]["content"][0]["text"])
    assert body["read_only"] is True

    search = stdio_server.request(
        "tools/call", {"name": "search_incidents", "arguments": {"limit": 2}}
    )
    payload = json.loads(search["result"]["content"][0]["text"])
    assert payload["count"] == 2
    assert [i["number"] for i in payload["incidents"]] == [
        "INC0000001",
        "INC0000002",
    ]


def test_startup_banner_and_audit_go_to_stderr(stdio_server: StdioClient):
    """stdout must carry protocol frames only."""
    stdio_server.initialize()
    response = stdio_server.request(
        "tools/call", {"name": "search_incidents", "arguments": {"limit": 1}}
    )
    # Every line read off stdout so far parsed as JSON-RPC; if the banner or an
    # audit line had gone to stdout, _read would have raised on it.
    assert response["jsonrpc"] == "2.0"
    assert "result" in response


def test_bad_configuration_exits_nonzero_without_touching_stdout():
    process = subprocess.run(
        [sys.executable, "-m", "servicenow_mcp"],
        capture_output=True,
        text=True,
        env={k: v for k, v in os.environ.items() if not k.startswith("SERVICENOW_")},
        timeout=60,
    )
    assert process.returncode == 2
    assert process.stdout == ""
    assert "configuration error" in process.stderr
    assert "SERVICENOW_INSTANCE_URL is required" in process.stderr
