#!/usr/bin/env python3
"""
SentinelGate E2E — Python MCP Client

Tests SentinelGate MCP proxy by acting as a real MCP client.
Uses ONLY Python stdlib (zero external dependencies).

Exit code 0 = all tests passed, 1 = at least one failure.
"""

import json
import os
import secrets
import sys
import urllib.request
import urllib.error

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def load_env(path: str) -> dict[str, str]:
    """Parse a .env file (KEY=VALUE per line) into a dict."""
    env: dict[str, str] = {}
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                eq = line.find("=")
                if eq > 0:
                    env[line[:eq]] = line[eq + 1 :]
    except FileNotFoundError:
        print(f"ERROR: env file not found: {path}", file=sys.stderr)
        sys.exit(1)
    return env


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_FILE = os.path.join(SCRIPT_DIR, "..", ".env.test")
ENV = load_env(ENV_FILE)

API_KEY = ENV.get("API_KEY", "")
BASE_URL = ENV.get("BASE_URL", "http://localhost:8080")
TEST_DIR = ENV.get("TEST_DIR", "/private/tmp/sg-e2e-test")

if not API_KEY:
    print("ERROR: API_KEY not set in .env.test", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# HTTP helpers (stdlib only)
# ---------------------------------------------------------------------------

def http_request(
    method: str,
    url: str,
    body: dict | str | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], str]:
    """
    Perform an HTTP request and return (status_code, response_headers, body_text).
    response_headers keys are lowercased.
    """
    if headers is None:
        headers = {}

    data: bytes | None = None
    if body is not None:
        if isinstance(body, dict):
            data = json.dumps(body).encode()
        else:
            data = body.encode()

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        resp = urllib.request.urlopen(req, timeout=30)
        status = resp.status
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        resp_body = resp.read().decode()
    except urllib.error.HTTPError as e:
        status = e.code
        resp_headers = {k.lower(): v for k, v in e.headers.items()}
        resp_body = e.read().decode()

    return status, resp_headers, resp_body


# ---------------------------------------------------------------------------
# MCP Client
# ---------------------------------------------------------------------------

class MCPClient:
    """Minimal MCP JSON-RPC client over HTTP."""

    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url
        self.api_key = api_key
        self.session_id: str | None = None
        self._next_id = 1

    # -- low-level ---------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        h = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        if self.session_id:
            h["Mcp-Session-Id"] = self.session_id
        return h

    def send(self, method: str, params: dict | None = None) -> dict:
        """Send a JSON-RPC request (with id) and return parsed result dict."""
        rid = self._next_id
        self._next_id += 1
        payload: dict = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            payload["params"] = params

        status, headers, body = http_request(
            "POST", f"{self.base_url}/mcp", payload, self._headers()
        )

        # Capture session id
        sid = headers.get("mcp-session-id")
        if sid:
            self.session_id = sid

        if status == 202:
            return {"id": rid, "result": None, "headers": headers}

        parsed = json.loads(body)
        return {
            "id": parsed.get("id"),
            "result": parsed.get("result"),
            "error": parsed.get("error"),
            "headers": headers,
        }

    def notify(self, method: str, params: dict | None = None) -> int:
        """Send a JSON-RPC notification (no id) and return HTTP status code."""
        payload: dict = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params

        status, _, _ = http_request(
            "POST", f"{self.base_url}/mcp", payload, self._headers()
        )
        return status

    # -- high-level --------------------------------------------------------

    def initialize(self) -> dict:
        res = self.send(
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "python-e2e", "version": "1.0.0"},
            },
        )
        if res.get("error"):
            raise RuntimeError(f"initialize failed: {res['error']}")
        self.notify("notifications/initialized")
        return res

    def tools_list(self) -> list:
        res = self.send("tools/list")
        if res.get("error"):
            raise RuntimeError(f"tools/list failed: {res['error']}")
        return res["result"].get("tools", [])

    def call_tool(self, name: str, arguments: dict | None = None) -> dict:
        params: dict = {"name": name}
        if arguments is not None:
            params["arguments"] = arguments
        res = self.send("tools/call", params)
        if res.get("error"):
            return {"error": res["error"], "isError": True}
        result = res.get("result") or {}
        return {
            "content": result.get("content"),
            "isError": result.get("isError", False),
        }

    def call_tool_text(self, name: str, arguments: dict | None = None) -> str:
        r = self.call_tool(name, arguments)
        if r.get("isError"):
            text = ""
            for c in (r.get("content") or []):
                text += c.get("text", "")
            raise RuntimeError(f"Tool {name} returned error: {text or r.get('error')}")
        return "".join(c.get("text", "") for c in (r.get("content") or []))


# ---------------------------------------------------------------------------
# Admin API helper (CSRF double-submit cookie pattern)
# ---------------------------------------------------------------------------

class AdminAPI:
    def __init__(self, base_url: str):
        self.base_url = base_url

    def _csrf_headers(self) -> dict[str, str]:
        token = secrets.token_hex(32)
        return {
            "Content-Type": "application/json",
            "X-CSRF-Token": token,
            "Cookie": f"sentinel_csrf_token={token}",
        }

    def post(self, path: str, body: dict | None = None) -> tuple[int, dict]:
        url = f"{self.base_url}/admin/api{path}"
        status, _, resp = http_request("POST", url, body, self._csrf_headers())
        try:
            return status, json.loads(resp)
        except (json.JSONDecodeError, ValueError):
            return status, {"raw": resp}

    def delete(self, path: str) -> int:
        url = f"{self.base_url}/admin/api{path}"
        status, _, _ = http_request("DELETE", url, None, self._csrf_headers())
        return status


# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------

class TestRunner:
    def __init__(self):
        self.results: list[tuple[str, bool, str]] = []

    def record(self, name: str, passed: bool, detail: str):
        self.results.append((name, passed, detail))
        tag = "PASS" if passed else "FAIL"
        print(f"[{tag}] {name}: {detail}")

    def summary(self) -> bool:
        total = len(self.results)
        passed = sum(1 for _, ok, _ in self.results if ok)
        print(f"\n=== Results: {passed}/{total} PASS ===")
        return passed == total


runner = TestRunner()
client = MCPClient(BASE_URL, API_KEY)
admin = AdminAPI(BASE_URL)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_initialize():
    """POST initialize -> get session ID, verify protocolVersion and capabilities."""
    try:
        res = client.initialize()
        result = res.get("result", {})
        headers = res.get("headers", {})
        sid = client.session_id

        assert sid and len(sid) == 64, f"expected 64-hex session id, got {sid!r}"
        assert result.get("protocolVersion"), "missing protocolVersion"
        assert result.get("capabilities") is not None, "missing capabilities"
        assert result.get("serverInfo"), "missing serverInfo"

        runner.record(
            "test_initialize",
            True,
            f"Session established (session_id={sid[:12]}...)",
        )
    except Exception as exc:
        runner.record("test_initialize", False, str(exc))


def test_tools_list():
    """tools/list -> non-empty list containing known tools."""
    try:
        tools = client.tools_list()
        names = [t["name"] for t in tools]
        assert len(tools) > 0, "tools list is empty"
        assert "read_file" in names, "read_file not found"
        assert "list_directory" in names, "list_directory not found"
        assert "create_entities" in names, "create_entities not found"

        runner.record("test_tools_list", True, f"Found {len(tools)} tools")
    except Exception as exc:
        runner.record("test_tools_list", False, str(exc))


def test_read_file():
    """tools/call read_file -> content contains expected string."""
    try:
        text = client.call_tool_text(
            "read_file", {"path": os.path.join(TEST_DIR, "test.txt")}
        )
        assert "Hello from SentinelGate E2E test!" in text, f"unexpected content: {text!r}"
        runner.record("test_read_file", True, "Got expected content")
    except Exception as exc:
        runner.record("test_read_file", False, str(exc))


def test_list_directory():
    """tools/call list_directory -> contains test.txt."""
    try:
        text = client.call_tool_text("list_directory", {"path": TEST_DIR})
        assert "test.txt" in text, f"test.txt not found in listing: {text!r}"
        runner.record("test_list_directory", True, "Found test.txt in listing")
    except Exception as exc:
        runner.record("test_list_directory", False, str(exc))


def test_memory_create():
    """tools/call create_entities -> success (no isError)."""
    try:
        result = client.call_tool(
            "create_entities",
            {
                "entities": [
                    {
                        "name": "python-test",
                        "entityType": "test",
                        "observations": ["created by python e2e"],
                    }
                ]
            },
        )
        assert not result.get("isError"), f"create_entities returned error: {result}"
        runner.record("test_memory_create", True, "Entity created")
    except Exception as exc:
        runner.record("test_memory_create", False, str(exc))


def test_memory_read():
    """tools/call read_graph -> result contains python-test."""
    try:
        text = client.call_tool_text("read_graph", {})
        assert "python-test" in text, f"python-test not found in graph: {text[:200]!r}"
        runner.record("test_memory_read", True, "Found python-test entity")
    except Exception as exc:
        runner.record("test_memory_read", False, str(exc))


def test_policy_deny():
    """Create deny policy, verify write_file is blocked, then clean up."""
    policy_id: str | None = None
    try:
        # a. Create deny policy via admin API
        status, body = admin.post(
            "/policies",
            {
                "name": "e2e-deny-write",
                "priority": 200,
                "enabled": True,
                "rules": [
                    {
                        "name": "deny-write",
                        "priority": 1,
                        "tool_match": "write_file",
                        "condition": "true",
                        "action": "deny",
                    }
                ],
            },
        )
        assert status < 400, f"Failed to create policy: HTTP {status} — {body}"
        policy_id = body.get("id")
        assert policy_id, f"No policy id in response: {body}"

        # b. tools/call write_file -> should be denied
        result = client.call_tool(
            "write_file",
            {
                "path": os.path.join(TEST_DIR, "denied.txt"),
                "content": "should fail",
            },
        )
        assert result.get("isError") or result.get("error"), (
            f"write_file should have been denied but got: {result}"
        )

        runner.record("test_policy_deny", True, "write_file correctly denied")
    except Exception as exc:
        runner.record("test_policy_deny", False, str(exc))
    finally:
        # c. Always clean up the policy
        if policy_id:
            try:
                admin.delete(f"/policies/{policy_id}")
            except Exception:
                print(f"  WARNING: failed to delete policy {policy_id}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=== SentinelGate E2E \u2014 Python MCP Client ===\n")

    test_initialize()
    test_tools_list()
    test_read_file()
    test_list_directory()
    test_memory_create()
    test_memory_read()
    test_policy_deny()

    all_passed = runner.summary()
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
