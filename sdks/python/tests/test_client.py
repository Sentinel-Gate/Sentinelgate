"""Tests for the SentinelGate Python SDK client."""

import io
import json
import os
import unittest
import warnings
from unittest.mock import MagicMock, patch, call

from sentinelgate.client import SentinelGateClient
from sentinelgate.exceptions import (
    ApprovalTimeoutError,
    PolicyDeniedError,
    ServerUnreachableError,
    SentinelGateError,
)


def _mock_urlopen_response(data, status=200):
    """Create a mock urlopen response."""
    resp = MagicMock()
    resp.read.return_value = json.dumps(data).encode("utf-8")
    resp.status = status
    resp.getcode.return_value = status
    return resp


class TestSentinelGateClient(unittest.TestCase):
    """Tests for SentinelGateClient."""

    def setUp(self):
        self.client = SentinelGateClient(
            server_addr="http://localhost:8080",
            api_key="test-key",
        )

    @patch("sentinelgate.client.urllib.request.urlopen")
    def test_evaluate_allow(self, mock_urlopen):
        """Test evaluate() with allow response."""
        mock_urlopen.return_value = _mock_urlopen_response({
            "decision": "allow",
            "rule_id": "",
            "rule_name": "",
            "reason": "",
            "help_url": "",
            "help_text": "",
            "request_id": "req-123",
            "latency_ms": 2,
        })

        result = self.client.evaluate("command_exec", "ls")

        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["request_id"], "req-123")

        # Verify request was sent correctly
        mock_urlopen.assert_called_once()
        req = mock_urlopen.call_args[0][0]
        body = json.loads(req.data.decode("utf-8"))
        self.assertEqual(body["action_type"], "command_exec")
        self.assertEqual(body["action_name"], "ls")
        self.assertEqual(body["protocol"], "sdk")
        self.assertEqual(body["identity_name"], "sdk-client")
        self.assertEqual(body["identity_roles"], ["agent"])

    @patch("sentinelgate.client.urllib.request.urlopen")
    def test_evaluate_deny_raises(self, mock_urlopen):
        """Test evaluate() with deny response raises PolicyDeniedError."""
        mock_urlopen.return_value = _mock_urlopen_response({
            "decision": "deny",
            "rule_id": "rule-1",
            "rule_name": "block-rm",
            "reason": "rm is blocked",
            "help_url": "/admin/policies#rule-rule-1",
            "help_text": "Contact admin",
            "request_id": "req-456",
            "latency_ms": 1,
        })

        with self.assertRaises(PolicyDeniedError) as ctx:
            self.client.evaluate("command_exec", "rm")

        err = ctx.exception
        self.assertEqual(err.rule_id, "rule-1")
        self.assertEqual(err.rule_name, "block-rm")
        self.assertEqual(err.reason, "rm is blocked")
        self.assertEqual(err.help_url, "/admin/policies#rule-rule-1")
        self.assertEqual(err.help_text, "Contact admin")

    @patch("sentinelgate.client.urllib.request.urlopen")
    def test_evaluate_deny_no_raise(self, mock_urlopen):
        """Test evaluate() with raise_on_deny=False returns dict without raising."""
        mock_urlopen.return_value = _mock_urlopen_response({
            "decision": "deny",
            "rule_id": "rule-1",
            "rule_name": "block-rm",
            "reason": "rm is blocked",
            "help_url": "",
            "help_text": "",
            "request_id": "req-789",
            "latency_ms": 1,
        })

        result = self.client.evaluate("command_exec", "rm", raise_on_deny=False)

        self.assertEqual(result["decision"], "deny")
        self.assertEqual(result["rule_id"], "rule-1")

    @patch("sentinelgate.client.urllib.request.urlopen")
    def test_check_allow(self, mock_urlopen):
        """Test check() returns True on allow."""
        mock_urlopen.return_value = _mock_urlopen_response({
            "decision": "allow",
            "rule_id": "",
            "rule_name": "",
            "reason": "",
            "help_url": "",
            "help_text": "",
            "request_id": "req-1",
            "latency_ms": 1,
        })

        self.assertTrue(self.client.check("command_exec", "ls"))

    @patch("sentinelgate.client.urllib.request.urlopen")
    def test_check_deny(self, mock_urlopen):
        """Test check() returns False on deny."""
        mock_urlopen.return_value = _mock_urlopen_response({
            "decision": "deny",
            "rule_id": "rule-1",
            "rule_name": "",
            "reason": "denied",
            "help_url": "",
            "help_text": "",
            "request_id": "req-2",
            "latency_ms": 1,
        })

        self.assertFalse(self.client.check("command_exec", "rm"))

    def test_env_var_configuration(self):
        """Test client auto-configures from environment variables."""
        env = {
            "SENTINELGATE_SERVER_ADDR": "http://sentinel:9090",
            "SENTINELGATE_API_KEY": "env-key-123",
            "SENTINELGATE_FAIL_MODE": "closed",
            "SENTINELGATE_CACHE_TTL": "10",
            "SENTINELGATE_IDENTITY_NAME": "my-agent",
            "SENTINELGATE_IDENTITY_ROLES": "admin,user",
        }
        with patch.dict(os.environ, env, clear=False):
            client = SentinelGateClient()
            self.assertEqual(client._server_addr, "http://sentinel:9090")
            self.assertEqual(client._api_key, "env-key-123")
            self.assertEqual(client._fail_mode, "closed")
            self.assertEqual(client._cache_ttl, 10)

    @patch("sentinelgate.client.urllib.request.urlopen")
    def test_cache_hit(self, mock_urlopen):
        """Test LRU cache hit -- second call does not make HTTP request."""
        mock_urlopen.return_value = _mock_urlopen_response({
            "decision": "allow",
            "rule_id": "",
            "rule_name": "",
            "reason": "",
            "help_url": "",
            "help_text": "",
            "request_id": "req-cache",
            "latency_ms": 1,
        })

        # First call -- makes HTTP request
        result1 = self.client.evaluate("command_exec", "echo")
        self.assertEqual(result1["decision"], "allow")
        self.assertEqual(mock_urlopen.call_count, 1)

        # Second call -- should use cache
        result2 = self.client.evaluate("command_exec", "echo")
        self.assertEqual(result2["decision"], "allow")
        self.assertEqual(mock_urlopen.call_count, 1)  # No additional call

    @patch("sentinelgate.client.urllib.request.urlopen")
    def test_fail_open_on_connection_error(self, mock_urlopen):
        """Test fail-open on connection error (warnings.warn + allow)."""
        mock_urlopen.side_effect = ConnectionError("Connection refused")

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = self.client.evaluate("command_exec", "ls")

        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["reason"], "fail-open")
        self.assertEqual(len(w), 1)
        self.assertIn("fail-open", str(w[0].message))

    @patch("sentinelgate.client.urllib.request.urlopen")
    def test_fail_closed_on_connection_error(self, mock_urlopen):
        """Test fail-closed on connection error (raises ServerUnreachableError)."""
        client = SentinelGateClient(
            server_addr="http://localhost:8080",
            api_key="test-key",
            fail_mode="closed",
        )
        mock_urlopen.side_effect = ConnectionError("Connection refused")

        with self.assertRaises(ServerUnreachableError):
            client.evaluate("command_exec", "ls")

    @patch("sentinelgate.client.urllib.request.urlopen")
    @patch("sentinelgate.client.time.sleep")
    def test_approval_required_polling(self, mock_sleep, mock_urlopen):
        """Test approval_required polling (pending then approved)."""
        # First call: evaluation returns approval_required
        eval_response = _mock_urlopen_response({
            "decision": "approval_required",
            "rule_id": "rule-approval",
            "rule_name": "needs-approval",
            "reason": "requires human approval",
            "help_url": "",
            "help_text": "",
            "request_id": "req-approval-1",
            "latency_ms": 3,
        })

        # Second call (first poll): still pending
        pending_response = _mock_urlopen_response({
            "request_id": "req-approval-1",
            "status": "pending",
            "decision": "approval_required",
            "updated_at": "2026-01-01T00:00:00Z",
        })

        # Third call (second poll): approved
        approved_response = _mock_urlopen_response({
            "request_id": "req-approval-1",
            "status": "approved",
            "decision": "allow",
            "updated_at": "2026-01-01T00:00:02Z",
        })

        mock_urlopen.side_effect = [eval_response, pending_response, approved_response]

        result = self.client.evaluate("command_exec", "deploy")

        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["reason"], "approved")
        self.assertEqual(result["request_id"], "req-approval-1")
        self.assertEqual(mock_sleep.call_count, 2)

    @patch("sentinelgate.client.urllib.request.urlopen")
    def test_evaluate_identity_from_env(self, mock_urlopen):
        """Test that identity defaults come from env vars when set."""
        mock_urlopen.return_value = _mock_urlopen_response({
            "decision": "allow",
            "rule_id": "",
            "rule_name": "",
            "reason": "",
            "help_url": "",
            "help_text": "",
            "request_id": "req-env",
            "latency_ms": 1,
        })

        env = {
            "SENTINELGATE_IDENTITY_NAME": "my-bot",
            "SENTINELGATE_IDENTITY_ROLES": "admin,reviewer",
        }
        with patch.dict(os.environ, env, clear=False):
            self.client.evaluate("command_exec", "test-cmd")

        req = mock_urlopen.call_args[0][0]
        body = json.loads(req.data.decode("utf-8"))
        self.assertEqual(body["identity_name"], "my-bot")
        self.assertEqual(body["identity_roles"], ["admin", "reviewer"])

    def test_exception_hierarchy(self):
        """Test that all exceptions inherit from SentinelGateError."""
        self.assertTrue(issubclass(PolicyDeniedError, SentinelGateError))
        self.assertTrue(issubclass(ApprovalTimeoutError, SentinelGateError))
        self.assertTrue(issubclass(ServerUnreachableError, SentinelGateError))
        self.assertTrue(issubclass(SentinelGateError, Exception))


if __name__ == "__main__":
    unittest.main()
