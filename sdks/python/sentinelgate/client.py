"""SentinelGate Python SDK client."""

import collections
import json
import os
import threading
import time
import urllib.request
import warnings

from .exceptions import (
    ApprovalTimeoutError,
    PolicyDeniedError,
    ServerUnreachableError,
)


class SentinelGateClient:
    """Client for the SentinelGate Policy Decision API.

    Evaluates actions against policies and returns structured decisions.
    Uses only Python stdlib (no third-party dependencies).

    Args:
        server_addr: SentinelGate server address. Defaults to SENTINELGATE_SERVER_ADDR env var.
        api_key: API key for authentication. Defaults to SENTINELGATE_API_KEY env var.
        default_protocol: Protocol identifier sent with requests. Defaults to "sdk".
        fail_mode: Behavior when server is unreachable: "open" (allow) or "closed" (raise).
            Defaults to SENTINELGATE_FAIL_MODE env var or "open".
        timeout: HTTP request timeout in seconds. Defaults to 5.
        cache_ttl: LRU cache TTL in seconds. Defaults to SENTINELGATE_CACHE_TTL env var or 5.
        cache_max_size: Maximum number of cached entries. Defaults to 1000.
    """

    def __init__(
        self,
        server_addr=None,
        api_key=None,
        default_protocol="sdk",
        fail_mode=None,
        timeout=5,
        cache_ttl=None,
        cache_max_size=1000,
    ):
        self._server_addr = (
            server_addr or os.environ.get("SENTINELGATE_SERVER_ADDR", "")
        ).rstrip("/")
        self._api_key = api_key or os.environ.get("SENTINELGATE_API_KEY", "")
        self._default_protocol = default_protocol
        self._fail_mode = (
            fail_mode or os.environ.get("SENTINELGATE_FAIL_MODE", "open")
        )
        self._timeout = timeout

        ttl = cache_ttl
        if ttl is None:
            ttl = int(os.environ.get("SENTINELGATE_CACHE_TTL", "5"))
        self._cache_ttl = ttl

        self._cache_max_size = cache_max_size

        # LRU cache: OrderedDict keyed by cache_key -> (response_dict, timestamp)
        self._cache = collections.OrderedDict()
        self._cache_lock = threading.Lock()

    # -- Public API -----------------------------------------------------------

    def evaluate(
        self,
        action_type,
        action_name,
        arguments=None,
        destination=None,
        identity_name=None,
        identity_roles=None,
        protocol=None,
        framework=None,
        raise_on_deny=True,
    ):
        """Evaluate an action against the Policy Decision API.

        Args:
            action_type: Type of action (e.g. "command_exec", "file_access", "http_request").
            action_name: Name of the action (e.g. command name, HTTP method).
            arguments: Optional dict of action arguments.
            destination: Optional destination dict (url, domain, port, scheme, path).
            identity_name: Identity name. Defaults to SENTINELGATE_IDENTITY_NAME env or "sdk-client".
            identity_roles: Identity roles list. Defaults to SENTINELGATE_IDENTITY_ROLES env
                (comma-separated) or ["agent"].
            protocol: Protocol string. Defaults to default_protocol ("sdk").
            framework: Framework hint string.
            raise_on_deny: If True (default), raises PolicyDeniedError on deny decisions.

        Returns:
            dict with keys: decision, rule_id, rule_name, reason, help_url, help_text,
            request_id, latency_ms.

        Raises:
            PolicyDeniedError: If decision is "deny" and raise_on_deny is True.
            ApprovalTimeoutError: If approval polling times out.
            ServerUnreachableError: If server is unreachable and fail_mode is "closed".
        """
        # Resolve identity defaults
        if identity_name is None:
            identity_name = os.environ.get("SENTINELGATE_IDENTITY_NAME", "sdk-client")
        if identity_roles is None:
            roles_env = os.environ.get("SENTINELGATE_IDENTITY_ROLES", "")
            if roles_env:
                identity_roles = [r.strip() for r in roles_env.split(",") if r.strip()]
            else:
                identity_roles = ["agent"]

        proto = protocol or self._default_protocol

        # Check LRU cache
        cache_key = self._cache_key(action_type, action_name, arguments)
        with self._cache_lock:
            if cache_key in self._cache:
                entry = self._cache[cache_key]
                if (time.time() - entry[1]) < self._cache_ttl:
                    self._cache.move_to_end(cache_key)
                    return entry[0]
                else:
                    del self._cache[cache_key]

        # Build request body matching PolicyEvaluateRequest schema
        body = {
            "action_type": action_type,
            "action_name": action_name,
            "protocol": proto,
            "identity_name": identity_name,
            "identity_roles": identity_roles,
        }
        if framework:
            body["framework"] = framework
        if arguments:
            body["arguments"] = arguments
        if destination:
            body["destination"] = destination

        # Send request
        try:
            url = "{}/admin/api/v1/policy/evaluate".format(self._server_addr)
            data = json.dumps(body).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer {}".format(self._api_key),
                },
                method="POST",
            )
            resp = urllib.request.urlopen(req, timeout=self._timeout)
            resp_data = json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            if self._fail_mode == "closed":
                raise ServerUnreachableError(
                    "SentinelGate server unreachable: {}".format(exc)
                )
            warnings.warn(
                "SentinelGate: Policy evaluation failed ({}), allowing action (fail-open)".format(exc),
                RuntimeWarning,
                stacklevel=2,
            )
            return {
                "decision": "allow",
                "reason": "fail-open",
                "rule_id": "",
                "rule_name": "",
                "help_url": "",
                "help_text": "",
                "request_id": "",
                "latency_ms": 0,
            }

        decision = resp_data.get("decision", "allow")

        # Handle approval_required by polling status endpoint
        if decision == "approval_required":
            request_id = resp_data.get("request_id", "")
            if request_id:
                return self._poll_approval(request_id, resp_data, raise_on_deny)
            # No request_id; return as-is
            return resp_data

        # Cache allow decisions
        if decision == "allow":
            with self._cache_lock:
                self._cache[cache_key] = (resp_data, time.time())
                while len(self._cache) > self._cache_max_size:
                    self._cache.popitem(last=False)

        # Raise on deny if configured
        if decision == "deny" and raise_on_deny:
            raise PolicyDeniedError(
                message="Policy denied: {}".format(resp_data.get("reason", "")),
                rule_id=resp_data.get("rule_id", ""),
                rule_name=resp_data.get("rule_name", ""),
                reason=resp_data.get("reason", ""),
                help_url=resp_data.get("help_url", ""),
                help_text=resp_data.get("help_text", ""),
            )

        return resp_data

    def check(self, action_type, action_name, **kwargs):
        """Check if an action is allowed without raising exceptions.

        Returns True if allowed, False if denied. Never raises PolicyDeniedError.
        All keyword arguments are forwarded to evaluate().

        Args:
            action_type: Type of action.
            action_name: Name of the action.

        Returns:
            bool: True if allowed, False if denied.
        """
        kwargs["raise_on_deny"] = False
        try:
            result = self.evaluate(action_type, action_name, **kwargs)
            return result.get("decision", "allow") == "allow"
        except Exception:
            # On any error, return True (fail-open behavior for check)
            return True

    # -- Approval Polling -----------------------------------------------------

    def _poll_approval(self, request_id, original_response, raise_on_deny):
        """Poll the evaluation status endpoint until approved, denied, or timeout."""
        url = "{}/admin/api/v1/policy/evaluate/{}/status".format(
            self._server_addr, request_id
        )
        max_polls = 30
        poll_interval = 2  # seconds

        for _ in range(max_polls):
            time.sleep(poll_interval)
            try:
                req = urllib.request.Request(
                    url,
                    headers={
                        "Authorization": "Bearer {}".format(self._api_key),
                    },
                    method="GET",
                )
                resp = urllib.request.urlopen(req, timeout=self._timeout)
                status_data = json.loads(resp.read().decode("utf-8"))
                status = status_data.get("status", "")

                if status in ("approved", "allow"):
                    return {
                        "decision": "allow",
                        "reason": "approved",
                        "request_id": request_id,
                        "rule_id": original_response.get("rule_id", ""),
                        "rule_name": original_response.get("rule_name", ""),
                        "help_url": "",
                        "help_text": "",
                        "latency_ms": original_response.get("latency_ms", 0),
                    }
                elif status in ("denied", "deny"):
                    result = {
                        "decision": "deny",
                        "reason": status_data.get("reason", "denied by reviewer"),
                        "request_id": request_id,
                        "rule_id": original_response.get("rule_id", ""),
                        "rule_name": original_response.get("rule_name", ""),
                        "help_url": original_response.get("help_url", ""),
                        "help_text": original_response.get("help_text", ""),
                        "latency_ms": original_response.get("latency_ms", 0),
                    }
                    if raise_on_deny:
                        raise PolicyDeniedError(
                            message="Policy denied: {}".format(result["reason"]),
                            rule_id=result["rule_id"],
                            rule_name=result["rule_name"],
                            reason=result["reason"],
                            help_url=result["help_url"],
                            help_text=result["help_text"],
                        )
                    return result
            except (PolicyDeniedError,):
                raise
            except Exception:
                continue

        raise ApprovalTimeoutError(
            message="Approval timed out after {}s".format(max_polls * poll_interval),
            request_id=request_id,
        )

    # -- Cache Key ------------------------------------------------------------

    def _cache_key(self, action_type, action_name, arguments):
        """Build a hashable cache key from action parameters."""
        if arguments:
            args_repr = repr(sorted(arguments.items()))
        else:
            args_repr = ""
        return (action_type, action_name, args_repr)
