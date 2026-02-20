"""
SentinelGate Python Runtime Bootstrap (sitecustomize.py)

This file is automatically placed on PYTHONPATH by `sentinel-gate run`.
Python imports sitecustomize.py before any user code, allowing transparent
monkey-patching of subprocess, open, requests, urllib, and httpx to intercept
all agent actions and evaluate them against the SentinelGate Policy Decision API.

Environment variables consumed:
    SENTINELGATE_SERVER_ADDR  - SentinelGate server address (required to activate)
    SENTINELGATE_API_KEY      - Runtime API key for authentication
    SENTINELGATE_AGENT_ID     - Unique agent process identifier
    SENTINELGATE_CACHE_TTL    - LRU cache TTL in seconds (default: 5)
    SENTINELGATE_FAIL_MODE    - Fail mode: "open" (default) or "closed"
    SENTINELGATE_FRAMEWORK    - Framework hint from Go-side detection (may be empty)
"""

import os as _os
import sys as _sys

# ---------------------------------------------------------------------------
# 1. Configuration
# ---------------------------------------------------------------------------

_SERVER_ADDR = _os.environ.get("SENTINELGATE_SERVER_ADDR", "")
_API_KEY = _os.environ.get("SENTINELGATE_API_KEY", "")
_AGENT_ID = _os.environ.get("SENTINELGATE_AGENT_ID", "")
_CACHE_TTL = int(_os.environ.get("SENTINELGATE_CACHE_TTL", "5"))
_FAIL_MODE = _os.environ.get("SENTINELGATE_FAIL_MODE", "open")

# Only activate instrumentation when server address is configured.
_ENABLED = bool(_SERVER_ADDR)

if _ENABLED:
    # ---------------------------------------------------------------------------
    # Imports needed for instrumentation (imported before any patching)
    # ---------------------------------------------------------------------------
    import builtins as _builtins
    import collections as _collections
    import json as _json
    import subprocess as _subprocess
    import threading as _threading
    import time as _time
    import urllib.request as _urllib_request
    import warnings as _warnings
    from urllib.parse import urlparse as _urlparse

    # Save original urllib.request.urlopen BEFORE any patching so the client
    # can use it without circular imports.
    _original_urlopen = _urllib_request.urlopen

    # ---------------------------------------------------------------------------
    # 1b. Framework Detection
    # ---------------------------------------------------------------------------

    def _detect_framework():
        """Detect the AI framework in use by probing installed packages.

        Checks for LangChain, CrewAI, AutoGen, and OpenAI Agents SDK via
        import probing. Falls back to SENTINELGATE_FRAMEWORK env var if set.
        Returns empty string if no framework is detected.
        """
        try:
            import langchain  # noqa: F401
            return "langchain"
        except ImportError:
            pass

        try:
            import crewai  # noqa: F401
            return "crewai"
        except ImportError:
            pass

        try:
            import autogen  # noqa: F401
            return "autogen"
        except ImportError:
            pass

        try:
            import openai as _openai_probe
            if hasattr(_openai_probe, "agents") or hasattr(_openai_probe, "swarm"):
                return "openai-agents-sdk"
        except ImportError:
            pass

        # Fall back to env var hint from Go-side detection.
        env_hint = _os.environ.get("SENTINELGATE_FRAMEWORK", "")
        if env_hint:
            return env_hint

        return ""

    # ---------------------------------------------------------------------------
    # 2. SentinelGate Client
    # ---------------------------------------------------------------------------

    class _SentinelGateClient:
        """Communicates with the SentinelGate Policy Decision API."""

        def __init__(self, server_addr, api_key, agent_id, cache_ttl, framework="", fail_mode="open"):
            self._server_addr = server_addr.rstrip("/")
            self._api_key = api_key
            self._agent_id = agent_id
            self._cache_ttl = cache_ttl  # seconds
            self._framework = framework
            self._fail_mode = fail_mode

            # LRU cache: OrderedDict keyed by cache_key -> (decision_dict, timestamp)
            self._cache = _collections.OrderedDict()
            self._cache_max = 1000
            self._cache_lock = _threading.Lock()

            # Audit buffer for offline events
            self._audit_buffer = []
            self._audit_lock = _threading.Lock()

        # -- Public API --------------------------------------------------------

        def evaluate(self, action_type, action_name, arguments=None, destination=None):
            """Evaluate an action against the Policy Decision API.

            Returns a dict with at least 'decision' key ('allow', 'deny', 'approval_required').
            """
            cache_key = self._cache_key(action_type, action_name, arguments)

            # Check LRU cache
            with self._cache_lock:
                if cache_key in self._cache:
                    entry = self._cache[cache_key]
                    if (_time.time() - entry[1]) < self._cache_ttl:
                        # Move to end (most recently used)
                        self._cache.move_to_end(cache_key)
                        return entry[0]
                    else:
                        # Expired
                        del self._cache[cache_key]

            # Build request body matching PolicyEvaluateRequest schema
            body = {
                "action_type": action_type,
                "action_name": action_name,
                "protocol": "runtime",
                "framework": self._framework,
                "gateway": "runtime",
                "arguments": arguments or {},
                "identity_name": "runtime-{}".format(self._agent_id),
                "identity_roles": ["agent"],
            }
            if destination:
                body["destination"] = destination

            try:
                url = "{}/admin/api/v1/policy/evaluate".format(self._server_addr)
                data = _json.dumps(body).encode("utf-8")
                req = _urllib_request.Request(
                    url,
                    data=data,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": "Bearer {}".format(self._api_key),
                    },
                    method="POST",
                )
                resp = _original_urlopen(req, timeout=5)
                resp_data = _json.loads(resp.read().decode("utf-8"))
            except Exception as exc:
                if self._fail_mode == "closed":
                    # Fail-closed: deny on connection error
                    self._buffer_audit_event(action_type, action_name, arguments, "deny", "fail-closed")
                    raise PermissionError(
                        "SentinelGate: Action denied - server unreachable (fail-closed mode)"
                    )
                # Fail-open: allow on connection error
                _warnings.warn(
                    "SentinelGate: Policy evaluation failed ({}), allowing action (fail-open)".format(exc),
                    RuntimeWarning,
                    stacklevel=2,
                )
                self._buffer_audit_event(action_type, action_name, arguments, "allow", "fail-open")
                return {"decision": "allow", "reason": "fail-open"}

            decision = resp_data.get("decision", "allow")

            if decision == "approval_required":
                request_id = resp_data.get("request_id", "")
                if request_id:
                    return self._poll_approval(request_id, resp_data)
                # No request_id means we can't poll; deny
                return resp_data

            # Cache "allow" decisions
            if decision == "allow":
                with self._cache_lock:
                    self._cache[cache_key] = (resp_data, _time.time())
                    # Evict oldest if over max
                    while len(self._cache) > self._cache_max:
                        self._cache.popitem(last=False)

            return resp_data

        # -- Approval Polling --------------------------------------------------

        def _poll_approval(self, request_id, original_response):
            """Poll the evaluation status endpoint until approved, denied, or timeout."""
            url = "{}/admin/api/v1/policy/evaluate/{}/status".format(
                self._server_addr, request_id
            )
            max_polls = 30
            poll_interval = 2  # seconds

            for _ in range(max_polls):
                _time.sleep(poll_interval)
                try:
                    req = _urllib_request.Request(
                        url,
                        headers={
                            "Authorization": "Bearer {}".format(self._api_key),
                        },
                        method="GET",
                    )
                    resp = _original_urlopen(req, timeout=5)
                    status_data = _json.loads(resp.read().decode("utf-8"))
                    status = status_data.get("status", "")

                    if status == "approved" or status == "allow":
                        return {"decision": "allow", "reason": "approved", "request_id": request_id}
                    elif status == "denied" or status == "deny":
                        return {
                            "decision": "deny",
                            "reason": status_data.get("reason", "denied by reviewer"),
                            "request_id": request_id,
                            "help_text": original_response.get("help_text", ""),
                        }
                except Exception:
                    # Network error during polling; continue trying
                    continue

            # Timeout: deny by default
            return {
                "decision": "deny",
                "reason": "approval timeout after {}s".format(max_polls * poll_interval),
                "request_id": request_id,
            }

        # -- Cache Key ---------------------------------------------------------

        def _cache_key(self, action_type, action_name, arguments):
            """Build a hashable cache key from action parameters."""
            if arguments:
                # Sort for deterministic representation
                args_repr = repr(sorted(arguments.items()))
            else:
                args_repr = ""
            return (action_type, action_name, args_repr)

        # -- Audit Buffer ------------------------------------------------------

        def _buffer_audit_event(self, action_type, action_name, arguments, decision, reason):
            """Store an audit event locally when the server is unreachable."""
            event = {
                "action_type": action_type,
                "action_name": action_name,
                "arguments": arguments or {},
                "decision": decision,
                "reason": reason,
                "timestamp": _time.time(),
                "agent_id": self._agent_id,
            }
            with self._audit_lock:
                self._audit_buffer.append(event)

        def _audit_buffer_flush(self):
            """Attempt to flush buffered audit events to the server."""
            with self._audit_lock:
                if not self._audit_buffer:
                    return
                events = list(self._audit_buffer)
                self._audit_buffer.clear()

            # Best-effort flush; re-buffer on failure
            try:
                url = "{}/admin/api/v1/audit/events".format(self._server_addr)
                data = _json.dumps({"events": events}).encode("utf-8")
                req = _urllib_request.Request(
                    url,
                    data=data,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": "Bearer {}".format(self._api_key),
                    },
                    method="POST",
                )
                _original_urlopen(req, timeout=5)
            except Exception:
                # Re-buffer events on failure
                with self._audit_lock:
                    self._audit_buffer = events + self._audit_buffer

    # ---------------------------------------------------------------------------
    # Instantiate client
    # ---------------------------------------------------------------------------

    _client = _SentinelGateClient(
        _SERVER_ADDR, _API_KEY, _AGENT_ID, _CACHE_TTL,
        framework=_detect_framework(), fail_mode=_FAIL_MODE,
    )

    # ---------------------------------------------------------------------------
    # 3. Subprocess Interception
    # ---------------------------------------------------------------------------

    _original_run = _subprocess.run
    _original_popen_init = _subprocess.Popen.__init__
    _original_call = _subprocess.call
    _original_check_call = _subprocess.check_call
    _original_check_output = _subprocess.check_output

    def _extract_command(args, kwargs):
        """Extract command name and full command from subprocess args."""
        cmd = args[0] if args else kwargs.get("args")
        if cmd is None:
            return "", [], ""
        if isinstance(cmd, str):
            parts = cmd.split()
            cmd_name = parts[0] if parts else cmd
            return cmd_name, parts, cmd
        elif isinstance(cmd, (list, tuple)):
            cmd_list = [str(c) for c in cmd]
            cmd_name = cmd_list[0] if cmd_list else ""
            return cmd_name, cmd_list, " ".join(cmd_list)
        return str(cmd), [str(cmd)], str(cmd)

    def _check_subprocess_decision(args, kwargs):
        """Evaluate a subprocess action; raise PermissionError if denied."""
        cmd_name, cmd_args, full_command = _extract_command(args, kwargs)
        if not cmd_name:
            return  # No command to evaluate
        result = _client.evaluate(
            "command_exec",
            cmd_name,
            {"args": cmd_args, "full_command": full_command},
        )
        decision = result.get("decision", "allow")
        if decision == "deny":
            reason = result.get("reason", "policy denied")
            help_text = result.get("help_text", "")
            msg = "SentinelGate: Action denied - {}".format(reason)
            if help_text:
                msg += ". {}".format(help_text)
            raise PermissionError(msg)

    def _sg_run(*args, **kwargs):
        _check_subprocess_decision(args, kwargs)
        return _original_run(*args, **kwargs)

    def _sg_popen_init(self, *args, **kwargs):
        _check_subprocess_decision(args, kwargs)
        return _original_popen_init(self, *args, **kwargs)

    def _sg_call(*args, **kwargs):
        _check_subprocess_decision(args, kwargs)
        return _original_call(*args, **kwargs)

    def _sg_check_call(*args, **kwargs):
        _check_subprocess_decision(args, kwargs)
        return _original_check_call(*args, **kwargs)

    def _sg_check_output(*args, **kwargs):
        _check_subprocess_decision(args, kwargs)
        return _original_check_output(*args, **kwargs)

    _subprocess.run = _sg_run
    _subprocess.Popen.__init__ = _sg_popen_init
    _subprocess.call = _sg_call
    _subprocess.check_call = _sg_check_call
    _subprocess.check_output = _sg_check_output

    # os.system interception
    _original_os_system = _os.system

    def _sg_os_system(command):
        if isinstance(command, str):
            parts = command.split()
            cmd_name = parts[0] if parts else command
            result = _client.evaluate(
                "command_exec",
                cmd_name,
                {"args": parts, "full_command": command},
            )
            decision = result.get("decision", "allow")
            if decision == "deny":
                reason = result.get("reason", "policy denied")
                help_text = result.get("help_text", "")
                msg = "SentinelGate: Action denied - {}".format(reason)
                if help_text:
                    msg += ". {}".format(help_text)
                raise PermissionError(msg)
        return _original_os_system(command)

    _os.system = _sg_os_system

    # ---------------------------------------------------------------------------
    # 4. File Access Interception
    # ---------------------------------------------------------------------------

    _original_open = _builtins.open

    # Paths to skip interception (import internals, system paths, bootstrap dir)
    _SKIP_PATH_PREFIXES = ("/dev/", "/proc/", "/sys/")
    _SKIP_PATH_CONTAINS = (".pyc", "__pycache__", "site-packages")

    # The bootstrap directory itself (avoid intercepting our own imports)
    _BOOTSTRAP_DIR = _os.path.dirname(_os.path.abspath(__file__))

    def _sg_open(*args, **kwargs):
        # Extract path
        file_path = args[0] if args else kwargs.get("file", kwargs.get("name", None))
        if file_path is None:
            return _original_open(*args, **kwargs)

        file_path_str = str(file_path)

        # Skip system/internal paths
        for prefix in _SKIP_PATH_PREFIXES:
            if file_path_str.startswith(prefix):
                return _original_open(*args, **kwargs)
        for pattern in _SKIP_PATH_CONTAINS:
            if pattern in file_path_str:
                return _original_open(*args, **kwargs)
        if file_path_str.startswith(_BOOTSTRAP_DIR):
            return _original_open(*args, **kwargs)

        # Extract mode
        mode = "r"
        if len(args) > 1:
            mode = args[1]
        else:
            mode = kwargs.get("mode", "r")

        # Determine access type
        if any(m in mode for m in ("w", "a", "x")):
            if "+" in mode:
                access = "readwrite"
            else:
                access = "write"
        elif "+" in mode:
            access = "readwrite"
        else:
            access = "read"

        result = _client.evaluate(
            "file_access",
            "open",
            {"path": file_path_str, "mode": mode, "access": access},
        )
        decision = result.get("decision", "allow")
        if decision == "deny":
            reason = result.get("reason", "policy denied")
            help_text = result.get("help_text", "")
            msg = "SentinelGate: Action denied - {}".format(reason)
            if help_text:
                msg += ". {}".format(help_text)
            raise PermissionError(msg)

        return _original_open(*args, **kwargs)

    _builtins.open = _sg_open

    # ---------------------------------------------------------------------------
    # 5. Network Interception (requests library)
    # ---------------------------------------------------------------------------

    def _make_requests_wrapper(method, original_fn):
        """Create a wrapper for a requests.api method."""
        def wrapper(*args, **kwargs):
            url = args[0] if args else kwargs.get("url", "")
            url_str = str(url)
            parsed = _urlparse(url_str)
            domain = parsed.hostname or ""
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            destination = {
                "url": url_str,
                "domain": domain,
                "scheme": parsed.scheme or "",
                "path": parsed.path or "",
                "port": port,
            }
            # Extract headers if provided
            headers = kwargs.get("headers", {})
            arguments = {
                "url": url_str,
                "headers": dict(headers) if headers else {},
            }

            result = _client.evaluate(
                "http_request",
                method.upper(),
                arguments=arguments,
                destination=destination,
            )
            decision = result.get("decision", "allow")
            if decision == "deny":
                reason = result.get("reason", "policy denied")
                help_text = result.get("help_text", "")
                msg = "SentinelGate: Action denied - {}".format(reason)
                if help_text:
                    msg += ". {}".format(help_text)
                raise PermissionError(msg)

            return original_fn(*args, **kwargs)
        wrapper.__name__ = "_sg_requests_{}".format(method)
        wrapper.__qualname__ = wrapper.__name__
        return wrapper

    try:
        import requests as _requests
        import requests.api as _requests_api

        _REQUESTS_METHODS = ("get", "post", "put", "delete", "patch", "head", "options")
        _original_requests = {}

        for _method in _REQUESTS_METHODS:
            _original_requests[_method] = getattr(_requests_api, _method)
            _wrapper = _make_requests_wrapper(_method, _original_requests[_method])
            setattr(_requests_api, _method, _wrapper)
            # Also patch the re-exported module-level functions
            setattr(_requests, _method, _wrapper)
    except ImportError:
        pass  # requests not installed; skip

    # ---------------------------------------------------------------------------
    # 6. Network Interception (urllib.request.urlopen)
    # ---------------------------------------------------------------------------

    def _sg_urlopen(*args, **kwargs):
        request = args[0] if args else kwargs.get("url", None)
        if request is None:
            return _original_urlopen(*args, **kwargs)

        # Extract URL from string or Request object
        if isinstance(request, _urllib_request.Request):
            url_str = request.full_url
        else:
            url_str = str(request)

        parsed = _urlparse(url_str)
        domain = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        destination = {
            "url": url_str,
            "domain": domain,
            "scheme": parsed.scheme or "",
            "path": parsed.path or "",
            "port": port,
        }
        arguments = {"url": url_str}

        result = _client.evaluate(
            "http_request",
            "URLOPEN",
            arguments=arguments,
            destination=destination,
        )
        decision = result.get("decision", "allow")
        if decision == "deny":
            reason = result.get("reason", "policy denied")
            help_text = result.get("help_text", "")
            msg = "SentinelGate: Action denied - {}".format(reason)
            if help_text:
                msg += ". {}".format(help_text)
            raise PermissionError(msg)

        return _original_urlopen(*args, **kwargs)

    _urllib_request.urlopen = _sg_urlopen

    # ---------------------------------------------------------------------------
    # 7. Network Interception (httpx library)
    # ---------------------------------------------------------------------------

    def _make_httpx_wrapper(method, original_fn, is_module_level=False):
        """Create a wrapper for an httpx method."""
        def wrapper(*args, **kwargs):
            if is_module_level:
                url = args[0] if args else kwargs.get("url", "")
            else:
                # Instance method: self is first arg, url is second
                url = args[1] if len(args) > 1 else kwargs.get("url", "")
            url_str = str(url)
            parsed = _urlparse(url_str)
            domain = parsed.hostname or ""
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            destination = {
                "url": url_str,
                "domain": domain,
                "scheme": parsed.scheme or "",
                "path": parsed.path or "",
                "port": port,
            }
            headers = kwargs.get("headers", {})
            arguments = {
                "url": url_str,
                "headers": dict(headers) if headers else {},
            }

            result = _client.evaluate(
                "http_request",
                method.upper(),
                arguments=arguments,
                destination=destination,
            )
            decision = result.get("decision", "allow")
            if decision == "deny":
                reason = result.get("reason", "policy denied")
                help_text = result.get("help_text", "")
                msg = "SentinelGate: Action denied - {}".format(reason)
                if help_text:
                    msg += ". {}".format(help_text)
                raise PermissionError(msg)

            return original_fn(*args, **kwargs)
        wrapper.__name__ = "_sg_httpx_{}".format(method)
        wrapper.__qualname__ = wrapper.__name__
        return wrapper

    try:
        import httpx as _httpx

        _HTTPX_METHODS = ("get", "post", "put", "delete", "patch", "head", "options")
        _original_httpx = {}
        _original_httpx_client = {}
        _original_httpx_async = {}

        # Patch module-level convenience functions
        for _method in _HTTPX_METHODS:
            if hasattr(_httpx, _method):
                _original_httpx[_method] = getattr(_httpx, _method)
                _wrapper = _make_httpx_wrapper(_method, _original_httpx[_method], is_module_level=True)
                setattr(_httpx, _method, _wrapper)

        # Patch httpx.Client instance methods
        for _method in _HTTPX_METHODS:
            if hasattr(_httpx.Client, _method):
                _original_httpx_client[_method] = getattr(_httpx.Client, _method)
                _wrapper = _make_httpx_wrapper(_method, _original_httpx_client[_method], is_module_level=False)
                setattr(_httpx.Client, _method, _wrapper)

        # Patch httpx.AsyncClient instance methods
        for _method in _HTTPX_METHODS:
            if hasattr(_httpx.AsyncClient, _method):
                _original_httpx_async[_method] = getattr(_httpx.AsyncClient, _method)
                # Note: async methods need async wrappers, but the evaluate call is sync.
                # We wrap the sync evaluation around the async call.
                _orig = _original_httpx_async[_method]

                def _make_async_wrapper(m, orig_fn):
                    async def async_wrapper(*args, **kwargs):
                        # Instance method: self is first arg, url is second
                        url = args[1] if len(args) > 1 else kwargs.get("url", "")
                        url_str = str(url)
                        parsed = _urlparse(url_str)
                        domain = parsed.hostname or ""
                        port = parsed.port or (443 if parsed.scheme == "https" else 80)
                        destination = {
                            "url": url_str,
                            "domain": domain,
                            "scheme": parsed.scheme or "",
                            "path": parsed.path or "",
                            "port": port,
                        }
                        headers = kwargs.get("headers", {})
                        arguments = {
                            "url": url_str,
                            "headers": dict(headers) if headers else {},
                        }
                        result = _client.evaluate(
                            "http_request",
                            m.upper(),
                            arguments=arguments,
                            destination=destination,
                        )
                        decision = result.get("decision", "allow")
                        if decision == "deny":
                            reason = result.get("reason", "policy denied")
                            help_text = result.get("help_text", "")
                            msg = "SentinelGate: Action denied - {}".format(reason)
                            if help_text:
                                msg += ". {}".format(help_text)
                            raise PermissionError(msg)
                        return await orig_fn(*args, **kwargs)
                    async_wrapper.__name__ = "_sg_httpx_async_{}".format(m)
                    async_wrapper.__qualname__ = async_wrapper.__name__
                    return async_wrapper

                setattr(_httpx.AsyncClient, _method, _make_async_wrapper(_method, _orig))
    except ImportError:
        pass  # httpx not installed; skip
