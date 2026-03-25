#!/usr/bin/env python3
"""Minimal MCP client testing through SentinelGate proxy — Session A6."""
import json
import os
import sys
import urllib.request
import urllib.error

PROXY_URL = os.environ.get("SG_PROXY_URL", "http://localhost:8080/mcp")
API_KEY = os.environ.get("SG_API_KEY", "")

passed = 0
failed = 0
req_id = 0


def mcp_call(method, params=None):
    global req_id
    req_id += 1
    payload = json.dumps({
        "jsonrpc": "2.0",
        "id": req_id,
        "method": method,
        "params": params or {}
    }).encode()
    req = urllib.request.Request(
        PROXY_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {API_KEY}"
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}", "body": e.read().decode()[:200]}
    except Exception as e:
        return {"error": str(e)}


def check(test_name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"PASS:{test_name}:{detail}")
    else:
        failed += 1
        print(f"FAIL:{test_name}:{detail}")


def main():
    if not API_KEY:
        print("FAIL:setup:SG_API_KEY environment variable required")
        sys.exit(1)

    # Test 1: Initialize
    result = mcp_call("initialize", {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "python-test-agent", "version": "1.0"}
    })
    has_server_info = "result" in result and "serverInfo" in result.get("result", {})
    check("initialize", has_server_info,
          result.get("result", {}).get("serverInfo", {}).get("name", "?"))

    # Test 2: List tools
    result = mcp_call("tools/list")
    tools = result.get("result", {}).get("tools", [])
    check("tools_list", len(tools) > 0, f"{len(tools)} tools")
    for t in tools[:5]:
        print(f"  TOOL: {t['name']}: {t.get('description', '')[:60]}")

    # Test 3: Call echo tool
    result = mcp_call("tools/call", {
        "name": "echo",
        "arguments": {"message": "Hello from Python agent!"}
    })
    has_result = "result" in result
    content_text = ""
    if has_result:
        contents = result["result"].get("content", [])
        if contents:
            content_text = contents[0].get("text", "")
    check("tool_call_echo", has_result and "Hello" in content_text, content_text[:80])

    # Test 4: Call get-sum tool
    result = mcp_call("tools/call", {
        "name": "get-sum",
        "arguments": {"a": 7, "b": 13}
    })
    has_result = "result" in result
    content_text = ""
    if has_result:
        contents = result["result"].get("content", [])
        if contents:
            content_text = contents[0].get("text", "")
    check("tool_call_get_sum", has_result and "20" in content_text, content_text[:80])

    # Summary
    print(f"SUMMARY:{passed}:{failed}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
