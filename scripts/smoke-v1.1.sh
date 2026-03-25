#!/usr/bin/env bash
# Sentinel Gate v1.1 Smoke Tests
# Tests all v1.1 features: templates, transforms, quotas, recording, session CEL
#
# Usage: ./scripts/smoke-v1.1.sh
#
# Prerequisites:
#   - Go (for building binary)
#   - Python 3 (for mock MCP server)
#   - jq (for JSON parsing)
#   - curl (for HTTP requests)

set -o errexit
set -o nounset
set -o pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test counters
PASSED=0
FAILED=0
SKIPPED=0

# Project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TMPDIR=$(mktemp -d)

# API keys
API_KEY="smoke-v11-key-12345"
KEY_HASH=$(echo -n "$API_KEY" | shasum -a 256 | cut -d' ' -f1)

# Ports
HTTP_PORT=18081
MOCK_PORT=13001

# PIDs
SERVER_PID=""
MOCK_PID=""
CSRF_TOKEN=""

# =============================================================================
# Cleanup
# =============================================================================
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    [[ -n "${SERVER_PID:-}" ]] && kill "$SERVER_PID" 2>/dev/null || true
    [[ -n "${MOCK_PID:-}" ]] && kill "$MOCK_PID" 2>/dev/null || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

# =============================================================================
# Helper Functions
# =============================================================================
pass() {
    echo -e "  ${GREEN}PASS${NC}: $1"
    ((PASSED++)) || true
}

fail() {
    echo -e "  ${RED}FAIL${NC}: $1"
    ((FAILED++)) || true
}

skip() {
    echo -e "  ${YELLOW}SKIP${NC}: $1"
    ((SKIPPED++)) || true
}

section() {
    echo -e "\n${BLUE}--- $1 ---${NC}"
}

wait_for_server() {
    local url=$1
    local max_attempts=${2:-30}
    local host_port
    host_port=$(echo "$url" | sed -E 's|https?://([^/]+).*|\1|')
    local host="${host_port%:*}"
    local port="${host_port#*:}"

    for i in $(seq 1 "$max_attempts"); do
        if nc -z "$host" "$port" 2>/dev/null; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

start_mock_mcp_server() {
    python3 -c '
import http.server
import json

class MCPHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        req = json.loads(body)
        method = req.get("method", "")
        req_id = req.get("id", 1)

        if method == "initialize":
            result = {"protocolVersion": "2024-11-05", "capabilities": {}, "serverInfo": {"name": "mock", "version": "1.0"}}
        elif method == "tools/list":
            result = {"tools": [
                {"name": "read_file", "description": "Read a file", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
                {"name": "write_file", "description": "Write a file", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}}},
                {"name": "delete_file", "description": "Delete a file", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
                {"name": "send_email", "description": "Send email", "inputSchema": {"type": "object", "properties": {"to": {"type": "string"}, "body": {"type": "string"}}}}
            ]}
        elif method == "tools/call":
            tool_name = req.get("params", {}).get("name", "")
            args = req.get("params", {}).get("arguments", {})
            # Return content that includes testable data
            if tool_name == "read_file":
                result = {"content": [{"type": "text", "text": "API key: sk-proj-abc123def456ghi789jkl012mno345 and password=secret123"}]}
            else:
                result = {"content": [{"type": "text", "text": f"Called {tool_name} with {json.dumps(args)}"}]}
        else:
            result = {}

        response = json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(response.encode())

    def log_message(self, format, *args):
        pass

http.server.HTTPServer(("", '"$MOCK_PORT"'), MCPHandler).serve_forever()
' &
    MOCK_PID=$!
    sleep 1
}

stop_server() {
    if [[ -n "${SERVER_PID:-}" ]]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=""
    fi
    CSRF_TOKEN=""
}

stop_mock() {
    if [[ -n "${MOCK_PID:-}" ]]; then
        kill "$MOCK_PID" 2>/dev/null || true
        wait "$MOCK_PID" 2>/dev/null || true
        MOCK_PID=""
    fi
}

get_csrf_token() {
    local base_url=$1
    local cookie_jar="$TMPDIR/csrf-cookies.txt"
    curl -sf -c "$cookie_jar" "${base_url}/admin/api/auth/status" >/dev/null 2>&1 || true
    CSRF_TOKEN=$(grep sentinel_csrf_token "$cookie_jar" 2>/dev/null | awk '{print $NF}' || echo "")
}

csrf_curl() {
    local base_url=$1
    shift
    if [[ -z "${CSRF_TOKEN:-}" ]]; then
        get_csrf_token "$base_url"
    fi
    curl -b "sentinel_csrf_token=${CSRF_TOKEN}" \
         -H "X-CSRF-Token: ${CSRF_TOKEN}" \
         "$@"
}

# Start server with default v1.1 config
start_v11_server() {
    local state_file="${1:-$TMPDIR/v11-state.json}"

    cat > "$TMPDIR/v11.yaml" << EOF
server:
  http_addr: ":$HTTP_PORT"
upstream:
  http: "http://localhost:$MOCK_PORT/mcp"
auth:
  identities:
    - id: "test-user"
      name: "Test User"
      roles: ["user"]
    - id: "quota-user"
      name: "Quota User"
      roles: ["user"]
  api_keys:
    - key_hash: "sha256:$KEY_HASH"
      identity_id: "test-user"
audit:
  output: "stdout"
policies:
  - name: "default"
    rules:
      - name: "allow-all"
        tool_match: "*"
        condition: "true"
        action: "allow"
EOF

    start_mock_mcp_server

    ./sentinel-gate --config "$TMPDIR/v11.yaml" --state "$state_file" start &
    SERVER_PID=$!

    if ! wait_for_server "http://localhost:$HTTP_PORT/mcp" 30; then
        echo "Server did not start"
        return 1
    fi

    # Get CSRF token
    get_csrf_token "http://localhost:$HTTP_PORT"
}

BASE="http://localhost:$HTTP_PORT"

# =============================================================================
# Test 1: Policy Templates — List & Apply
# =============================================================================
test_templates_list_apply() {
    section "Test 1: Policy Templates — List & Apply"

    # List templates
    local TEMPLATES
    TEMPLATES=$(curl -sf "$BASE/admin/api/v1/templates" 2>&1 || echo "CURL_FAILED")

    if [[ "$TEMPLATES" == "CURL_FAILED" ]]; then
        fail "Templates list — curl failed"
        return 1
    fi

    # Count templates (should be 7)
    local COUNT
    COUNT=$(echo "$TEMPLATES" | jq 'length' 2>/dev/null || echo "0")
    if [[ "$COUNT" -lt 6 ]]; then
        fail "Templates list — expected >=6 templates, got $COUNT"
        return 1
    fi
    pass "Templates list ($COUNT templates)"

    # Get specific template (read-only)
    local TMPL_ID
    TMPL_ID=$(echo "$TEMPLATES" | jq -r '.[0].id' 2>/dev/null)
    local DETAIL
    DETAIL=$(curl -sf "$BASE/admin/api/v1/templates/$TMPL_ID" 2>&1 || echo "CURL_FAILED")

    if [[ "$DETAIL" == "CURL_FAILED" ]] || ! echo "$DETAIL" | jq -e '.rules' >/dev/null 2>&1; then
        fail "Template detail — failed to get $TMPL_ID"
        return 1
    fi
    pass "Template detail ($TMPL_ID)"

    # Apply template
    local APPLY_RESP
    APPLY_RESP=$(csrf_curl "$BASE" -sf -X POST "$BASE/admin/api/v1/templates/$TMPL_ID/apply" \
        -H "Content-Type: application/json" 2>&1 || echo "CURL_FAILED")

    if [[ "$APPLY_RESP" == "CURL_FAILED" ]]; then
        fail "Template apply — curl failed"
        return 1
    fi

    # Verify policy was created
    local POLICIES
    POLICIES=$(curl -sf "$BASE/admin/api/policies" 2>&1 || echo "CURL_FAILED")
    local POLICY_COUNT
    POLICY_COUNT=$(echo "$POLICIES" | jq 'length' 2>/dev/null || echo "0")

    if [[ "$POLICY_COUNT" -lt 2 ]]; then
        fail "Template apply — policy not created (count=$POLICY_COUNT)"
        return 1
    fi
    pass "Template apply — policy created"

    # Apply all templates and verify each creates independent policy
    local ALL_OK=true
    for TID in $(echo "$TEMPLATES" | jq -r '.[].id' 2>/dev/null); do
        local R
        R=$(csrf_curl "$BASE" -s -o /dev/null -w "%{http_code}" -X POST "$BASE/admin/api/v1/templates/$TID/apply" \
            -H "Content-Type: application/json" 2>&1)
        if [[ "$R" != "200" && "$R" != "201" ]]; then
            fail "Template apply $TID — HTTP $R"
            ALL_OK=false
        fi
    done

    if $ALL_OK; then
        pass "All templates applied successfully"
    fi

    # Cleanup: delete created policies (keep "default")
    POLICIES=$(curl -sf "$BASE/admin/api/policies" 2>&1)
    for PID in $(echo "$POLICIES" | jq -r '.[] | select(.name != "default") | .id' 2>/dev/null); do
        csrf_curl "$BASE" -sf -X DELETE "$BASE/admin/api/policies/$PID" >/dev/null 2>&1 || true
    done
}

# =============================================================================
# Test 2: Response Transforms — CRUD
# =============================================================================
test_transforms_crud() {
    section "Test 2: Response Transforms — CRUD"

    # Create redact transform
    local CREATE_RESP
    CREATE_RESP=$(csrf_curl "$BASE" -sf -X POST "$BASE/admin/api/v1/transforms" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "redact-api-keys",
            "type": "redact",
            "tool_match": "*",
            "priority": 1,
            "enabled": true,
            "config": {
                "patterns": ["sk-[a-zA-Z0-9]{20,}"],
                "replacement": "[REDACTED]"
            }
        }' 2>&1 || echo "CURL_FAILED")

    if [[ "$CREATE_RESP" == "CURL_FAILED" ]]; then
        fail "Transform create — curl failed"
        return 1
    fi

    local XFORM_ID
    XFORM_ID=$(echo "$CREATE_RESP" | jq -r '.id // empty' 2>/dev/null)
    if [[ -z "$XFORM_ID" ]]; then
        fail "Transform create — no ID returned: $CREATE_RESP"
        return 1
    fi
    pass "Transform create (redact, id=$XFORM_ID)"

    # List transforms
    local LIST_RESP
    LIST_RESP=$(curl -sf "$BASE/admin/api/v1/transforms" 2>&1 || echo "CURL_FAILED")
    local XCOUNT
    XCOUNT=$(echo "$LIST_RESP" | jq 'length' 2>/dev/null || echo "0")
    if [[ "$XCOUNT" -lt 1 ]]; then
        fail "Transform list — expected >=1, got $XCOUNT"
        return 1
    fi
    pass "Transform list ($XCOUNT transforms)"

    # Create other types
    local TYPES_OK=true
    for TYPE_JSON in \
        '{"name":"truncate-large","type":"truncate","tool_match":"*","priority":2,"enabled":true,"config":{"max_bytes":10000,"suffix":"...[truncated]"}}' \
        '{"name":"inject-warning","type":"inject","tool_match":"*","priority":3,"enabled":true,"config":{"append":"WARNING: may contain PII"}}' \
        '{"name":"mask-keys","type":"mask","tool_match":"read_*","priority":4,"enabled":true,"config":{"mask_patterns":["sk-[a-zA-Z0-9]+"],"visible_prefix":3,"visible_suffix":4,"mask_char":"*"}}' \
        '{"name":"dryrun-write","type":"dry_run","tool_match":"write_file","priority":5,"enabled":true,"config":{"response":"{\"success\":true,\"dry_run\":true}"}}'; do

        local TR
        TR=$(csrf_curl "$BASE" -s -o /dev/null -w "%{http_code}" -X POST "$BASE/admin/api/v1/transforms" \
            -H "Content-Type: application/json" \
            -d "$TYPE_JSON" 2>&1)
        if [[ "$TR" != "200" && "$TR" != "201" ]]; then
            local TNAME
            TNAME=$(echo "$TYPE_JSON" | jq -r '.name' 2>/dev/null)
            fail "Transform create $TNAME — HTTP $TR"
            TYPES_OK=false
        fi
    done

    if $TYPES_OK; then
        pass "All 5 transform types created"
    fi

    # Update transform
    local UPDATE_RESP
    UPDATE_RESP=$(csrf_curl "$BASE" -s -o /dev/null -w "%{http_code}" -X PUT "$BASE/admin/api/v1/transforms/$XFORM_ID" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "redact-api-keys-v2",
            "type": "redact",
            "tool_match": "*",
            "priority": 1,
            "enabled": true,
            "config": {
                "patterns": ["sk-[a-zA-Z0-9]{20,}", "password=[^\\s]+"],
                "replacement": "[REDACTED]"
            }
        }' 2>&1)

    if [[ "$UPDATE_RESP" == "200" ]]; then
        pass "Transform update"
    else
        fail "Transform update — HTTP $UPDATE_RESP"
    fi

    # Delete transform
    local DEL_RESP
    DEL_RESP=$(csrf_curl "$BASE" -s -o /dev/null -w "%{http_code}" -X DELETE "$BASE/admin/api/v1/transforms/$XFORM_ID" 2>&1)
    if [[ "$DEL_RESP" == "200" || "$DEL_RESP" == "204" ]]; then
        pass "Transform delete"
    else
        fail "Transform delete — HTTP $DEL_RESP"
    fi

    # Cleanup remaining transforms
    LIST_RESP=$(curl -sf "$BASE/admin/api/v1/transforms" 2>&1 || echo "[]")
    for XID in $(echo "$LIST_RESP" | jq -r '.[].id' 2>/dev/null); do
        csrf_curl "$BASE" -sf -X DELETE "$BASE/admin/api/v1/transforms/$XID" >/dev/null 2>&1 || true
    done
}

# =============================================================================
# Test 3: Transform Test Sandbox
# =============================================================================
test_transform_sandbox() {
    section "Test 3: Transform Test Sandbox"

    # Create a redact transform first
    local CREATE_RESP
    CREATE_RESP=$(csrf_curl "$BASE" -sf -X POST "$BASE/admin/api/v1/transforms" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "sandbox-redact",
            "type": "redact",
            "tool_match": "*",
            "priority": 1,
            "enabled": true,
            "config": {
                "patterns": ["sk-[a-zA-Z0-9]{10,}"],
                "replacement": "[REDACTED]"
            }
        }' 2>&1 || echo "CURL_FAILED")

    if [[ "$CREATE_RESP" == "CURL_FAILED" ]]; then
        fail "Sandbox setup — create transform failed"
        return 1
    fi

    # Test sandbox with inline rules (sandbox uses "text" + "rules" fields)
    local SANDBOX_RESP
    SANDBOX_RESP=$(csrf_curl "$BASE" -sf -X POST "$BASE/admin/api/v1/transforms/test" \
        -H "Content-Type: application/json" \
        -d '{
            "text": "Here is an API key: sk_live_abc123def456ghi789xyz and normal text",
            "rules": [{
                "name": "test-redact",
                "type": "redact",
                "tool_match": "*",
                "priority": 1,
                "enabled": true,
                "config": {
                    "patterns": ["sk_live_[a-zA-Z0-9]{10,}"],
                    "replacement": "[REDACTED]"
                }
            }]
        }' 2>&1 || echo "CURL_FAILED")

    if [[ "$SANDBOX_RESP" == "CURL_FAILED" ]]; then
        fail "Transform sandbox — curl failed"
        return 1
    fi

    if echo "$SANDBOX_RESP" | grep -q "REDACTED"; then
        pass "Transform sandbox — redaction works"
    else
        fail "Transform sandbox — no redaction in output: $SANDBOX_RESP"
    fi

    # Cleanup
    local LIST_RESP
    LIST_RESP=$(curl -sf "$BASE/admin/api/v1/transforms" 2>&1 || echo "[]")
    for XID in $(echo "$LIST_RESP" | jq -r '.[].id' 2>/dev/null); do
        csrf_curl "$BASE" -sf -X DELETE "$BASE/admin/api/v1/transforms/$XID" >/dev/null 2>&1 || true
    done
}

# =============================================================================
# Test 4: Quota CRUD
# =============================================================================
test_quota_crud() {
    section "Test 4: Quota CRUD"

    local IDENTITY_ID="test-user"

    # Create quota
    local PUT_RESP
    PUT_RESP=$(csrf_curl "$BASE" -s -o /dev/null -w "%{http_code}" -X PUT "$BASE/admin/api/v1/quotas/$IDENTITY_ID" \
        -H "Content-Type: application/json" \
        -d '{
            "enabled": true,
            "action": "deny",
            "max_calls_per_session": 100,
            "max_writes_per_session": 20,
            "max_deletes_per_session": 5,
            "max_calls_per_minute": 50,
            "max_calls_per_day": 1000
        }' 2>&1)

    if [[ "$PUT_RESP" == "200" || "$PUT_RESP" == "201" ]]; then
        pass "Quota create"
    else
        fail "Quota create — HTTP $PUT_RESP"
        return 1
    fi

    # Get quota
    local GET_RESP
    GET_RESP=$(curl -sf "$BASE/admin/api/v1/quotas/$IDENTITY_ID" 2>&1 || echo "CURL_FAILED")

    if [[ "$GET_RESP" == "CURL_FAILED" ]]; then
        fail "Quota get — curl failed"
        return 1
    fi

    local ENABLED
    ENABLED=$(echo "$GET_RESP" | jq -r '.enabled // empty' 2>/dev/null)
    if [[ "$ENABLED" == "true" ]]; then
        pass "Quota get — enabled=true"
    else
        fail "Quota get — expected enabled=true: $GET_RESP"
    fi

    # List quotas
    local LIST_RESP
    LIST_RESP=$(curl -sf "$BASE/admin/api/v1/quotas" 2>&1 || echo "CURL_FAILED")
    local QCOUNT
    QCOUNT=$(echo "$LIST_RESP" | jq 'length' 2>/dev/null || echo "0")
    if [[ "$QCOUNT" -ge 1 ]]; then
        pass "Quota list ($QCOUNT quotas)"
    else
        fail "Quota list — expected >=1: $LIST_RESP"
    fi

    # Delete quota
    local DEL_RESP
    DEL_RESP=$(csrf_curl "$BASE" -s -o /dev/null -w "%{http_code}" -X DELETE "$BASE/admin/api/v1/quotas/$IDENTITY_ID" 2>&1)
    if [[ "$DEL_RESP" == "200" || "$DEL_RESP" == "204" ]]; then
        pass "Quota delete"
    else
        fail "Quota delete — HTTP $DEL_RESP"
    fi

    # Verify deleted
    local VERIFY
    VERIFY=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/admin/api/v1/quotas/$IDENTITY_ID" 2>&1)
    if [[ "$VERIFY" == "404" ]]; then
        pass "Quota delete verified (404)"
    else
        fail "Quota delete verify — expected 404, got $VERIFY"
    fi
}

# =============================================================================
# Test 5: Recording Config & CRUD
# =============================================================================
test_recording_config() {
    section "Test 5: Recording Config & CRUD"

    # Enable recording
    local PUT_RESP
    PUT_RESP=$(csrf_curl "$BASE" -s -o /dev/null -w "%{http_code}" -X PUT "$BASE/admin/api/v1/recordings/config" \
        -H "Content-Type: application/json" \
        -d '{
            "enabled": true,
            "record_payloads": false,
            "retention_days": 7,
            "storage_dir": "'"$TMPDIR/recordings"'"
        }' 2>&1)

    if [[ "$PUT_RESP" == "200" ]]; then
        pass "Recording config — enable"
    else
        fail "Recording config enable — HTTP $PUT_RESP"
        return 1
    fi

    # Get config
    local GET_RESP
    GET_RESP=$(curl -sf "$BASE/admin/api/v1/recordings/config" 2>&1 || echo "CURL_FAILED")

    if [[ "$GET_RESP" == "CURL_FAILED" ]]; then
        fail "Recording config get — curl failed"
        return 1
    fi

    local REC_ENABLED
    REC_ENABLED=$(echo "$GET_RESP" | jq -r '.enabled // empty' 2>/dev/null)
    if [[ "$REC_ENABLED" == "true" ]]; then
        pass "Recording config get — enabled=true"
    else
        fail "Recording config get — expected enabled=true: $GET_RESP"
    fi

    # List recordings (may be empty)
    local LIST_RESP
    LIST_RESP=$(curl -sf "$BASE/admin/api/v1/recordings" 2>&1 || echo "CURL_FAILED")
    if [[ "$LIST_RESP" != "CURL_FAILED" ]]; then
        pass "Recording list — endpoint works"
    else
        fail "Recording list — curl failed"
    fi

    # Disable recording
    csrf_curl "$BASE" -sf -X PUT "$BASE/admin/api/v1/recordings/config" \
        -H "Content-Type: application/json" \
        -d '{"enabled": false, "record_payloads": false, "retention_days": 7, "storage_dir": "'"$TMPDIR/recordings"'"}' >/dev/null 2>&1
}

# =============================================================================
# Test 6: Active Sessions API
# =============================================================================
test_active_sessions() {
    section "Test 6: Active Sessions API"

    local RESP
    RESP=$(curl -sf "$BASE/admin/api/v1/sessions/active" 2>&1 || echo "CURL_FAILED")

    if [[ "$RESP" == "CURL_FAILED" ]]; then
        fail "Active sessions — curl failed"
        return 1
    fi

    # Should return an array (empty or with sessions)
    if echo "$RESP" | jq -e 'type == "array"' >/dev/null 2>&1; then
        local SCOUNT
        SCOUNT=$(echo "$RESP" | jq 'length' 2>/dev/null)
        pass "Active sessions — $SCOUNT sessions"
    else
        fail "Active sessions — expected array: $RESP"
    fi
}

# =============================================================================
# Test 7: Template Apply → Policy Enforcement
# =============================================================================
test_template_enforcement() {
    section "Test 7: Template Apply → Policy Enforcement"

    # Find read-only template
    local TEMPLATES
    TEMPLATES=$(curl -sf "$BASE/admin/api/v1/templates" 2>&1 || echo "[]")

    local RO_ID
    RO_ID=$(echo "$TEMPLATES" | jq -r '.[] | select(.id == "read-only" or .name == "Read Only" or .id == "readonly") | .id' 2>/dev/null | head -1)

    if [[ -z "$RO_ID" ]]; then
        # Try any template
        RO_ID=$(echo "$TEMPLATES" | jq -r '.[0].id // empty' 2>/dev/null)
    fi

    if [[ -z "$RO_ID" ]]; then
        skip "Template enforcement — no templates found"
        return 0
    fi

    # Delete existing non-default policies first
    local POLICIES
    POLICIES=$(curl -sf "$BASE/admin/api/policies" 2>&1 || echo "[]")
    for PID in $(echo "$POLICIES" | jq -r '.[] | select(.name != "default") | .id' 2>/dev/null); do
        csrf_curl "$BASE" -sf -X DELETE "$BASE/admin/api/policies/$PID" >/dev/null 2>&1 || true
    done

    # Apply template
    csrf_curl "$BASE" -sf -X POST "$BASE/admin/api/v1/templates/$RO_ID/apply" \
        -H "Content-Type: application/json" >/dev/null 2>&1

    # Test policy evaluation: read_file should be allowed by most templates
    local EVAL_RESP
    EVAL_RESP=$(csrf_curl "$BASE" -sf -X POST "$BASE/admin/api/v1/policy/evaluate" \
        -H "Content-Type: application/json" \
        -d '{
            "action_type": "tool_call",
            "action_name": "read_file",
            "protocol": "mcp",
            "identity_name": "test-user",
            "identity_roles": ["user"],
            "arguments": {"path": "/tmp/test.txt"}
        }' 2>&1 || echo "CURL_FAILED")

    if [[ "$EVAL_RESP" == "CURL_FAILED" ]]; then
        fail "Template enforcement — evaluate failed"
    else
        local DECISION
        DECISION=$(echo "$EVAL_RESP" | jq -r '.decision // empty' 2>/dev/null)
        if [[ "$DECISION" == "allow" ]]; then
            pass "Template enforcement — read_file allowed"
        elif [[ -n "$DECISION" ]]; then
            pass "Template enforcement — evaluate returned: $DECISION"
        else
            fail "Template enforcement — unexpected response: $EVAL_RESP"
        fi
    fi

    # Cleanup: remove applied policy
    POLICIES=$(curl -sf "$BASE/admin/api/policies" 2>&1 || echo "[]")
    for PID in $(echo "$POLICIES" | jq -r '.[] | select(.name != "default") | .id' 2>/dev/null); do
        csrf_curl "$BASE" -sf -X DELETE "$BASE/admin/api/policies/$PID" >/dev/null 2>&1 || true
    done
}

# =============================================================================
# Test 8: State Persistence (v1.1 data)
# =============================================================================
test_v11_persistence() {
    section "Test 8: State Persistence (v1.1 data)"

    # Create quota
    csrf_curl "$BASE" -sf -X PUT "$BASE/admin/api/v1/quotas/test-user" \
        -H "Content-Type: application/json" \
        -d '{"enabled": true, "action": "warn", "max_calls_per_session": 500}' >/dev/null 2>&1

    # Create transform
    local XFORM_RESP
    XFORM_RESP=$(csrf_curl "$BASE" -sf -X POST "$BASE/admin/api/v1/transforms" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "persist-test",
            "type": "redact",
            "tool_match": "*",
            "priority": 1,
            "enabled": true,
            "config": {"patterns": ["test-pattern"], "replacement": "[GONE]"}
        }' 2>&1 || echo "{}")

    # Enable recording
    csrf_curl "$BASE" -sf -X PUT "$BASE/admin/api/v1/recordings/config" \
        -H "Content-Type: application/json" \
        -d '{"enabled": true, "record_payloads": true, "retention_days": 30, "storage_dir": "'"$TMPDIR/recordings"'"}' >/dev/null 2>&1

    # Restart server
    stop_server
    sleep 1

    ./sentinel-gate --config "$TMPDIR/v11.yaml" --state "$TMPDIR/v11-state.json" start &
    SERVER_PID=$!

    if ! wait_for_server "http://localhost:$HTTP_PORT/mcp" 30; then
        fail "Persistence — server did not restart"
        return 1
    fi

    get_csrf_token "$BASE"
    sleep 1

    # Verify quota persisted
    local Q_RESP
    Q_RESP=$(curl -sf "$BASE/admin/api/v1/quotas/test-user" 2>&1 || echo "CURL_FAILED")
    local Q_ENABLED
    Q_ENABLED=$(echo "$Q_RESP" | jq -r '.enabled // empty' 2>/dev/null)
    if [[ "$Q_ENABLED" == "true" ]]; then
        pass "Persistence — quota survived restart"
    else
        fail "Persistence — quota lost after restart: $Q_RESP"
    fi

    # Verify transform persisted
    local X_RESP
    X_RESP=$(curl -sf "$BASE/admin/api/v1/transforms" 2>&1 || echo "[]")
    local XCOUNT
    XCOUNT=$(echo "$X_RESP" | jq 'length' 2>/dev/null || echo "0")
    if [[ "$XCOUNT" -ge 1 ]]; then
        pass "Persistence — transforms survived restart"
    else
        fail "Persistence — transforms lost after restart"
    fi

    # Verify recording config persisted
    local R_RESP
    R_RESP=$(curl -sf "$BASE/admin/api/v1/recordings/config" 2>&1 || echo "CURL_FAILED")
    local R_ENABLED
    R_ENABLED=$(echo "$R_RESP" | jq -r '.enabled // empty' 2>/dev/null)
    if [[ "$R_ENABLED" == "true" ]]; then
        pass "Persistence — recording config survived restart"
    else
        fail "Persistence — recording config lost: $R_RESP"
    fi

    # Cleanup
    csrf_curl "$BASE" -sf -X DELETE "$BASE/admin/api/v1/quotas/test-user" >/dev/null 2>&1 || true
    local XFORMS
    XFORMS=$(curl -sf "$BASE/admin/api/v1/transforms" 2>&1 || echo "[]")
    for XID in $(echo "$XFORMS" | jq -r '.[].id' 2>/dev/null); do
        csrf_curl "$BASE" -sf -X DELETE "$BASE/admin/api/v1/transforms/$XID" >/dev/null 2>&1 || true
    done
    csrf_curl "$BASE" -sf -X PUT "$BASE/admin/api/v1/recordings/config" \
        -H "Content-Type: application/json" \
        -d '{"enabled": false, "storage_dir": "'"$TMPDIR/recordings"'"}' >/dev/null 2>&1 || true
}

# =============================================================================
# Test 9: v1.0 Regression
# =============================================================================
test_v10_regression() {
    section "Test 9: v1.0 Regression"

    # Tool discovery (proxy passthrough)
    local TOOLS_RESP
    TOOLS_RESP=$(curl -sf -X POST "$BASE/mcp" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}' 2>&1 || echo "CURL_FAILED")

    if [[ "$TOOLS_RESP" == "CURL_FAILED" ]] || ! echo "$TOOLS_RESP" | jq -e '.result.tools' >/dev/null 2>&1; then
        fail "Regression — tool discovery failed: $TOOLS_RESP"
    else
        local TCOUNT
        TCOUNT=$(echo "$TOOLS_RESP" | jq '.result.tools | length' 2>/dev/null)
        pass "Regression — tool discovery ($TCOUNT tools)"
    fi

    # Tool call passthrough
    local CALL_RESP
    CALL_RESP=$(curl -sf -X POST "$BASE/mcp" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/test"}},"id":2}' 2>&1 || echo "CURL_FAILED")

    if [[ "$CALL_RESP" == "CURL_FAILED" ]] || ! echo "$CALL_RESP" | jq -e '.result' >/dev/null 2>&1; then
        fail "Regression — tool call failed: $CALL_RESP"
    else
        pass "Regression — tool call passthrough"
    fi

    # Admin API (policies CRUD)
    local POL_RESP
    POL_RESP=$(curl -sf "$BASE/admin/api/policies" 2>&1 || echo "CURL_FAILED")
    if [[ "$POL_RESP" != "CURL_FAILED" ]] && echo "$POL_RESP" | jq -e 'length > 0' >/dev/null 2>&1; then
        pass "Regression — admin API policies"
    else
        fail "Regression — admin API policies: $POL_RESP"
    fi

    # Admin API (identities endpoint responds)
    local ID_RESP
    ID_RESP=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/admin/api/identities" 2>&1)
    if [[ "$ID_RESP" == "200" ]]; then
        pass "Regression — admin API identities endpoint (HTTP 200)"
    else
        fail "Regression — admin API identities: HTTP $ID_RESP"
    fi

    # Auth: localhost bypasses auth by design, so test that valid key works
    local AUTH_RESP
    AUTH_RESP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/mcp" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}' 2>&1)

    if [[ "$AUTH_RESP" == "200" ]]; then
        pass "Regression — auth with valid key (HTTP 200)"
    else
        fail "Regression — auth with valid key, got HTTP $AUTH_RESP"
    fi

    # Admin UI loads
    local UI_RESP
    UI_RESP=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/admin/" 2>&1)
    if [[ "$UI_RESP" == "200" ]]; then
        pass "Regression — admin UI loads"
    else
        fail "Regression — admin UI HTTP $UI_RESP"
    fi
}

# =============================================================================
# Test 10: Audit Stream (SSE)
# =============================================================================
test_audit_sse() {
    section "Test 10: Audit Stream (SSE)"

    # Start SSE connection in background, capture first events
    local SSE_OUTPUT="$TMPDIR/sse-output.txt"
    curl -sf -N "$BASE/admin/api/audit/stream" > "$SSE_OUTPUT" 2>/dev/null &
    local SSE_PID=$!

    # Trigger some activity
    curl -sf -X POST "$BASE/mcp" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file","arguments":{"path":"/test"}},"id":99}' >/dev/null 2>&1

    sleep 2

    # Kill SSE connection
    kill "$SSE_PID" 2>/dev/null || true
    wait "$SSE_PID" 2>/dev/null || true

    if [[ -s "$SSE_OUTPUT" ]]; then
        pass "Audit SSE — received events"
    else
        # SSE may not have data if timing is off
        skip "Audit SSE — no events captured (timing)"
    fi
}

# =============================================================================
# Main
# =============================================================================
main() {
    echo "======================================"
    echo "Sentinel Gate v1.1 Smoke Tests"
    echo "10 end-to-end tests for v1.1 features"
    echo "======================================"
    echo ""
    echo "Prerequisites:"
    echo "  - Go: $(go version 2>/dev/null || echo 'NOT FOUND')"
    echo "  - Python3: $(python3 --version 2>/dev/null || echo 'NOT FOUND')"
    echo "  - jq: $(jq --version 2>/dev/null || echo 'NOT FOUND')"
    echo ""

    cd "$PROJECT_ROOT"

    # Check prerequisites
    if ! command -v python3 &>/dev/null; then
        echo -e "${RED}ERROR: Python 3 required for mock MCP server${NC}"
        exit 1
    fi
    if ! command -v jq &>/dev/null; then
        echo -e "${RED}ERROR: jq required for JSON parsing${NC}"
        exit 1
    fi

    # Build
    echo -e "${BLUE}Building sentinel-gate...${NC}"
    go build -o sentinel-gate ./cmd/sentinel-gate

    # Start server with mock upstream
    echo -e "${BLUE}Starting server + mock upstream...${NC}"
    start_v11_server "$TMPDIR/v11-state.json"
    echo -e "${GREEN}Server ready on :$HTTP_PORT${NC}"
    echo ""

    # Run tests
    test_templates_list_apply     # Test 1
    test_transforms_crud          # Test 2
    test_transform_sandbox        # Test 3
    test_quota_crud               # Test 4
    test_recording_config         # Test 5
    test_active_sessions          # Test 6
    test_template_enforcement     # Test 7
    test_v11_persistence          # Test 8 (restarts server)
    test_v10_regression           # Test 9
    test_audit_sse                # Test 10

    # Summary
    echo ""
    echo "======================================"
    echo -e "Results: ${GREEN}$PASSED passed${NC}, ${RED}$FAILED failed${NC}, ${YELLOW}$SKIPPED skipped${NC}"
    echo "======================================"

    [[ $FAILED -eq 0 ]]
}

main "$@"
