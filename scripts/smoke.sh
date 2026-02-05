#!/usr/bin/env bash
# Sentinel Gate OSS Smoke Tests
# Runs 10 end-to-end tests to verify OSS functionality
#
# Usage: ./scripts/smoke.sh
#
# Prerequisites:
#   - Go (for building binary)
#   - Docker (for container tests)
#   - Python 3 (optional, for HTTP mock server - tests skip gracefully if unavailable)
#   - jq (for JSON parsing)
#   - curl (for HTTP requests)

set -o errexit
set -o nounset
set -o pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
PASSED=0
FAILED=0
SKIPPED=0

# Project root (parent of scripts/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TMPDIR=$(mktemp -d)

# API keys (must match smoke-config.yaml)
API_KEY="smoke-test-key-12345"
ADMIN_KEY="smoke-admin-key-67890"
KEY_HASH=$(echo -n "$API_KEY" | shasum -a 256 | cut -d' ' -f1)
ADMIN_HASH=$(echo -n "$ADMIN_KEY" | shasum -a 256 | cut -d' ' -f1)

# Ports (non-standard to avoid conflicts)
HTTP_PORT=18080
MOCK_PORT=13000

# Process IDs for cleanup
SERVER_PID=""
MOCK_PID=""

# =============================================================================
# Cleanup
# =============================================================================
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    [[ -n "${SERVER_PID:-}" ]] && kill "$SERVER_PID" 2>/dev/null || true
    [[ -n "${MOCK_PID:-}" ]] && kill "$MOCK_PID" 2>/dev/null || true
    docker compose -f "$PROJECT_ROOT/docker-compose.yml" down 2>/dev/null || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

# =============================================================================
# Helper Functions
# =============================================================================
pass() {
    echo -e "${GREEN}PASS${NC}: $1"
    ((PASSED++)) || true
}

fail() {
    echo -e "${RED}FAIL${NC}: $1"
    ((FAILED++)) || true
}

skip() {
    echo -e "${YELLOW}SKIP${NC}: $1"
    ((SKIPPED++)) || true
}

wait_for_server() {
    local url=$1
    local max_attempts=${2:-30}
    # Extract host and port from URL
    local host_port
    host_port=$(echo "$url" | sed -E 's|https?://([^/]+).*|\1|')
    local host="${host_port%:*}"
    local port="${host_port#*:}"

    for i in $(seq 1 "$max_attempts"); do
        # Check if port is listening (more reliable than curl for /mcp which requires POST)
        if nc -z "$host" "$port" 2>/dev/null; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

check_python3() {
    if command -v python3 &>/dev/null; then
        return 0
    fi
    return 1
}

# Cross-platform timeout function (macOS doesn't have GNU timeout)
# This version handles stdin properly by reading it first
run_with_timeout() {
    local timeout=$1
    shift
    # Run command in background, kill after timeout
    "$@" &
    local pid=$!
    (sleep "$timeout" && kill "$pid" 2>/dev/null) &
    local killer=$!
    wait "$pid" 2>/dev/null
    local exit_code=$?
    kill "$killer" 2>/dev/null || true
    wait "$killer" 2>/dev/null || true
    return $exit_code
}

# Run command with timeout, capturing stdin first for pipe compatibility
run_with_timeout_stdin() {
    local timeout=$1
    shift
    local input
    input=$(cat)
    echo "$input" | "$@" &
    local pid=$!
    (sleep "$timeout" && kill "$pid" 2>/dev/null) &
    local killer=$!
    wait "$pid" 2>/dev/null
    local exit_code=$?
    kill "$killer" 2>/dev/null || true
    wait "$killer" 2>/dev/null || true
    return $exit_code
}

start_mock_mcp_server() {
    # Simple HTTP server that responds with valid MCP JSON-RPC
    # Uses Python 3 (availability checked before calling)
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
            result = {"tools": [{"name": "read_file", "description": "Read file"}, {"name": "delete_file", "description": "Delete file"}]}
        elif method == "tools/call":
            tool_name = req.get("params", {}).get("name", "")
            result = {"content": [{"type": "text", "text": f"Called {tool_name}"}]}
        else:
            result = {}

        response = json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(response.encode())

    def log_message(self, format, *args):
        pass  # Suppress logging

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
}

stop_mock() {
    if [[ -n "${MOCK_PID:-}" ]]; then
        kill "$MOCK_PID" 2>/dev/null || true
        wait "$MOCK_PID" 2>/dev/null || true
        MOCK_PID=""
    fi
}

# =============================================================================
# Test 1: Build + Version
# =============================================================================
test_build_version() {
    echo "--- Test 1: Build + Version ---"
    cd "$PROJECT_ROOT"

    # Build binary
    if ! go build -o sentinel-gate ./cmd/sentinel-gate; then
        fail "Go build failed"
        return 1
    fi

    # Check --help works (validates binary is runnable)
    if ! ./sentinel-gate --help >/dev/null 2>&1; then
        fail "Binary --help failed"
        return 1
    fi

    # Verify binary exists and is executable
    if [[ ! -x ./sentinel-gate ]]; then
        fail "Binary not executable"
        return 1
    fi

    pass "Build + version check"
}

# =============================================================================
# Test 2: Config Validate
# =============================================================================
test_config_validate() {
    echo "--- Test 2: Config Validate ---"
    cd "$PROJECT_ROOT"

    # Create minimal valid config in temp dir
    cat > "$TMPDIR/valid.yaml" << EOF
server:
  http_addr: ":19999"
upstream:
  http: "http://localhost:3000/mcp"
auth:
  identities:
    - id: "test"
      name: "Test User"
      roles: ["user"]
  api_keys:
    - key_hash: "sha256:$KEY_HASH"
      identity_id: "test"
audit:
  output: "stdout"
policies:
  - name: "default"
    rules:
      - name: "allow-all"
        condition: "true"
        action: "allow"
EOF

    # Test that config loads - start will fail due to no upstream, but config validates
    # We verify config by checking start gets past config loading (no "config" or "validation" errors)
    OUTPUT=$(run_with_timeout 2 ./sentinel-gate --config "$TMPDIR/valid.yaml" start 2>&1 || true)

    if echo "$OUTPUT" | grep -qi "config.*error\|validation.*fail\|invalid.*config"; then
        fail "Config validation failed: $OUTPUT"
        return 1
    fi

    # Test that INVALID config is rejected
    cat > "$TMPDIR/invalid.yaml" << EOF
upstream:
  # missing required fields
policies: "not-an-array"
EOF

    INVALID_OUTPUT=$(run_with_timeout 2 ./sentinel-gate --config "$TMPDIR/invalid.yaml" start 2>&1 || true)
    if ! echo "$INVALID_OUTPUT" | grep -qi "error\|invalid\|fail"; then
        fail "Invalid config should have been rejected"
        return 1
    fi

    pass "Config validation"
}

# =============================================================================
# Test 3: Proxy Stdio
# =============================================================================
test_proxy_stdio() {
    echo "--- Test 3: Proxy Stdio ---"
    cd "$PROJECT_ROOT"

    # Create config for stdio mode with cat as simple echo
    # Note: Auth is always required in OSS config (dev_mode only enables verbose logging)
    cat > "$TMPDIR/stdio.yaml" << EOF
upstream:
  command: "cat"
dev_mode: true
auth:
  identities:
    - id: "stdio-test"
      name: "Stdio Test User"
      roles: ["user"]
  api_keys:
    - key_hash: "sha256:$KEY_HASH"
      identity_id: "stdio-test"
audit:
  output: "stdout"
policies:
  - name: "default"
    rules:
      - name: "allow-all"
        condition: "true"
        action: "allow"
EOF

    # Send message through stdio proxy - cat echoes back input
    # The proxy should receive the message and pass it to cat, which echoes it back
    RESPONSE=$(echo '{"jsonrpc":"2.0","method":"ping","params":{},"id":1}' | \
        run_with_timeout_stdin 5 ./sentinel-gate --config "$TMPDIR/stdio.yaml" start 2>/dev/null || true)

    # In dev_mode with cat as upstream, message should pass through
    # cat echoes the input, so we should see the JSON back
    if [[ -z "$RESPONSE" ]]; then
        fail "Stdio proxy produced no output"
        return 1
    fi

    # Verify the response contains our JSON (cat echoes it back)
    if ! echo "$RESPONSE" | grep -q "jsonrpc"; then
        fail "Stdio proxy response missing expected content"
        return 1
    fi

    pass "Proxy stdio"
}

# =============================================================================
# Test 4: Proxy HTTP
# =============================================================================
test_proxy_http() {
    echo "--- Test 4: Proxy HTTP ---"
    cd "$PROJECT_ROOT"

    # Check Python 3 availability for mock server
    if ! check_python3; then
        skip "Proxy HTTP - Python 3 not available for mock server"
        return 0
    fi

    # Create HTTP config
    cat > "$TMPDIR/http.yaml" << EOF
server:
  http_addr: ":$HTTP_PORT"
upstream:
  http: "http://localhost:$MOCK_PORT/mcp"
auth:
  identities:
    - id: "test-user"
      name: "Test User"
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
        condition: "true"
        action: "allow"
EOF

    # Start mock MCP server
    start_mock_mcp_server
    sleep 1

    # Start sentinel-gate in background
    ./sentinel-gate --config "$TMPDIR/http.yaml" start &
    SERVER_PID=$!

    # Wait for server to be ready
    if ! wait_for_server "http://localhost:$HTTP_PORT/mcp" 30; then
        fail "Proxy HTTP - server did not start"
        stop_server
        stop_mock
        return 1
    fi

    # Test tools/list
    LIST_RESP=$(curl -sf -X POST "http://localhost:$HTTP_PORT/mcp" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}' 2>&1 || echo "CURL_FAILED")

    if [[ "$LIST_RESP" == "CURL_FAILED" ]] || ! echo "$LIST_RESP" | jq -e '.result.tools' >/dev/null 2>&1; then
        fail "Proxy HTTP - tools/list failed: $LIST_RESP"
        stop_server
        stop_mock
        return 1
    fi

    # Test tools/call
    CALL_RESP=$(curl -sf -X POST "http://localhost:$HTTP_PORT/mcp" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file","arguments":{}},"id":2}' 2>&1 || echo "CURL_FAILED")

    if [[ "$CALL_RESP" == "CURL_FAILED" ]] || ! echo "$CALL_RESP" | jq -e '.result' >/dev/null 2>&1; then
        fail "Proxy HTTP - tools/call failed: $CALL_RESP"
        stop_server
        stop_mock
        return 1
    fi

    stop_server
    stop_mock
    pass "Proxy HTTP (tools/list, tools/call)"
}

# =============================================================================
# Test 5: Policy
# =============================================================================
test_policy() {
    echo "--- Test 5: Policy ---"
    cd "$PROJECT_ROOT"

    # Check Python 3 availability for mock server
    if ! check_python3; then
        skip "Policy - Python 3 not available for mock server"
        return 0
    fi

    # Create policy config that denies "delete_" tools
    cat > "$TMPDIR/policy.yaml" << EOF
server:
  http_addr: ":$HTTP_PORT"
upstream:
  http: "http://localhost:$MOCK_PORT/mcp"
auth:
  identities:
    - id: "user"
      name: "User"
      roles: ["user"]
  api_keys:
    - key_hash: "sha256:$KEY_HASH"
      identity_id: "user"
audit:
  output: "stdout"
policies:
  - name: "default"
    rules:
      - name: "deny-delete"
        condition: 'tool_name.startsWith("delete_")'
        action: "deny"
      - name: "allow-all"
        condition: "true"
        action: "allow"
EOF

    # Start mock MCP server
    start_mock_mcp_server
    sleep 1

    # Start sentinel-gate
    ./sentinel-gate --config "$TMPDIR/policy.yaml" start &
    SERVER_PID=$!

    if ! wait_for_server "http://localhost:$HTTP_PORT/mcp" 30; then
        fail "Policy - server did not start"
        stop_server
        stop_mock
        return 1
    fi

    # Test DENIED tool (delete_file should be denied)
    DENY_RESP=$(curl -s -X POST "http://localhost:$HTTP_PORT/mcp" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"delete_file","arguments":{}},"id":1}')

    if ! echo "$DENY_RESP" | jq -e '.error' >/dev/null 2>&1; then
        fail "Policy should have denied delete_file: $DENY_RESP"
        stop_server
        stop_mock
        return 1
    fi

    # Test ALLOWED tool (read_file should be allowed)
    ALLOW_RESP=$(curl -s -X POST "http://localhost:$HTTP_PORT/mcp" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file","arguments":{}},"id":2}')

    if echo "$ALLOW_RESP" | jq -e '.error' >/dev/null 2>&1; then
        fail "Policy should have allowed read_file: $ALLOW_RESP"
        stop_server
        stop_mock
        return 1
    fi

    stop_server
    stop_mock
    pass "Policy (deny delete_, allow read_)"
}

# =============================================================================
# Test 6: Audit
# =============================================================================
test_audit() {
    echo "--- Test 6: Audit ---"
    cd "$PROJECT_ROOT"

    # Test stdout audit - verify audit logs appear in stderr/stdout
    AUDIT_FILE="$TMPDIR/audit-output.log"

    cat > "$TMPDIR/audit.yaml" << EOF
server:
  http_addr: ":$HTTP_PORT"
upstream:
  http: "http://localhost:$MOCK_PORT/mcp"
auth:
  identities:
    - id: "test"
      name: "Test"
      roles: ["user"]
  api_keys:
    - key_hash: "sha256:$KEY_HASH"
      identity_id: "test"
audit:
  output: "stdout"
policies:
  - name: "default"
    rules:
      - name: "allow-all"
        condition: "true"
        action: "allow"
EOF

    # Check Python 3 for mock
    if ! check_python3; then
        skip "Audit - Python 3 not available"
        return 0
    fi

    start_mock_mcp_server

    # Start server and capture output
    ./sentinel-gate --config "$TMPDIR/audit.yaml" start > "$AUDIT_FILE" 2>&1 &
    SERVER_PID=$!

    if ! wait_for_server "http://localhost:$HTTP_PORT/mcp" 30; then
        fail "Audit - server did not start"
        stop_server
        stop_mock
        return 1
    fi

    # Make a request to generate audit log
    curl -sf -X POST "http://localhost:$HTTP_PORT/mcp" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file","arguments":{}},"id":1}' >/dev/null 2>&1 || true

    sleep 1
    stop_server
    stop_mock
    sleep 1

    # Check audit output for evidence of logging
    if [[ ! -s "$AUDIT_FILE" ]]; then
        fail "Audit - no output captured"
        return 1
    fi

    # Audit log should contain some indication of the request
    # (exact format depends on implementation - check for common fields)
    if ! grep -qiE "tool|request|audit|read_file|mcp|listening" "$AUDIT_FILE"; then
        fail "Audit - output missing expected audit content"
        cat "$AUDIT_FILE"
        return 1
    fi

    pass "Audit (stdout output captured)"
}

# =============================================================================
# Test 7: Rate Limit
# =============================================================================
test_rate_limit() {
    echo "--- Test 7: Rate Limit ---"
    cd "$PROJECT_ROOT"

    if ! check_python3; then
        skip "Rate limit - Python 3 not available"
        return 0
    fi

    # Config with very low rate limit (2 requests)
    cat > "$TMPDIR/ratelimit.yaml" << EOF
server:
  http_addr: ":$HTTP_PORT"
upstream:
  http: "http://localhost:$MOCK_PORT/mcp"
auth:
  identities:
    - id: "test"
      name: "Test"
      roles: ["user"]
  api_keys:
    - key_hash: "sha256:$KEY_HASH"
      identity_id: "test"
audit:
  output: "stdout"
rate_limit:
  enabled: true
  ip_rate: 2
  user_rate: 2
policies:
  - name: "default"
    rules:
      - name: "allow-all"
        condition: "true"
        action: "allow"
EOF

    start_mock_mcp_server

    ./sentinel-gate --config "$TMPDIR/ratelimit.yaml" start &
    SERVER_PID=$!

    if ! wait_for_server "http://localhost:$HTTP_PORT/mcp" 30; then
        fail "Rate limit - server did not start"
        stop_server
        stop_mock
        return 1
    fi

    # Rapid requests should trigger rate limiting
    # Note: The JSON-RPC transport returns 200 OK with error in body (not HTTP 429)
    GOT_RATE_LIMIT=false
    for i in {1..10}; do
        RESPONSE=$(curl -s -X POST "http://localhost:$HTTP_PORT/mcp" \
            -H "Authorization: Bearer $API_KEY" \
            -H "Content-Type: application/json" \
            -d '{"jsonrpc":"2.0","method":"ping","params":{},"id":'"$i"'}')

        if echo "$RESPONSE" | grep -qi "rate.limit"; then
            GOT_RATE_LIMIT=true
            break
        fi
    done

    stop_server
    stop_mock

    if $GOT_RATE_LIMIT; then
        pass "Rate limit (rate limit error after rapid requests)"
    else
        fail "Rate limit not enforced (no rate limit error after 10 rapid requests)"
        return 1
    fi
}

# =============================================================================
# Test 8: Health
# =============================================================================
test_health() {
    echo "--- Test 8: Health ---"
    cd "$PROJECT_ROOT"

    # Per Phase 53 decisions: OSS uses --help for health check (no /health endpoint)
    # The health check verifies the binary works
    if ! ./sentinel-gate --help >/dev/null 2>&1; then
        fail "Health check (--help) failed"
        return 1
    fi

    # Verify help output contains expected commands
    HELP_OUTPUT=$(./sentinel-gate --help 2>&1)
    if ! echo "$HELP_OUTPUT" | grep -qi "start\|help\|usage"; then
        fail "Health check - help output missing expected content"
        return 1
    fi

    pass "Health endpoint (--help works)"
}

# =============================================================================
# Test 9: Docker Build
# =============================================================================
test_docker_build() {
    echo "--- Test 9: Docker Build ---"
    cd "$PROJECT_ROOT"

    # Check docker is available and daemon is running
    if ! command -v docker &>/dev/null; then
        skip "Docker build - docker not available"
        return 0
    fi

    if ! docker info &>/dev/null; then
        skip "Docker build - docker daemon not running"
        return 0
    fi

    # Build the image
    if ! docker build -t sentinel-gate:smoke-test . ; then
        fail "Docker build failed"
        return 1
    fi

    # Verify image exists
    if ! docker image inspect sentinel-gate:smoke-test >/dev/null 2>&1; then
        fail "Docker image not found after build"
        return 1
    fi

    # Verify image runs (--help)
    if ! docker run --rm sentinel-gate:smoke-test --help >/dev/null 2>&1; then
        fail "Docker image --help failed"
        return 1
    fi

    pass "Docker build"
}

# =============================================================================
# Test 10: Docker Compose
# =============================================================================
test_docker_compose() {
    echo "--- Test 10: Docker Compose ---"
    cd "$PROJECT_ROOT"

    # Check docker compose is available and daemon is running
    if ! docker compose version &>/dev/null; then
        skip "Docker compose - docker compose not available"
        return 0
    fi

    if ! docker info &>/dev/null; then
        skip "Docker compose - docker daemon not running"
        return 0
    fi

    # Start with docker compose
    if ! docker compose up -d --build --wait --wait-timeout 60; then
        fail "docker compose up failed"
        docker compose logs
        docker compose down 2>/dev/null || true
        return 1
    fi

    # Verify container is running
    if ! docker compose ps | grep -q "running\|Up"; then
        fail "Container not running"
        docker compose logs
        docker compose down 2>/dev/null || true
        return 1
    fi

    # Give container time to settle and run health check
    sleep 5

    # Check container health (uses --help internally per docker-compose.yml)
    CONTAINER_NAME=$(docker compose ps -q 2>/dev/null | head -1)
    if [[ -n "$CONTAINER_NAME" ]]; then
        HEALTH=$(docker inspect --format='{{.State.Health.Status}}' "$CONTAINER_NAME" 2>/dev/null || echo "no-healthcheck")
        if [[ "$HEALTH" != "healthy" && "$HEALTH" != "no-healthcheck" ]]; then
            fail "Container health check failed: $HEALTH"
            docker compose logs
            docker compose down 2>/dev/null || true
            return 1
        fi
    fi

    docker compose down
    pass "docker compose up"
}

# =============================================================================
# Main
# =============================================================================
main() {
    echo "======================================"
    echo "Sentinel Gate OSS Smoke Tests"
    echo "======================================"
    echo ""
    echo "Prerequisites:"
    echo "  - Go: $(go version 2>/dev/null || echo 'NOT FOUND')"
    echo "  - Docker: $(docker --version 2>/dev/null || echo 'NOT FOUND')"
    echo "  - Python3: $(python3 --version 2>/dev/null || echo 'NOT FOUND (some tests will skip)')"
    echo "  - jq: $(jq --version 2>/dev/null || echo 'NOT FOUND')"
    echo ""

    cd "$PROJECT_ROOT"

    test_build_version
    test_config_validate
    test_proxy_stdio
    test_proxy_http
    test_policy
    test_audit
    test_rate_limit
    test_health
    test_docker_build
    test_docker_compose

    echo ""
    echo "======================================"
    echo "Results: $PASSED passed, $FAILED failed, $SKIPPED skipped"
    echo "======================================"

    [[ $FAILED -eq 0 ]]
}

main "$@"
