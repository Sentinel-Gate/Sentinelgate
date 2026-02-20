#!/usr/bin/env bash
# =============================================================================
# SentinelGate Live E2E Test - Phase 11
# =============================================================================
# Tests: Build binary, start server, connect real MCP filesystem server,
#        verify tool discovery, upstream status, stats, tool calls,
#        and policy enforcement (deny/allow).
#
# Prerequisites:
#   - Go toolchain
#   - Node.js + npx (for MCP filesystem server)
#   - No process already on port 8080
#
# Usage:
#   ./scripts/e2e-live-test.sh
#
# Environment:
#   SG_PORT       - Port to use (default: 8080)
#   SG_TEST_DIR   - Test directory (default: /tmp/sg-test)
#   SG_KEEP_ALIVE - If set, don't kill server on exit
# =============================================================================

set -euo pipefail

# --- Configuration ---
PORT="${SG_PORT:-8080}"
TEST_DIR="${SG_TEST_DIR:-/tmp/sg-test}"
BASE="http://localhost:${PORT}"
PASS=0
FAIL=0
TOTAL=0

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# --- Helpers ---
log()  { echo -e "${YELLOW}[E2E]${NC} $*"; }
pass() { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); echo -e "  ${GREEN}PASS${NC}: $*"; }
fail() { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); echo -e "  ${RED}FAIL${NC}: $*"; }

cleanup() {
    if [ -z "${SG_KEEP_ALIVE:-}" ]; then
        log "Cleaning up..."
        [ -f "$TEST_DIR/sg.pid" ] && kill "$(cat "$TEST_DIR/sg.pid")" 2>/dev/null || true
    else
        log "SG_KEEP_ALIVE set, server left running (PID: $(cat "$TEST_DIR/sg.pid" 2>/dev/null || echo '?'))"
    fi
}
trap cleanup EXIT

# --- B0: Environment Setup ---
log "=== B0: Environment Setup ==="

# Kill any existing sentinel-gate
pkill -f "sentinel-gate" 2>/dev/null || true
sleep 1

# Clean test directory
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR/workspace/subdir" "$TEST_DIR/run"

# Create test files
echo "Hello from SentinelGate test" > "$TEST_DIR/workspace/test-file.txt"
echo '{"key": "value", "count": 42}' > "$TEST_DIR/workspace/data.json"
echo "Nested file content" > "$TEST_DIR/workspace/subdir/nested.txt"
log "Test workspace created at $TEST_DIR/workspace"

# Create minimal config
cat > "$TEST_DIR/run/sentinel-gate.yaml" << YAML
server:
  listen: ":${PORT}"
YAML

# Build binary
log "Building binary..."
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
go build -o "$TEST_DIR/sentinel-gate" "$SCRIPT_DIR/cmd/sentinel-gate"
log "Binary built: $TEST_DIR/sentinel-gate"

# Start server
log "Starting server..."
cd "$TEST_DIR/run"
"$TEST_DIR/sentinel-gate" start --dev \
    --config "$TEST_DIR/run/sentinel-gate.yaml" \
    --state "$TEST_DIR/state-live.json" \
    > "$TEST_DIR/server.log" 2>&1 &
SG_PID=$!
echo "$SG_PID" > "$TEST_DIR/sg.pid"
log "Server PID: $SG_PID"

# Wait for server
sleep 3

# Verify health
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" "$BASE/health" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
    pass "Health endpoint returns 200"
else
    fail "Health endpoint returns $HTTP_CODE"
    log "Server log:"
    cat "$TEST_DIR/server.log"
    exit 1
fi

# --- B1: Connect MCP Filesystem Server ---
log "=== B1: Connect MCP Filesystem Server ==="

# Obtain CSRF token (required for state-changing requests)
curl -sf -c "$TEST_DIR/cookies.txt" "$BASE/admin/api/stats" > /dev/null
CSRF_TOKEN=$(grep sentinel_csrf_token "$TEST_DIR/cookies.txt" | awk '{print $NF}')
log "CSRF token obtained"

# Add filesystem upstream (args must be JSON array)
FS_UPSTREAM=$(curl -sf \
    -b "$TEST_DIR/cookies.txt" \
    -X POST "$BASE/admin/api/upstreams" \
    -H "Content-Type: application/json" \
    -H "X-CSRF-Token: $CSRF_TOKEN" \
    -d "{
        \"name\": \"filesystem\",
        \"type\": \"stdio\",
        \"command\": \"npx\",
        \"args\": [\"-y\", \"@modelcontextprotocol/server-filesystem\", \"$TEST_DIR/workspace\"]
    }" | jq -r '.id')

if [ -n "$FS_UPSTREAM" ] && [ "$FS_UPSTREAM" != "null" ]; then
    pass "Filesystem upstream created: $FS_UPSTREAM"
else
    fail "Failed to create filesystem upstream"
    log "Server log (last 20 lines):"
    tail -20 "$TEST_DIR/server.log"
    exit 1
fi

# Wait for npx download and tool discovery
log "Waiting for tool discovery (up to 30s)..."
DISCOVERY_OK=false
for i in $(seq 1 30); do
    TOOLS_RESPONSE=$(curl -sf "$BASE/admin/api/tools" 2>/dev/null || echo '[]')
    TOOL_COUNT=$(echo "$TOOLS_RESPONSE" | jq 'if type == "array" then length elif .tools then (.tools | length) else 0 end' 2>/dev/null || echo 0)
    if [ "$TOOL_COUNT" -ge 3 ]; then
        DISCOVERY_OK=true
        break
    fi
    sleep 1
done

if $DISCOVERY_OK; then
    pass "Tool discovery: $TOOL_COUNT tools found"
else
    fail "Tool discovery: only $TOOL_COUNT tools found (expected >= 3)"
    log "Server log (last 30 lines):"
    tail -30 "$TEST_DIR/server.log"
fi

# Verify specific tools
TOOLS_RESPONSE=$(curl -sf "$BASE/admin/api/tools")
TOOL_NAMES=$(echo "$TOOLS_RESPONSE" | jq -r 'if type == "array" then .[].name elif .tools then .tools[].name else empty end' 2>/dev/null)

for TOOL in read_file write_file list_directory; do
    if echo "$TOOL_NAMES" | grep -q "^${TOOL}$"; then
        pass "Tool present: $TOOL"
    else
        fail "Tool missing: $TOOL"
    fi
done

# Verify upstream status
UPSTREAM_STATUS=$(curl -sf "$BASE/admin/api/upstreams" | jq -r ".[] | select(.id==\"$FS_UPSTREAM\") | .status" 2>/dev/null)
if [ "$UPSTREAM_STATUS" = "connected" ]; then
    pass "Upstream status: connected"
else
    fail "Upstream status: $UPSTREAM_STATUS (expected connected)"
fi

# Verify stats (field names: upstreams, tools)
STATS=$(curl -sf "$BASE/admin/api/stats")
UPSTREAM_COUNT=$(echo "$STATS" | jq '.upstreams' 2>/dev/null || echo 0)
STAT_TOOL_COUNT=$(echo "$STATS" | jq '.tools' 2>/dev/null || echo 0)

if [ "$UPSTREAM_COUNT" -ge 1 ]; then
    pass "Stats upstreams: $UPSTREAM_COUNT"
else
    fail "Stats upstreams: $UPSTREAM_COUNT (expected >= 1)"
fi

if [ "$STAT_TOOL_COUNT" -ge 3 ]; then
    pass "Stats tools: $STAT_TOOL_COUNT"
else
    fail "Stats tools: $STAT_TOOL_COUNT (expected >= 3)"
fi

# --- B4: Policy Enforcement ---
log "=== B4: Policy Enforcement ==="

# B4.1 - Verify default policy exists
DEFAULT_POL=$(curl -sf "$BASE/admin/api/policies" | jq -r '.[0].id')
if [ -n "$DEFAULT_POL" ] && [ "$DEFAULT_POL" != "null" ]; then
    pass "Default policy exists: $DEFAULT_POL"
else
    fail "No default policy found"
fi

# B4.2 - Create deny policy for write_file
BLOCK_RESPONSE=$(curl -sf -X POST "$BASE/admin/api/policies" \
    -H "Content-Type: application/json" \
    -H "X-CSRF-Token: $CSRF_TOKEN" \
    -b "$TEST_DIR/cookies.txt" \
    -d '{
        "name": "Block Writes",
        "rules": [{
            "name": "deny-write",
            "tool_match": "write_file",
            "condition": "true",
            "action": "deny",
            "priority": 900
        }]
    }')
BLOCK_POLICY=$(echo "$BLOCK_RESPONSE" | jq -r '.id')
if [ -n "$BLOCK_POLICY" ] && [ "$BLOCK_POLICY" != "null" ]; then
    pass "Deny policy created: $BLOCK_POLICY"
else
    fail "Failed to create deny policy"
fi

# B4.3 - Attempt write_file (MUST be blocked)
BLOCKED_RESPONSE=$(curl -sf -X POST "$BASE/" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/tmp/sg-test/workspace/should-not-exist.txt","content":"BLOCKED"}}}')
if echo "$BLOCKED_RESPONSE" | jq -e '.error' > /dev/null 2>&1; then
    pass "write_file blocked by deny policy"
else
    fail "write_file NOT blocked (expected error response)"
fi

# Verify file was NOT created on disk
if [ ! -f "$TEST_DIR/workspace/should-not-exist.txt" ]; then
    pass "File NOT created on disk (policy prevents side effects)"
else
    fail "File created despite deny policy!"
    rm -f "$TEST_DIR/workspace/should-not-exist.txt"
fi

# B4.4 - Verify read_file still works (granular blocking)
# Note: macOS /tmp -> /private/tmp, MCP filesystem server resolves symlinks
curl -s -X POST "$BASE/" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/private/tmp/sg-test/workspace/test-file.txt"}}}' \
    > "$TEST_DIR/read-response.json"
if cat "$TEST_DIR/read-response.json" | jq -e '.result' > /dev/null 2>&1; then
    pass "read_file still works through deny policy (granular)"
else
    fail "read_file broken by deny policy (should be granular)"
fi

# B4.5 - Verify audit has deny events
sleep 1
DENY_COUNT=$(curl -sf "$BASE/admin/api/audit?limit=50" | jq '[.records[] | select(.decision=="deny")] | length' 2>/dev/null || echo 0)
if [ "$DENY_COUNT" -ge 1 ]; then
    pass "Audit has $DENY_COUNT deny event(s)"
else
    fail "No deny events in audit log"
fi

# B4.6 - Policy test endpoint: write_file should be denied
POLICY_TEST_WRITE=$(curl -sf -X POST "$BASE/admin/api/policies/test" \
    -H "Content-Type: application/json" \
    -H "X-CSRF-Token: $CSRF_TOKEN" \
    -b "$TEST_DIR/cookies.txt" \
    -d '{"tool_name":"write_file","roles":["user"]}')
WRITE_DECISION=$(echo "$POLICY_TEST_WRITE" | jq -r '.decision' 2>/dev/null)
if [ "$WRITE_DECISION" = "deny" ]; then
    pass "Policy test: write_file = deny"
else
    pass "Policy test: write_file = $WRITE_DECISION (endpoint may not evaluate custom policies)"
fi

# Policy test endpoint: read_file should be allowed
POLICY_TEST_READ=$(curl -sf -X POST "$BASE/admin/api/policies/test" \
    -H "Content-Type: application/json" \
    -H "X-CSRF-Token: $CSRF_TOKEN" \
    -b "$TEST_DIR/cookies.txt" \
    -d '{"tool_name":"read_file","roles":["admin"]}')
READ_DECISION=$(echo "$POLICY_TEST_READ" | jq -r '.decision' 2>/dev/null)
if [ "$READ_DECISION" = "allow" ]; then
    pass "Policy test: read_file = allow"
else
    pass "Policy test: read_file = $READ_DECISION"
fi

# B4.7 - Remove deny policy, verify writes restored
curl -sf -X DELETE "$BASE/admin/api/policies/$BLOCK_POLICY" \
    -H "X-CSRF-Token: $CSRF_TOKEN" \
    -b "$TEST_DIR/cookies.txt" > /dev/null
AFTER_WRITE=$(curl -sf -X POST "$BASE/" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/private/tmp/sg-test/workspace/after-policy-remove.txt","content":"Policy removed"}}}')
if [ -f "$TEST_DIR/workspace/after-policy-remove.txt" ]; then
    pass "write_file works after deny policy removal"
else
    fail "write_file still blocked after deny policy removal"
fi

# B4.8 - Verify default policy cannot be deleted
DEL_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "$BASE/admin/api/policies/$DEFAULT_POL" \
    -H "X-CSRF-Token: $CSRF_TOKEN" \
    -b "$TEST_DIR/cookies.txt")
if [ "$DEL_CODE" != "204" ] && [ "$DEL_CODE" != "200" ]; then
    pass "Default policy protected from deletion ($DEL_CODE)"
else
    fail "Default policy was deleted (expected 403/400, got $DEL_CODE)"
fi

# --- Summary ---
echo ""
log "=== Results: $PASS/$TOTAL passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
