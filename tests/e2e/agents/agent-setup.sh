#!/usr/bin/env bash
# =============================================================================
# agent-setup.sh — SentinelGate E2E Agent Testing Setup
#
# Prepares the environment for manual testing of real AI agents
# (Claude Code, Gemini CLI, Codex CLI) against a running SentinelGate instance.
#
# Usage:
#   ./agent-setup.sh          # interactive mode (prompts for y/n)
#   ./agent-setup.sh --auto   # auto-configure everything, no prompts
#   ./agent-setup.sh --help   # show help
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
AUTO_MODE=false
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROJECT_DIR="$(cd "$E2E_DIR/../.." && pwd)"

SG_URL="http://localhost:8080"
SG_MCP_URL="${SG_URL}/mcp"
SG_HEALTH_URL="${SG_URL}/health"

TEST_DIR="/tmp/sg-e2e-test"
ENV_FILE="${E2E_DIR}/.env.test"

API_KEY=""

# Summary tracking
SUMMARY_ITEMS=()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; }
header()  { echo -e "\n${BOLD}═══ $* ═══${NC}\n"; }

summary_add() { SUMMARY_ITEMS+=("$1"); }

confirm() {
    local prompt="$1"
    if $AUTO_MODE; then
        info "$prompt [auto: y]"
        return 0
    fi
    echo -en "${YELLOW}$prompt [y/N]${NC} "
    read -r answer
    [[ "$answer" =~ ^[Yy]$ ]]
}

# ---------------------------------------------------------------------------
# --help
# ---------------------------------------------------------------------------
show_help() {
    cat <<'HELP'
agent-setup.sh — SentinelGate E2E Agent Testing Setup

Prepares the local environment for manual testing of real AI agents
(Claude Code, Gemini CLI, Codex CLI) against a running SentinelGate instance.

Usage:
  ./agent-setup.sh          Interactive mode (prompts before each change)
  ./agent-setup.sh --auto   Auto-configure everything without prompts
  ./agent-setup.sh --help   Show this help message

What the script does:
  1. Creates test files in /tmp/sg-e2e-test/
  2. Checks that SentinelGate is running on localhost:8080
  3. Backs up existing agent config files (Gemini, Codex)
  4. Reads the API key from tests/e2e/.env.test
  5. Displays config snippets for Claude Code, Gemini CLI, Codex CLI
  6. Optionally auto-configures Gemini and Codex (with confirmation)

Notes:
  - Idempotent: safe to run multiple times
  - Backups are only created once (*.sg-backup files are never overwritten)
  - Claude Code uses `claude mcp add` (no file editing needed)
HELP
    exit 0
}

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
for arg in "$@"; do
    case "$arg" in
        --auto) AUTO_MODE=true ;;
        --help|-h) show_help ;;
        *)
            error "Unknown argument: $arg"
            echo "Run with --help for usage information."
            exit 1
            ;;
    esac
done

# ============================================================================
# STEP 1 — Create test directory and files
# ============================================================================
header "Step 1: Creating test files"

mkdir -p "${TEST_DIR}/subdir"

echo "This is a test file for SentinelGate E2E testing." > "${TEST_DIR}/test.txt"
echo '{"key": "value", "number": 42}' > "${TEST_DIR}/data.json"
echo "Nested file content" > "${TEST_DIR}/subdir/nested.txt"

success "Test files created in ${TEST_DIR}/"
info "  ${TEST_DIR}/test.txt"
info "  ${TEST_DIR}/data.json"
info "  ${TEST_DIR}/subdir/nested.txt"
summary_add "Created test files in ${TEST_DIR}/"

# ============================================================================
# STEP 2 — Check SentinelGate is running
# ============================================================================
header "Step 2: Checking SentinelGate"

if curl -sf --connect-timeout 3 "${SG_HEALTH_URL}" >/dev/null 2>&1; then
    success "SentinelGate is running at ${SG_URL}"
    summary_add "SentinelGate: running"
else
    warn "SentinelGate is NOT reachable at ${SG_HEALTH_URL}"
    echo ""
    info "Start it with:"
    echo -e "  ${BOLD}cd ${PROJECT_DIR}${NC}"
    echo -e "  ${BOLD}go build -o sentinel-gate ./cmd/sentinel-gate && ./sentinel-gate${NC}"
    echo ""
    warn "Continuing anyway — you can start it before running agents."
    summary_add "SentinelGate: NOT running (start it manually)"
fi

# ============================================================================
# STEP 3 — Backup existing agent configs
# ============================================================================
header "Step 3: Backing up agent configs"

BACKED_UP=0

# --- Gemini CLI ---
GEMINI_CONFIG="${HOME}/.gemini/settings.json"
GEMINI_BACKUP="${GEMINI_CONFIG}.sg-backup"

if [[ -f "$GEMINI_CONFIG" ]]; then
    if [[ -f "$GEMINI_BACKUP" ]]; then
        info "Gemini backup already exists: ${GEMINI_BACKUP} (skipping)"
    else
        cp "$GEMINI_CONFIG" "$GEMINI_BACKUP"
        success "Backed up Gemini config → ${GEMINI_BACKUP}"
        BACKED_UP=$((BACKED_UP + 1))
        summary_add "Backed up ${GEMINI_CONFIG}"
    fi
else
    info "No Gemini config found at ${GEMINI_CONFIG} (nothing to back up)"
fi

# --- Codex CLI ---
CODEX_CONFIG="${HOME}/.codex/config.toml"
CODEX_BACKUP="${CODEX_CONFIG}.sg-backup"

if [[ -f "$CODEX_CONFIG" ]]; then
    if [[ -f "$CODEX_BACKUP" ]]; then
        info "Codex backup already exists: ${CODEX_BACKUP} (skipping)"
    else
        cp "$CODEX_CONFIG" "$CODEX_BACKUP"
        success "Backed up Codex config → ${CODEX_BACKUP}"
        BACKED_UP=$((BACKED_UP + 1))
        summary_add "Backed up ${CODEX_CONFIG}"
    fi
else
    info "No Codex config found at ${CODEX_CONFIG} (nothing to back up)"
fi

# --- Claude Code ---
info "Claude Code uses 'claude mcp add/remove' — no file backup needed."

if [[ $BACKED_UP -eq 0 ]]; then
    info "No configs needed backing up."
fi

# ============================================================================
# STEP 4 — Read / display API key
# ============================================================================
header "Step 4: API Key"

if [[ -f "$ENV_FILE" ]]; then
    # Try to extract API_KEY from .env.test (supports KEY=value and KEY="value")
    API_KEY=$(grep -E '^API_KEY=' "$ENV_FILE" | head -1 | sed 's/^API_KEY=//' | tr -d '"' | tr -d "'" || true)
fi

if [[ -n "$API_KEY" ]]; then
    # Mask the key for display (show first 6 chars + mask)
    MASKED="${API_KEY:0:6}••••••••"
    success "API key loaded from ${ENV_FILE}: ${MASKED}"
    summary_add "API key: loaded from .env.test"
else
    warn "No API key found in ${ENV_FILE}"
    echo ""
    info "To create one:"
    info "  1. Open ${BOLD}${SG_URL}${NC} in your browser"
    info "  2. Go to ${BOLD}Identities${NC} → create one (e.g. 'e2e-agent')"
    info "  3. Go to ${BOLD}API Keys${NC} → create a key for that identity"
    info "  4. Save it to ${ENV_FILE}:"
    echo -e "     ${BOLD}echo 'API_KEY=sg_your_key_here' > ${ENV_FILE}${NC}"
    echo ""

    if ! $AUTO_MODE; then
        echo -en "${YELLOW}Paste the API key now (or press Enter to skip): ${NC}"
        read -r API_KEY
    fi

    if [[ -z "$API_KEY" ]]; then
        API_KEY="<YOUR_API_KEY>"
        warn "Using placeholder key — replace <YOUR_API_KEY> in the snippets below."
        summary_add "API key: NOT set (using placeholder)"
    else
        success "API key set for this session."
        summary_add "API key: entered manually"
    fi
fi

# ============================================================================
# STEP 5 — Display config snippets
# ============================================================================
header "Step 5: Agent configuration snippets"

# --- Claude Code ---
echo -e "${BOLD}┌─────────────────────────────────────┐${NC}"
echo -e "${BOLD}│         Claude Code (CLI)            │${NC}"
echo -e "${BOLD}└─────────────────────────────────────┘${NC}"
echo ""
echo -e "${CYAN}Run this command to add the MCP server:${NC}"
echo ""
echo -e "  claude mcp add sentinelgate \\"
echo -e "    --transport http \\"
echo -e "    ${SG_MCP_URL} \\"
echo -e "    -H \"Authorization: Bearer ${API_KEY}\""
echo ""
echo -e "${CYAN}To remove it later:${NC}"
echo -e "  claude mcp remove sentinelgate"
echo ""

# --- Gemini CLI ---
echo -e "${BOLD}┌─────────────────────────────────────┐${NC}"
echo -e "${BOLD}│         Gemini CLI                   │${NC}"
echo -e "${BOLD}└─────────────────────────────────────┘${NC}"
echo ""
echo -e "${CYAN}Add this to ~/.gemini/settings.json:${NC}"
echo ""
GEMINI_SNIPPET=$(cat <<GEOF
{
  "mcpServers": {
    "sentinelgate": {
      "url": "${SG_MCP_URL}",
      "headers": {
        "Authorization": "Bearer ${API_KEY}"
      }
    }
  }
}
GEOF
)
echo "$GEMINI_SNIPPET"
echo ""

# --- Codex CLI ---
echo -e "${BOLD}┌─────────────────────────────────────┐${NC}"
echo -e "${BOLD}│         Codex CLI                    │${NC}"
echo -e "${BOLD}└─────────────────────────────────────┘${NC}"
echo ""
echo -e "${CYAN}Add this to ~/.codex/config.toml:${NC}"
echo ""
CODEX_SNIPPET=$(cat <<CEOF
[mcp_servers.sentinelgate]
url = "${SG_MCP_URL}"

[mcp_servers.sentinelgate.headers]
Authorization = "Bearer ${API_KEY}"
CEOF
)
echo "$CODEX_SNIPPET"
echo ""

# ============================================================================
# STEP 6 — Auto-configure Gemini and Codex
# ============================================================================
header "Step 6: Auto-configuration"

# Skip auto-config if we only have the placeholder key
if [[ "$API_KEY" == "<YOUR_API_KEY>" ]]; then
    warn "Skipping auto-configuration — no real API key available."
    warn "Set the API key first, then re-run the script."
    summary_add "Auto-config: skipped (no API key)"
else

    # --- Gemini CLI auto-config ---
    GEMINI_CONFIGURED=false
    if confirm "Auto-configure Gemini CLI (${GEMINI_CONFIG})?"; then
        mkdir -p "$(dirname "$GEMINI_CONFIG")"

        if [[ -f "$GEMINI_CONFIG" ]]; then
            # Check if jq is available
            if command -v jq >/dev/null 2>&1; then
                # Merge sentinelgate into existing mcpServers (or create the key)
                EXISTING=$(cat "$GEMINI_CONFIG")

                SG_SERVER_JSON=$(cat <<SJEOF
{
  "url": "${SG_MCP_URL}",
  "headers": {
    "Authorization": "Bearer ${API_KEY}"
  }
}
SJEOF
)
                MERGED=$(echo "$EXISTING" | jq --argjson sg "$SG_SERVER_JSON" '
                    .mcpServers = ((.mcpServers // {}) + {"sentinelgate": $sg})
                ')

                echo "$MERGED" > "$GEMINI_CONFIG"
                success "Gemini config updated (merged sentinelgate server)."
                GEMINI_CONFIGURED=true
            else
                warn "jq is not installed — cannot safely merge JSON."
                info "Install jq (brew install jq) or manually add the snippet above."
            fi
        else
            # Create new settings.json
            echo "$GEMINI_SNIPPET" > "$GEMINI_CONFIG"
            success "Gemini config created at ${GEMINI_CONFIG}."
            GEMINI_CONFIGURED=true
        fi

        if $GEMINI_CONFIGURED; then
            summary_add "Gemini CLI: configured"
        else
            summary_add "Gemini CLI: manual config needed (no jq)"
        fi
    else
        info "Skipping Gemini auto-configuration."
        summary_add "Gemini CLI: skipped"
    fi

    # --- Codex CLI auto-config ---
    CODEX_CONFIGURED=false
    if confirm "Auto-configure Codex CLI (${CODEX_CONFIG})?"; then
        mkdir -p "$(dirname "$CODEX_CONFIG")"

        if [[ -f "$CODEX_CONFIG" ]]; then
            # Check if sentinelgate is already configured
            if grep -q '\[mcp_servers\.sentinelgate\]' "$CODEX_CONFIG" 2>/dev/null; then
                # Remove existing sentinelgate block before re-adding
                # We remove from [mcp_servers.sentinelgate] up to the next section or EOF
                TEMP_CODEX=$(mktemp)
                awk '
                    /^\[mcp_servers\.sentinelgate\]/ { skip=1; next }
                    /^\[/ && skip { skip=0 }
                    !skip { print }
                ' "$CODEX_CONFIG" > "$TEMP_CODEX"
                cp "$TEMP_CODEX" "$CODEX_CONFIG"
                rm -f "$TEMP_CODEX"
                info "Removed existing sentinelgate block from Codex config."
            fi

            # Append the TOML block
            # Ensure a blank line before the new block
            if [[ -s "$CODEX_CONFIG" ]]; then
                LAST_CHAR=$(tail -c 1 "$CODEX_CONFIG")
                if [[ -n "$LAST_CHAR" ]]; then
                    echo "" >> "$CODEX_CONFIG"
                fi
            fi
            echo "$CODEX_SNIPPET" >> "$CODEX_CONFIG"
            success "Codex config updated (appended sentinelgate server)."
            CODEX_CONFIGURED=true
        else
            # Create new config.toml
            echo "$CODEX_SNIPPET" > "$CODEX_CONFIG"
            success "Codex config created at ${CODEX_CONFIG}."
            CODEX_CONFIGURED=true
        fi

        if $CODEX_CONFIGURED; then
            summary_add "Codex CLI: configured"
        else
            summary_add "Codex CLI: manual config needed"
        fi
    else
        info "Skipping Codex auto-configuration."
        summary_add "Codex CLI: skipped"
    fi

    # --- Claude Code reminder ---
    echo ""
    info "For ${BOLD}Claude Code${NC}, run the command shown in Step 5 manually."
    summary_add "Claude Code: run 'claude mcp add' manually"
fi

# ============================================================================
# SUMMARY
# ============================================================================
header "Summary"

for item in "${SUMMARY_ITEMS[@]}"; do
    echo -e "  ${GREEN}✓${NC} $item"
done

echo ""
echo -e "${BOLD}Next steps:${NC}"
echo -e "  1. Make sure SentinelGate is running (${SG_URL})"
echo -e "  2. Configure Claude Code with the command above"
echo -e "  3. Open each agent and test MCP tools (list_tools, read_file, etc.)"
echo ""
echo -e "${CYAN}Restore backups later with:${NC}"
[[ -f "$GEMINI_BACKUP" ]] && echo -e "  cp ${GEMINI_BACKUP} ${GEMINI_CONFIG}"
[[ -f "$CODEX_BACKUP" ]] && echo -e "  cp ${CODEX_BACKUP} ${CODEX_CONFIG}"
echo -e "  claude mcp remove sentinelgate"
echo ""
success "Setup complete."
