#!/usr/bin/env bash
# agent-cleanup.sh — Clean up after manual E2E testing of real AI agents with SentinelGate
# Safe to run multiple times (idempotent)
set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ── Defaults ──────────────────────────────────────────────────────────────────
KEEP_TEST_DIR=false
TEST_DIR="/tmp/sg-e2e-test"

# ── Summary counters ─────────────────────────────────────────────────────────
RESTORED=0
REMOVED=0
SKIPPED=0

# ── Helpers ───────────────────────────────────────────────────────────────────
info()    { echo -e "${YELLOW}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
err()     { echo -e "${RED}[ERR]${NC}   $*"; }

usage() {
    cat <<EOF
${BOLD}agent-cleanup.sh${NC} — Clean up after SentinelGate manual agent testing

${BOLD}Usage:${NC}
  $(basename "$0") [OPTIONS]

${BOLD}Options:${NC}
  --keep-test-dir   Do not remove ${TEST_DIR}
  --help, -h        Show this help message

${BOLD}What it does:${NC}
  1. Restore Gemini config from backup (or strip sentinelgate entry)
  2. Restore Codex config from backup (or strip sentinelgate block)
  3. Remove 'sentinelgate' MCP server from Claude Code
  4. Remove ${TEST_DIR} (unless --keep-test-dir)
EOF
    exit 0
}

# ── Parse flags ───────────────────────────────────────────────────────────────
for arg in "$@"; do
    case "$arg" in
        --keep-test-dir) KEEP_TEST_DIR=true ;;
        --help|-h)       usage ;;
        *)               err "Unknown option: $arg"; usage ;;
    esac
done

echo ""
echo -e "${BOLD}═══ SentinelGate Agent Cleanup ═══${NC}"
echo ""

# ── 1. Gemini ─────────────────────────────────────────────────────────────────
GEMINI_CFG="$HOME/.gemini/settings.json"
GEMINI_BAK="$HOME/.gemini/settings.json.sg-backup"

info "Gemini config: ${GEMINI_CFG}"

if [[ -f "$GEMINI_BAK" ]]; then
    cp "$GEMINI_BAK" "$GEMINI_CFG"
    rm "$GEMINI_BAK"
    success "Restored Gemini config from backup"
    ((RESTORED++))
elif [[ -f "$GEMINI_CFG" ]]; then
    if command -v jq &>/dev/null; then
        if jq -e '.mcpServers.sentinelgate' "$GEMINI_CFG" &>/dev/null; then
            tmp=$(mktemp)
            jq 'del(.mcpServers.sentinelgate)' "$GEMINI_CFG" > "$tmp" && mv "$tmp" "$GEMINI_CFG"
            success "Removed .mcpServers.sentinelgate from Gemini config (jq)"
            ((REMOVED++))
        else
            info "Gemini config exists but has no sentinelgate entry — nothing to do"
            ((SKIPPED++))
        fi
    else
        err "jq not found — cannot clean Gemini config automatically"
        err "Manually remove the sentinelgate block from ${GEMINI_CFG}"
    fi
else
    info "No Gemini config found — skipping"
    ((SKIPPED++))
fi

# ── 2. Codex ──────────────────────────────────────────────────────────────────
CODEX_CFG="$HOME/.codex/config.toml"
CODEX_BAK="$HOME/.codex/config.toml.sg-backup"

info "Codex config: ${CODEX_CFG}"

if [[ -f "$CODEX_BAK" ]]; then
    cp "$CODEX_BAK" "$CODEX_CFG"
    rm "$CODEX_BAK"
    success "Restored Codex config from backup"
    ((RESTORED++))
elif [[ -f "$CODEX_CFG" ]]; then
    # Codex TOML block looks like:
    #   [mcp_servers.sentinelgate]
    #   ...lines until next [section] or EOF
    if grep -q '\[mcp_servers\.sentinelgate\]' "$CODEX_CFG" 2>/dev/null; then
        tmp=$(mktemp)
        # Remove from [mcp_servers.sentinelgate] up to (but not including) the next [section] or EOF
        awk '
            /^\[mcp_servers\.sentinelgate\]/ { skip=1; next }
            /^\[/                            { skip=0 }
            !skip                            { print }
        ' "$CODEX_CFG" > "$tmp" && mv "$tmp" "$CODEX_CFG"
        success "Removed [mcp_servers.sentinelgate] block from Codex config"
        ((REMOVED++))
    else
        info "Codex config exists but has no sentinelgate block — nothing to do"
        ((SKIPPED++))
    fi
else
    info "No Codex config found — skipping"
    ((SKIPPED++))
fi

# ── 3. Claude Code ───────────────────────────────────────────────────────────
info "Removing sentinelgate MCP server from Claude Code..."
if command -v claude &>/dev/null; then
    if claude mcp remove sentinelgate 2>/dev/null; then
        success "Removed sentinelgate from Claude Code"
        ((REMOVED++))
    else
        info "sentinelgate was not registered in Claude Code — nothing to do"
        ((SKIPPED++))
    fi
else
    info "claude CLI not found — skipping Claude Code cleanup"
    ((SKIPPED++))
fi

# ── 4. Test directory ────────────────────────────────────────────────────────
if [[ "$KEEP_TEST_DIR" == true ]]; then
    info "Keeping test directory ${TEST_DIR} (--keep-test-dir)"
    ((SKIPPED++))
elif [[ -d "$TEST_DIR" ]]; then
    rm -rf "$TEST_DIR"
    success "Removed test directory ${TEST_DIR}"
    ((REMOVED++))
else
    info "Test directory ${TEST_DIR} does not exist — nothing to do"
    ((SKIPPED++))
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}── Summary ──${NC}"
echo -e "  ${GREEN}Restored from backup:${NC} ${RESTORED}"
echo -e "  ${GREEN}Entries removed:${NC}      ${REMOVED}"
echo -e "  ${YELLOW}Skipped (nothing):${NC}   ${SKIPPED}"
echo ""
echo -e "${GREEN}Cleanup complete.${NC}"
