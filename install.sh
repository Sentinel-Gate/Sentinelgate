#!/bin/sh
# SentinelGate installer
# Usage: curl -sSfL https://raw.githubusercontent.com/Sentinel-Gate/Sentinelgate/main/install.sh | sh
#
# Environment variables:
#   VERSION      - specific version to install (e.g., v0.5.0). Default: latest
#   INSTALL_DIR  - installation directory. Default: /usr/local/bin

set -e

REPO="Sentinel-Gate/Sentinelgate"
BINARY_NAME="sentinel-gate"
DEFAULT_INSTALL_DIR="/usr/local/bin"
FALLBACK_INSTALL_DIR="${HOME}/.local/bin"

# ── Cleanup ──────────────────────────────────────────────────────────────────

TMPDIR_INSTALL=""

cleanup() {
    if [ -n "${TMPDIR_INSTALL}" ] && [ -d "${TMPDIR_INSTALL}" ]; then
        rm -rf "${TMPDIR_INSTALL}"
    fi
}

trap cleanup EXIT

# ── Colors ───────────────────────────────────────────────────────────────────

setup_colors() {
    if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
        RED='\033[0;31m'
        GREEN='\033[0;32m'
        YELLOW='\033[0;33m'
        BLUE='\033[0;34m'
        BOLD='\033[1m'
        RESET='\033[0m'
    else
        RED=''
        GREEN=''
        YELLOW=''
        BLUE=''
        BOLD=''
        RESET=''
    fi
}

# ── Logging ──────────────────────────────────────────────────────────────────

info() {
    printf "${BLUE}=>${RESET} %s\n" "$1"
}

success() {
    printf "${GREEN}=>${RESET} %s\n" "$1"
}

warn() {
    printf "${YELLOW}WARNING:${RESET} %s\n" "$1" >&2
}

error() {
    printf "${RED}ERROR:${RESET} %s\n" "$1" >&2
    exit 1
}

# ── Dependency checks ────────────────────────────────────────────────────────

check_deps() {
    if command -v curl >/dev/null 2>&1; then
        HTTP_CLIENT="curl"
    elif command -v wget >/dev/null 2>&1; then
        HTTP_CLIENT="wget"
    else
        error "Either curl or wget is required. Please install one and try again."
    fi

    if ! command -v tar >/dev/null 2>&1; then
        error "tar is required. Please install it and try again."
    fi

    if command -v sha256sum >/dev/null 2>&1; then
        SHA_CMD="sha256sum"
    elif command -v shasum >/dev/null 2>&1; then
        SHA_CMD="shasum -a 256"
    else
        error "sha256sum or shasum is required. Please install one and try again."
    fi
}

# ── HTTP helpers ─────────────────────────────────────────────────────────────

http_get() {
    url="$1"
    output="$2"
    if [ "${HTTP_CLIENT}" = "curl" ]; then
        curl -sSfL -o "${output}" "${url}"
    else
        wget -q -O "${output}" "${url}"
    fi
}

http_get_stdout() {
    url="$1"
    if [ "${HTTP_CLIENT}" = "curl" ]; then
        curl -sSfL "${url}"
    else
        wget -q -O - "${url}"
    fi
}

# ── OS / Architecture detection ──────────────────────────────────────────────

detect_os() {
    os="$(uname -s)"
    case "${os}" in
        Linux)  OS="linux" ;;
        Darwin) OS="darwin" ;;
        *)      error "Unsupported operating system: ${os}. Only Linux and macOS are supported." ;;
    esac
}

detect_arch() {
    arch="$(uname -m)"
    case "${arch}" in
        x86_64|amd64)   ARCH="amd64" ;;
        aarch64|arm64)  ARCH="arm64" ;;
        *)              error "Unsupported architecture: ${arch}. Only amd64 and arm64 are supported." ;;
    esac
}

# ── Version resolution ───────────────────────────────────────────────────────

resolve_version() {
    if [ -n "${VERSION:-}" ]; then
        info "Using specified version: ${VERSION}"
        return
    fi

    info "Fetching latest release version..."

    # Try stable release first, fall back to most recent (includes pre-releases)
    api_url="https://api.github.com/repos/${REPO}/releases/latest"
    response="$(http_get_stdout "${api_url}" 2>/dev/null)" || {
        info "No stable release found, checking pre-releases..."
        api_url="https://api.github.com/repos/${REPO}/releases"
        response="$(http_get_stdout "${api_url}")" || error "Failed to fetch releases from GitHub API."
    }

    # Extract tag_name without jq (POSIX-compatible)
    VERSION="$(printf '%s' "${response}" | tr ',' '\n' | grep '"tag_name"' | head -1 | cut -d'"' -f4)"

    if [ -z "${VERSION}" ]; then
        error "Could not determine latest version from GitHub API response."
    fi

    info "Latest version: ${VERSION}"
}

# ── Download and verify ──────────────────────────────────────────────────────

download_and_verify() {
    TMPDIR_INSTALL="$(mktemp -d)"

    archive_name="${BINARY_NAME}_${OS}_${ARCH}.tar.gz"
    archive_url="https://github.com/${REPO}/releases/download/${VERSION}/${archive_name}"
    checksums_url="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"

    info "Downloading ${archive_name}..."
    http_get "${archive_url}" "${TMPDIR_INSTALL}/${archive_name}" || \
        error "Failed to download archive from ${archive_url}"

    info "Downloading checksums..."
    http_get "${checksums_url}" "${TMPDIR_INSTALL}/checksums.txt" || \
        error "Failed to download checksums from ${checksums_url}"

    info "Verifying SHA-256 checksum..."
    expected="$(grep "${archive_name}" "${TMPDIR_INSTALL}/checksums.txt" | cut -d' ' -f1)"
    if [ -z "${expected}" ]; then
        error "Could not find checksum for ${archive_name} in checksums.txt"
    fi

    actual="$(cd "${TMPDIR_INSTALL}" && ${SHA_CMD} "${archive_name}" | cut -d' ' -f1)"
    if [ "${expected}" != "${actual}" ]; then
        error "Checksum mismatch for ${archive_name}\n  Expected: ${expected}\n  Actual:   ${actual}"
    fi

    success "Checksum verified."
}

# ── Install ──────────────────────────────────────────────────────────────────

install_binary() {
    info "Extracting ${BINARY_NAME}..."
    tar -xzf "${TMPDIR_INSTALL}/${BINARY_NAME}_${OS}_${ARCH}.tar.gz" -C "${TMPDIR_INSTALL}"

    if [ ! -f "${TMPDIR_INSTALL}/${BINARY_NAME}" ]; then
        error "Binary '${BINARY_NAME}' not found in archive."
    fi

    # Determine install directory
    install_dir="${INSTALL_DIR:-}"
    if [ -z "${install_dir}" ]; then
        if [ -d "${DEFAULT_INSTALL_DIR}" ] && [ -w "${DEFAULT_INSTALL_DIR}" ]; then
            install_dir="${DEFAULT_INSTALL_DIR}"
        else
            install_dir="${FALLBACK_INSTALL_DIR}"
            mkdir -p "${install_dir}"
            warn "${DEFAULT_INSTALL_DIR} is not writable. Installing to ${install_dir}"
            case ":${PATH}:" in
                *":${install_dir}:"*) ;;
                *) warn "Add ${install_dir} to your PATH: export PATH=\"\${PATH}:${install_dir}\"" ;;
            esac
        fi
    else
        if [ ! -d "${install_dir}" ]; then
            mkdir -p "${install_dir}"
        fi
    fi

    cp "${TMPDIR_INSTALL}/${BINARY_NAME}" "${install_dir}/${BINARY_NAME}"
    chmod +x "${install_dir}/${BINARY_NAME}"

    INSTALLED_PATH="${install_dir}/${BINARY_NAME}"
}

# ── Main ─────────────────────────────────────────────────────────────────────

main() {
    setup_colors

    printf '\n%sSentinelGate Installer%s\n\n' "${BOLD}" "${RESET}"

    check_deps
    detect_os
    detect_arch
    resolve_version
    download_and_verify
    install_binary

    printf "\n"
    success "SentinelGate ${VERSION} installed successfully!"
    info "Binary: ${INSTALLED_PATH}"
    info "Run '${BOLD}sentinel-gate start${RESET}' to get started."

    CA_CERT="${HOME}/.sentinelgate/ca-cert.pem"
    if [ -f "${CA_CERT}" ]; then
        printf "\n"
        info "Found existing CA certificate. To trust it system-wide, run:"
        info "  ${INSTALLED_PATH} trust-ca"
    fi

    printf "\n"
}

main
