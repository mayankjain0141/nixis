#!/bin/sh
set -euo pipefail

REPO="mayankjain0141/nixis"
INSTALL_DIR="${NIXIS_INSTALL_DIR:-$HOME/.nixis}"

info() { printf "\033[1;34m==>\033[0m %s\n" "$1"; }
warn() { printf "\033[1;33mWARN:\033[0m %s\n" "$1"; }
err() { printf "\033[1;31mERROR:\033[0m %s\n" "$1" >&2; exit 1; }

detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    case "$OS" in
        darwin) OS="darwin" ;;
        linux)  OS="linux" ;;
        *)      err "Unsupported OS: $OS" ;;
    esac

    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64)  ARCH="amd64" ;;
        arm64|aarch64) ARCH="arm64" ;;
        *)             err "Unsupported architecture: $ARCH" ;;
    esac
}

get_version() {
    if [ -n "${NIXIS_VERSION:-}" ]; then
        VERSION="$NIXIS_VERSION"
        info "Using specified version: $VERSION"
        return
    fi

    info "Fetching latest release version..."
    VERSION=$(curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' \
        | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')

    if [ -z "$VERSION" ]; then
        err "Failed to determine latest version. Set NIXIS_VERSION manually."
    fi
    info "Latest version: $VERSION"
}

download() {
    VERSION_STRIPPED=$(echo "$VERSION" | sed 's/^v//')
    TARBALL="nixis_${OS}_${ARCH}.tar.gz"
    BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"

    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT

    info "Downloading ${TARBALL}..."
    curl -sSfL -o "${TMPDIR}/${TARBALL}" "${BASE_URL}/${TARBALL}" \
        || err "Download failed. Check that release ${VERSION} exists for ${OS}/${ARCH}."

    info "Downloading checksums..."
    curl -sSfL -o "${TMPDIR}/checksums.txt" "${BASE_URL}/checksums.txt" \
        || err "Failed to download checksums.txt"
}

verify_checksum() {
    info "Verifying SHA-256 checksum..."
    EXPECTED=$(grep "${TARBALL}" "${TMPDIR}/checksums.txt" | awk '{print $1}')
    if [ -z "$EXPECTED" ]; then
        err "Checksum for ${TARBALL} not found in checksums.txt"
    fi

    if command -v sha256sum >/dev/null 2>&1; then
        ACTUAL=$(sha256sum "${TMPDIR}/${TARBALL}" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        ACTUAL=$(shasum -a 256 "${TMPDIR}/${TARBALL}" | awk '{print $1}')
    else
        err "No sha256sum or shasum found. Cannot verify checksum."
    fi

    if [ "$EXPECTED" != "$ACTUAL" ]; then
        err "Checksum mismatch!\n  Expected: ${EXPECTED}\n  Actual:   ${ACTUAL}"
    fi
    info "Checksum verified."
}

install_binaries() {
    info "Installing to ${INSTALL_DIR}..."
    mkdir -p "$INSTALL_DIR"
    mkdir -p "${TMPDIR}/extracted"
    tar -xzf "${TMPDIR}/${TARBALL}" -C "${TMPDIR}/extracted"
    for bin in nixis nixis-hook nixis-daemon; do
        mv -f "${TMPDIR}/extracted/${bin}" "${INSTALL_DIR}/${bin}"
    done
    chmod +x "${INSTALL_DIR}/nixis" "${INSTALL_DIR}/nixis-hook" "${INSTALL_DIR}/nixis-daemon"
    # Move policies from tarball into install dir
    if [ -d "${TMPDIR}/extracted/policies" ]; then
        mkdir -p "${INSTALL_DIR}/policies"
        cp -r "${TMPDIR}/extracted/policies/." "${INSTALL_DIR}/policies/"
    fi
}

run_setup() {
    info "Configuring (daemon + hook)..."
    # Policies are already in ${INSTALL_DIR}/policies from the tarball;
    # pass --policy-dir so setup doesn't look for ./policies in CWD.
    "${INSTALL_DIR}/nixis" setup --yes --skip-binaries --policy-dir "${INSTALL_DIR}/policies"
}

# Detect the shell config file to write PATH into.
detect_shell_config() {
    # Prefer the running shell's rc file; fall back to common defaults.
    SHELL_NAME=$(basename "${SHELL:-}")
    case "$SHELL_NAME" in
        zsh)  SHELL_CONFIG="$HOME/.zshrc" ;;
        bash) SHELL_CONFIG="${HOME}/.bashrc" ;;
        fish) SHELL_CONFIG="$HOME/.config/fish/config.fish" ;;
        *)    SHELL_CONFIG="" ;;
    esac

    # Fall back to the first file that already exists.
    if [ -z "$SHELL_CONFIG" ] || [ ! -f "$SHELL_CONFIG" ]; then
        for f in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile"; do
            if [ -f "$f" ]; then
                SHELL_CONFIG="$f"
                break
            fi
        done
    fi
}

add_to_path() {
    detect_shell_config

    # Already in PATH — nothing to do.
    case ":${PATH}:" in
        *":${INSTALL_DIR}:"*) return ;;
    esac

    if [ -z "$SHELL_CONFIG" ]; then
        warn "Could not detect shell config file. Add this manually:"
        warn "  export PATH=\"${INSTALL_DIR}:\$PATH\""
        return
    fi

    # Already written to this config file — skip.
    if grep -q "${INSTALL_DIR}" "$SHELL_CONFIG" 2>/dev/null; then
        return
    fi

    if [ "$SHELL_NAME" = "fish" ]; then
        printf '\n# Nixis\nfish_add_path %s\n' "$INSTALL_DIR" >> "$SHELL_CONFIG"
    else
        printf '\n# Nixis\nexport PATH="%s:$PATH"\n' "$INSTALL_DIR" >> "$SHELL_CONFIG"
    fi

    info "Added ${INSTALL_DIR} to PATH in ${SHELL_CONFIG}"
    NEEDS_SOURCE="$SHELL_CONFIG"
}

print_success() {
    printf "\n\033[1;32m✓ Nixis %s installed to %s\033[0m\n\n" "$VERSION" "$INSTALL_DIR"
}

handle_macos_gatekeeper() {
    if [ "$OS" != "darwin" ]; then return; fi
    # Only safe to do because we already verified SHA-256 integrity above.
    if command -v xattr >/dev/null 2>&1; then
        xattr -d com.apple.quarantine "${INSTALL_DIR}/nixis" 2>/dev/null || true
        xattr -d com.apple.quarantine "${INSTALL_DIR}/nixis-hook" 2>/dev/null || true
        xattr -d com.apple.quarantine "${INSTALL_DIR}/nixis-daemon" 2>/dev/null || true
    fi
}

main() {
    info "Installing Nixis..."
    detect_platform
    info "Platform: ${OS}/${ARCH}"
    get_version
    download
    verify_checksum
    install_binaries
    handle_macos_gatekeeper
    run_setup
    print_success
}

main
