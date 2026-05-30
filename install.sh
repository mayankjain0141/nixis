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
    tar -xzf "${TMPDIR}/${TARBALL}" -C "$INSTALL_DIR"
    chmod +x "${INSTALL_DIR}/nixis" "${INSTALL_DIR}/nixis-hook"
}

print_success() {
    printf "\n\033[1;32m✓ Nixis installed successfully!\033[0m\n\n"
    printf "  Binaries: %s/nixis, %s/nixis-hook\n" "$INSTALL_DIR" "$INSTALL_DIR"
    printf "  Version:  %s\n\n" "$VERSION"

    case ":${PATH}:" in
        *":${INSTALL_DIR}:"*) ;;
        *)
            printf "  Add to your PATH:\n"
            printf "    export PATH=\"%s:\$PATH\"\n\n" "$INSTALL_DIR"
            ;;
    esac

    printf "  Run 'nixis setup' to configure.\n\n"
}

main() {
    info "Installing Nixis..."
    detect_platform
    info "Platform: ${OS}/${ARCH}"
    get_version
    download
    verify_checksum
    install_binaries
    print_success
}

main
