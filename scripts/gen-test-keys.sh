#!/usr/bin/env bash
# gen-test-keys.sh — generate Ed25519 key pair for go test ./...
# Keys are gitignored. Run once after cloning, or after deleting testdata/.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TESTDATA="$REPO_ROOT/testdata"

mkdir -p "$TESTDATA"
openssl genpkey -algorithm ed25519 -out "$TESTDATA/bundle_signing_key.pem"
openssl pkey -in "$TESTDATA/bundle_signing_key.pem" -pubout -out "$TESTDATA/bundle_signing_pub.pem"
echo "Test keys written to $TESTDATA/"
