#!/usr/bin/env bash
# Optional local signature helper for Linux/macOS/Git Bash.
# Usage: ./scripts_test_signature.sh 'secret' '{"action":"opened"}'
set -euo pipefail
SECRET="${1:?secret required}"
BODY="${2:?json body required}"
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $2}')
echo "sha256=$SIG"
