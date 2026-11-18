#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/tests/smoke-php-compat.php"

for bin in php8.3 php8.4 php8.5 php; do
    if command -v "$bin" >/dev/null 2>&1; then
        "$bin" "$SCRIPT"
    fi
done