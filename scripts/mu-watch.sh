#!/usr/bin/env bash
set -euo pipefail

if ! command -v fswatch >/dev/null 2>&1; then
  echo "fswatch er ikke installert. Installer med: brew install fswatch"
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="$ROOT_DIR/mu-plugins"

"$ROOT_DIR/scripts/mu-sync.sh"

fswatch -o "$SRC_DIR" | while read -r _; do
  "$ROOT_DIR/scripts/mu-sync.sh"
done
