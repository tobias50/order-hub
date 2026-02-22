#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

fail=0

err() {
  echo "[guard] ERROR: $*" >&2
  fail=1
}

if command -v rg >/dev/null 2>&1; then
  search_n() { rg -n "$@"; }
  search_q() { rg -q "$@"; }
else
  search_n() { grep -R -n -E -- "$1" "${@:2}"; }
  search_q() { grep -R -q -E -- "$1" "${@:2}"; }
fi

while IFS=':' read -r wrapper refactor; do
  [ -n "$wrapper" ] || continue
  [ -n "$refactor" ] || continue

  if [ ! -f "mu-plugins/$wrapper" ]; then
    err "Missing wrapper: mu-plugins/$wrapper"
    continue
  fi
  if [ ! -f "mu-plugins/$refactor/bootstrap.php" ]; then
    err "Missing bootstrap: mu-plugins/$refactor/bootstrap.php"
  fi
  if [ ! -f "mu-plugins/$refactor/includes/modules/001-runtime-main.php" ]; then
    err "Missing main module: mu-plugins/$refactor/includes/modules/001-runtime-main.php"
  fi
  if [ ! -d "mu-plugins/$refactor/includes/modules/001-runtime-main.d" ]; then
    err "Missing segments directory: mu-plugins/$refactor/includes/modules/001-runtime-main.d"
  fi

  refactor_basename="$(basename "$refactor")"
  if ! search_q "$refactor_basename/bootstrap\\.php" "mu-plugins/$wrapper"; then
    err "Wrapper does not point at bootstrap: mu-plugins/$wrapper"
  fi
  if ! search_q "001-runtime-main\\.d/001-runtime-main-seg-\\*\\.php" "mu-plugins/$refactor/includes/modules/001-runtime-main.php"; then
    err "Main module must load segment files: mu-plugins/$refactor/includes/modules/001-runtime-main.php"
  fi
  if ! find "mu-plugins/$refactor/includes/modules/001-runtime-main.d" -type f -name '001-runtime-main-seg-*.php' | grep -q .; then
    err "No segment files found: mu-plugins/$refactor/includes/modules/001-runtime-main.d"
  fi
done <<'MAP'
np-order-hub/np-order-hub.php:np-order-hub/np-order-hub-refactor
np-order-hub/np-order-hub-store-wpo.php:np-order-hub/np-order-hub-store-wpo-refactor
MAP

if git ls-files | rg -n "\.DS_Store$" >/tmp/refactor_ci_guard_ds_store_order_hub.txt 2>/dev/null; then
  err "Tracked .DS_Store files found:"
  cat /tmp/refactor_ci_guard_ds_store_order_hub.txt >&2
fi

if find mu-plugins \
  \( -path 'mu-plugins/np-order-hub/vendor' -o -path 'mu-plugins/np-order-hub/vendor/*' \) -prune \
  -o -print | rg -n "[A-Z]|[[:space:]]|\.DS_Store|\.\.+" >/tmp/refactor_ci_guard_naming_order_hub.txt 2>/dev/null; then
  err "Found non-normalized names in mu-plugins:"
  cat /tmp/refactor_ci_guard_naming_order_hub.txt >&2
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "Refactor CI guard OK."
