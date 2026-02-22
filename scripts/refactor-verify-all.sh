#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

echo "== Refactor CI guard =="
./scripts/refactor-ci-guard.sh

echo "== Refactor audit =="
php mu-plugins/refactor-tools/audit_refactor_structure.php

echo "== Refactor lint (mu-plugins, vendor excluded) =="
find mu-plugins \
  \( -path 'mu-plugins/np-order-hub/vendor' -o -path 'mu-plugins/np-order-hub/vendor/*' \) -prune \
  -o -type f -name '*.php' -print0 | xargs -0 -n1 php -d error_reporting=E_ERROR -l >/tmp/refactor_verify_lint_order_hub.out

echo "== Verify complete =="
