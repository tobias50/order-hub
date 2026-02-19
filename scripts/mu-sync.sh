#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="$ROOT_DIR/mu-plugins/"
SSH_KEY="${HOME}/.ssh/servebolt_deploy"

# Optional override file: scripts/.env
if [[ -f "$ROOT_DIR/scripts/.env" ]]; then
  # shellcheck disable=SC1091
  source "$ROOT_DIR/scripts/.env"
fi

DEST_USER="${ORDERHUB_SSH_USER:-}"
DEST_HOST="${ORDERHUB_SSH_HOST:-angelo-osl.servebolt.cloud}"
DEST_PATH="${ORDERHUB_WEB_ROOT:-}"

if [[ -z "$DEST_USER" || -z "$DEST_PATH" ]]; then
  echo "Mangler ORDERHUB_SSH_USER eller ORDERHUB_WEB_ROOT."
  echo "Sett i scripts/.env, f.eks:"
  echo "  ORDERHUB_SSH_USER='ordre_12345'"
  echo "  ORDERHUB_WEB_ROOT='/cust/0/bolt_xxxxx/ordre_12345/site/public'"
  exit 1
fi

if [[ ! -f "$SSH_KEY" ]]; then
  echo "Mangler SSH key: $SSH_KEY"
  exit 1
fi

DEST="${DEST_USER}@${DEST_HOST}:${DEST_PATH}/wp-content/mu-plugins/"
SSH_CMD="ssh -p 22 -i $SSH_KEY -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new"

rsync -avz --delete -e "$SSH_CMD" "$SRC_DIR" "$DEST"
