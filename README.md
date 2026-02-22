# Order hub (MU plugins)

Source of truth: `mu-plugins/`

## Local autosync
1. Copy config template:
   - `cp scripts/.env.example scripts/.env`
2. Set:
   - `ORDERHUB_SSH_USER`
   - `ORDERHUB_WEB_ROOT`
3. Run once:
   - `scripts/mu-sync.sh`
4. Run watch mode:
   - `scripts/mu-watch.sh`

## GitHub deploy
Push to `main` with changes in `mu-plugins/**`.

Required repo secret:
- `SERVEBOLT_SSH_KEY`

Required repo variables:
- `ORDERHUB_SSH_USER`
- `ORDERHUB_WEB_ROOT`

## Refactor maintenance
- Split runtime modules after larger edits:
  - `php scripts/refactor-phase3-split-runtime.php`
- Run full validation:
  - `./scripts/refactor-verify-all.sh`
