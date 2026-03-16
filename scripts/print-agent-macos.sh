#!/usr/bin/env bash
set -euo pipefail

# Order Hub print agent for macOS
# Polls Order Hub for next job, downloads merged PDF, prints via `lp`, reports result.
#
# Required environment variables:
#   HUB_BASE_URL   e.g. https://ordrehub.nordicprofil.no
#   PRINT_TOKEN    token from Order Hub -> Debug -> Auto print queue
#   PRINTER_NAME   exact CUPS printer name
#
# Optional:
#   AGENT_NAME     defaults to "lager-mac-1"
#   HUB_API_BASE   defaults to ${HUB_BASE_URL}/index.php/wp-json
#   LP_TIMEOUT_SECONDS defaults to 45
#   CURL_TIMEOUT_SECONDS defaults to 45
#   HTTP_RETRY_ATTEMPTS defaults to 3
#   HTTP_RETRY_DELAY_SECONDS defaults to 2
#   SELF_UPDATE_ENABLED defaults to true
#   SELF_UPDATE_URL defaults to ${HUB_BASE_URL}/wp-content/uploads/np-order-hub-print-agent/print-agent-macos.sh
#   LP_MEDIA is locked to Custom.102.7x190mm
#   LP_EXTRA_OPTIONS comma-separated (defaults set for top-aligned label print)
#   LP_IMAGE_OPTIONS comma-separated (defaults set for raster/image print)
#   LP_SPLIT_PAGES defaults to false (merged PDF fallback stays single-job)
#   LP_RASTER_DPI is locked to 203
#   LABEL_WIDTH_MM is locked to 102.7
#   LABEL_HEIGHT_MM is locked to 190
#   LP_RASTERIZE_LABEL defaults to true
#   LP_VERIFY_SECONDS defaults to 120 (wait for verified CUPS/IPP completion signal)
#   LP_FORCE_MERGED_JOB defaults to false (Zebra is more reliable with rasterized slip+label)
#
# Example:
#   HUB_BASE_URL="https://ordrehub.nordicprofil.no" \
#   PRINT_TOKEN="..." \
#   PRINTER_NAME="Zebra_etikett" \
#   AGENT_NAME="lager-mac-1" \
#   /path/to/print-agent-macos.sh

HUB_BASE_URL="${HUB_BASE_URL:-https://ordrehub.nordicprofil.no}"
PRINT_TOKEN="${PRINT_TOKEN:-}"
PRINTER_NAME="${PRINTER_NAME:-}"
AGENT_NAME="${AGENT_NAME:-lager-mac-1}"
HUB_API_BASE="${HUB_API_BASE:-${HUB_BASE_URL%/}/index.php/wp-json}"
LP_TIMEOUT_SECONDS="${LP_TIMEOUT_SECONDS:-45}"
CURL_TIMEOUT_SECONDS="${CURL_TIMEOUT_SECONDS:-45}"
HTTP_RETRY_ATTEMPTS="${HTTP_RETRY_ATTEMPTS:-3}"
HTTP_RETRY_DELAY_SECONDS="${HTTP_RETRY_DELAY_SECONDS:-2}"
SELF_UPDATE_ENABLED="${SELF_UPDATE_ENABLED:-true}"
SELF_UPDATE_URL="${SELF_UPDATE_URL:-${HUB_BASE_URL%/}/wp-content/uploads/np-order-hub-print-agent/print-agent-macos.sh}"
# Width lock for stable label format. Do not relax this without explicit printer re-calibration.
LP_MEDIA_REQUESTED="${LP_MEDIA:-}"
LP_RASTER_DPI_REQUESTED="${LP_RASTER_DPI:-}"
LABEL_WIDTH_MM_REQUESTED="${LABEL_WIDTH_MM:-}"
LABEL_HEIGHT_MM_REQUESTED="${LABEL_HEIGHT_MM:-}"
LOCKED_LABEL_WIDTH_MM="102.7"
LOCKED_LABEL_HEIGHT_MM="190"
LOCKED_RASTER_DPI="203"
LOCKED_MEDIA="Custom.${LOCKED_LABEL_WIDTH_MM}x${LOCKED_LABEL_HEIGHT_MM}mm"
LABEL_WIDTH_MM="${LOCKED_LABEL_WIDTH_MM}"
LABEL_HEIGHT_MM="${LOCKED_LABEL_HEIGHT_MM}"
LP_RASTER_DPI="${LOCKED_RASTER_DPI}"
LP_MEDIA="${LOCKED_MEDIA}"
# Force 1:1 print by default (no fit-to-page shrink). Keep top-left with zero margins.
LP_EXTRA_OPTIONS="${LP_EXTRA_OPTIONS:-print-scaling=none,position=top-left,scaling=100,number-up=1,sides=one-sided,page-top=0,page-bottom=0,page-left=0,page-right=0}"
# For rasterized images, use fit-to-page so CUPS/driver DPI assumptions do not shrink label width.
LP_IMAGE_OPTIONS="${LP_IMAGE_OPTIONS:-fit-to-page,position=top-left,number-up=1,sides=one-sided,page-top=0,page-bottom=0,page-left=0,page-right=0}"
LP_SPLIT_PAGES="${LP_SPLIT_PAGES:-false}"
LP_FORCE_MERGED_JOB="${LP_FORCE_MERGED_JOB:-false}"
LP_RASTERIZE_LABEL="${LP_RASTERIZE_LABEL:-true}"
LP_VERIFY_SECONDS="${LP_VERIFY_SECONDS:-120}"
LP_MEDIA_RESOLVED=""

if ! [[ "${HTTP_RETRY_ATTEMPTS}" =~ ^[0-9]+$ ]] || [[ "${HTTP_RETRY_ATTEMPTS}" -lt 1 ]]; then
  HTTP_RETRY_ATTEMPTS="3"
fi
if ! [[ "${HTTP_RETRY_DELAY_SECONDS}" =~ ^[0-9]+$ ]] || [[ "${HTTP_RETRY_DELAY_SECONDS}" -lt 0 ]]; then
  HTTP_RETRY_DELAY_SECONDS="2"
fi
if ! [[ "${LP_VERIFY_SECONDS}" =~ ^[0-9]+$ ]] || [[ "${LP_VERIFY_SECONDS}" -lt 120 ]]; then
  LP_VERIFY_SECONDS="120"
fi

force_merged_job_lc="$(printf '%s' "${LP_FORCE_MERGED_JOB}" | tr '[:upper:]' '[:lower:]')"
if [[ "${force_merged_job_lc}" == "1" || "${force_merged_job_lc}" == "true" || "${force_merged_job_lc}" == "yes" ]]; then
  LP_FORCE_MERGED_JOB="true"
  LP_SPLIT_PAGES="false"
else
  LP_FORCE_MERGED_JOB="false"
fi

if [[ -n "${LP_MEDIA_REQUESTED}" && "${LP_MEDIA_REQUESTED}" != "${LP_MEDIA}" ]]; then
  echo "Ignoring LP_MEDIA override '${LP_MEDIA_REQUESTED}'. Using locked '${LP_MEDIA}'." >&2
fi
if [[ -n "${LABEL_WIDTH_MM_REQUESTED}" && "${LABEL_WIDTH_MM_REQUESTED}" != "${LABEL_WIDTH_MM}" ]]; then
  echo "Ignoring LABEL_WIDTH_MM override '${LABEL_WIDTH_MM_REQUESTED}'. Using locked '${LABEL_WIDTH_MM}'." >&2
fi
if [[ -n "${LABEL_HEIGHT_MM_REQUESTED}" && "${LABEL_HEIGHT_MM_REQUESTED}" != "${LABEL_HEIGHT_MM}" ]]; then
  echo "Ignoring LABEL_HEIGHT_MM override '${LABEL_HEIGHT_MM_REQUESTED}'. Using locked '${LABEL_HEIGHT_MM}'." >&2
fi
if [[ -n "${LP_RASTER_DPI_REQUESTED}" && "${LP_RASTER_DPI_REQUESTED}" != "${LP_RASTER_DPI}" ]]; then
  echo "Ignoring LP_RASTER_DPI override '${LP_RASTER_DPI_REQUESTED}'. Using locked '${LP_RASTER_DPI}'." >&2
fi

if [[ -z "${PRINT_TOKEN}" ]]; then
  echo "PRINT_TOKEN is required."
  exit 1
fi

if [[ -z "${PRINTER_NAME}" ]]; then
  echo "PRINTER_NAME is required."
  exit 1
fi

CLAIM_URL="${HUB_API_BASE%/}/np-order-hub/v1/print-agent/claim"
FINISH_URL="${HUB_API_BASE%/}/np-order-hub/v1/print-agent/finish"
TMP_DIR="${TMPDIR:-/tmp}/np-order-hub-print-agent"
mkdir -p "${TMP_DIR}"

self_update_if_needed() {
  local enabled_lc
  enabled_lc="$(printf '%s' "${SELF_UPDATE_ENABLED}" | tr '[:upper:]' '[:lower:]')"
  if [[ "${enabled_lc}" != "1" && "${enabled_lc}" != "true" && "${enabled_lc}" != "yes" ]]; then
    return 0
  fi
  if [[ "${NP_AGENT_SELF_UPDATED:-0}" == "1" ]]; then
    return 0
  fi
  if [[ -z "${SELF_UPDATE_URL}" ]]; then
    return 0
  fi

  local script_path tmp_update current_hash new_hash
  script_path="${BASH_SOURCE[0]}"
  if [[ -z "${script_path}" || ! -f "${script_path}" ]]; then
    return 0
  fi

  tmp_update="$(/usr/bin/mktemp "${TMP_DIR}/self-update.XXXXXX")" || return 0
  if ! curl -fLsS --connect-timeout 10 --max-time 20 "${SELF_UPDATE_URL}" -o "${tmp_update}"; then
    rm -f "${tmp_update}" || true
    return 0
  fi
  if ! bash -n "${tmp_update}" >/dev/null 2>&1; then
    rm -f "${tmp_update}" || true
    return 0
  fi

  current_hash="$(shasum -a 256 "${script_path}" | awk '{print $1}')"
  new_hash="$(shasum -a 256 "${tmp_update}" | awk '{print $1}')"
  if [[ -z "${current_hash}" || -z "${new_hash}" || "${current_hash}" == "${new_hash}" ]]; then
    rm -f "${tmp_update}" || true
    return 0
  fi

  cp "${tmp_update}" "${script_path}"
  chmod +x "${script_path}"
  rm -f "${tmp_update}" || true
  echo "Self-updated print agent script (${current_hash} -> ${new_hash}). Restarting script."
  export NP_AGENT_SELF_UPDATED=1
  exec /bin/bash "${script_path}"
}

self_update_if_needed

acquire_run_lock() {
  local lock_dir pid_file existing_pid
  lock_dir="${TMP_DIR}/run.lock"
  pid_file="${lock_dir}/pid"

  if mkdir "${lock_dir}" 2>/dev/null; then
    printf '%s\n' "$$" > "${pid_file}"
    trap 'rm -rf "'"${lock_dir}"'" >/dev/null 2>&1 || true' EXIT INT TERM
    return 0
  fi

  if [[ -f "${pid_file}" ]]; then
    existing_pid="$(cat "${pid_file}" 2>/dev/null || true)"
    if [[ "${existing_pid}" =~ ^[0-9]+$ ]] && kill -0 "${existing_pid}" 2>/dev/null; then
      echo "Another print-agent run is active (pid ${existing_pid}). Skipping this run."
      exit 0
    fi
  fi

  rm -rf "${lock_dir}" >/dev/null 2>&1 || true
  if mkdir "${lock_dir}" 2>/dev/null; then
    printf '%s\n' "$$" > "${pid_file}"
    trap 'rm -rf "'"${lock_dir}"'" >/dev/null 2>&1 || true' EXIT INT TERM
    return 0
  fi

  echo "Unable to acquire print-agent run lock. Skipping this run."
  exit 0
}

acquire_run_lock

PRINT_META_CURRENT_MODE=""
PRINT_META_VERIFICATION_STATE=""
PRINT_META_VERIFICATION_METHOD=""
PRINT_META_VERIFICATION_NOTE=""
PRINT_META_VERIFIED_AT_GMT=""
PRINT_META_CUPS_JOB_MAP=""
PRINT_META_CUPS_JOB_IDS=""
PRINT_META_FAILURE_STAGE=""
PRINT_META_FAILURE_CODE=""
PRINT_META_HARD_FAILURE="false"

slugify_stage() {
  local value="$1"
  value="$(printf '%s' "${value}" | tr '[:upper:]' '[:lower:]' | tr ' /' '__' | tr -cd 'a-z0-9_-')"
  if [[ -z "${value}" ]]; then
    value="job"
  fi
  printf '%s' "${value}"
}

append_unique_csv() {
  local existing="$1"
  local value="$2"
  if [[ -z "${value}" ]]; then
    printf '%s' "${existing}"
    return 0
  fi
  if [[ -z "${existing}" ]]; then
    printf '%s' "${value}"
    return 0
  fi
  local part
  IFS=',' read -r -a parts <<<"${existing}"
  for part in "${parts[@]}"; do
    if [[ "${part}" == "${value}" ]]; then
      printf '%s' "${existing}"
      return 0
    fi
  done
  printf '%s,%s' "${existing}" "${value}"
}

append_note_unique() {
  local existing="$1"
  local value="$2"
  if [[ -z "${value}" ]]; then
    printf '%s' "${existing}"
    return 0
  fi
  if [[ -z "${existing}" ]]; then
    printf '%s' "${value}"
    return 0
  fi
  if [[ "${existing}" == *"${value}"* ]]; then
    printf '%s' "${existing}"
    return 0
  fi
  printf '%s; %s' "${existing}" "${value}"
}

record_cups_job() {
  local stage_label="$1"
  local job_id="$2"
  local stage_slug
  stage_slug="$(slugify_stage "${stage_label}")"
  if [[ -z "${job_id}" ]]; then
    return 0
  fi
  if [[ -z "${PRINT_META_CUPS_JOB_MAP}" ]]; then
    PRINT_META_CUPS_JOB_MAP="${stage_slug}::${job_id}"
  else
    case "||${PRINT_META_CUPS_JOB_MAP}||" in
      *"||${stage_slug}::${job_id}||"*) ;;
      *) PRINT_META_CUPS_JOB_MAP="${PRINT_META_CUPS_JOB_MAP}||${stage_slug}::${job_id}" ;;
    esac
  fi
  PRINT_META_CUPS_JOB_IDS="$(append_unique_csv "${PRINT_META_CUPS_JOB_IDS}" "${job_id}")"
}

set_print_verified() {
  local method="$1"
  local note="${2:-}"
  if [[ "${PRINT_META_VERIFICATION_STATE}" != "needs_review" ]]; then
    PRINT_META_VERIFICATION_STATE="verified"
  fi
  if [[ -n "${method}" ]]; then
    PRINT_META_VERIFICATION_METHOD="${method}"
  fi
  PRINT_META_VERIFIED_AT_GMT="$(date -u '+%Y-%m-%d %H:%M:%S')"
  if [[ -n "${note}" ]]; then
    PRINT_META_VERIFICATION_NOTE="$(append_note_unique "${PRINT_META_VERIFICATION_NOTE}" "${note}")"
  fi
}

set_print_needs_review() {
  local note="$1"
  if [[ "${PRINT_META_VERIFICATION_STATE}" == "" || "${PRINT_META_VERIFICATION_STATE}" == "verified" ]]; then
    PRINT_META_VERIFICATION_STATE="needs_review"
  fi
  if [[ -n "${note}" ]]; then
    PRINT_META_VERIFICATION_NOTE="$(append_note_unique "${PRINT_META_VERIFICATION_NOTE}" "${note}")"
  fi
}

set_print_failure_meta() {
  local stage_label="$1"
  local failure_code="$2"
  local hard_failure="${3:-true}"
  PRINT_META_FAILURE_STAGE="$(slugify_stage "${stage_label}")"
  PRINT_META_FAILURE_CODE="${failure_code}"
  if [[ "${hard_failure}" == "true" ]]; then
    PRINT_META_HARD_FAILURE="true"
  else
    PRINT_META_HARD_FAILURE="false"
  fi
}

build_json() {
  /usr/bin/python3 - "$@" <<'PY'
import json
import sys

args = sys.argv[1:]
obj = {}
for raw in args:
    if "=" not in raw:
        continue
    key, value = raw.split("=", 1)
    if value == "__BOOL_TRUE__":
        obj[key] = True
    elif value == "__BOOL_FALSE__":
        obj[key] = False
    else:
        obj[key] = value
print(json.dumps(obj))
PY
}

build_finish_payload_json() {
  local job_key="$1"
  local claim_id="$2"
  local success="$3"
  local error_message="${4:-}"

  /usr/bin/python3 - \
    "$job_key" \
    "$claim_id" \
    "$success" \
    "$error_message" \
    "$AGENT_NAME" \
    "$PRINT_META_CURRENT_MODE" \
    "$PRINT_META_CUPS_JOB_IDS" \
    "$PRINT_META_CUPS_JOB_MAP" \
    "$PRINT_META_FAILURE_STAGE" \
    "$PRINT_META_FAILURE_CODE" \
    "$PRINT_META_HARD_FAILURE" \
    "$PRINT_META_VERIFIED_AT_GMT" \
    "$PRINT_META_VERIFICATION_STATE" \
    "$PRINT_META_VERIFICATION_METHOD" \
    "$PRINT_META_VERIFICATION_NOTE" <<'PY'
import json
import sys

(
    job_key,
    claim_id,
    success_raw,
    error_message,
    agent_name,
    mode,
    cups_job_ids,
    cups_job_map,
    failure_stage,
    failure_code,
    hard_failure_raw,
    verified_at_gmt,
    verification_state,
    verification_method,
    verification_note,
) = sys.argv[1:16]

payload = {
    "job_key": job_key,
    "claim_id": claim_id,
    "success": success_raw.lower() == "true",
    "error": error_message,
    "agent": agent_name,
}

print_meta = {
    "agent_name": agent_name,
    "mode": mode,
    "cups_job_ids": cups_job_ids,
    "cups_job_map": cups_job_map,
    "failure_stage": failure_stage,
    "failure_code": failure_code,
    "hard_failure": hard_failure_raw.lower() == "true",
    "verified_at_gmt": verified_at_gmt,
    "verification_state": verification_state,
    "verification_method": verification_method,
    "verification_note": verification_note,
}
print_meta = {k: v for k, v in print_meta.items() if not (isinstance(v, str) and v == "")}
if print_meta:
    payload["print_meta"] = print_meta

print(json.dumps(payload))
PY
}

finish_job() {
  local job_key="$1"
  local claim_id="$2"
  local success="$3"
  local error_message="${4:-}"
  local attempt

  local payload
  payload="$(build_finish_payload_json "${job_key}" "${claim_id}" "${success}" "${error_message}")"

  for ((attempt=1; attempt<=HTTP_RETRY_ATTEMPTS; attempt++)); do
    if curl -sS --connect-timeout 10 --max-time "${CURL_TIMEOUT_SECONDS}" -X POST "${FINISH_URL}" -H "X-NP-Print-Token: ${PRINT_TOKEN}" -H "Content-Type: application/json" --data "${payload}" >/dev/null; then
      return 0
    fi
    if [[ "${attempt}" -lt "${HTTP_RETRY_ATTEMPTS}" ]]; then
      sleep "${HTTP_RETRY_DELAY_SECONDS}"
    fi
  done

  echo "Finish request failed after ${HTTP_RETRY_ATTEMPTS} attempts (job=${job_key}, claim=${claim_id})." >&2
  return 1
}

claim_payload="$(build_json "agent=${AGENT_NAME}")"
claim_response=""
claim_ok="false"
for ((claim_attempt=1; claim_attempt<=HTTP_RETRY_ATTEMPTS; claim_attempt++)); do
  if claim_response="$(curl -sS --connect-timeout 10 --max-time "${CURL_TIMEOUT_SECONDS}" -X POST "${CLAIM_URL}" -H "X-NP-Print-Token: ${PRINT_TOKEN}" -H "Content-Type: application/json" --data "${claim_payload}")"; then
    claim_ok="true"
    break
  fi
  if [[ "${claim_attempt}" -lt "${HTTP_RETRY_ATTEMPTS}" ]]; then
    sleep "${HTTP_RETRY_DELAY_SECONDS}"
  fi
done
if [[ "${claim_ok}" != "true" ]]; then
  echo "Claim request failed after ${HTTP_RETRY_ATTEMPTS} attempts (network/curl error)." >&2
  exit 1
fi

claim_assignments="$(/usr/bin/python3 - "${claim_response}" <<'PY'
import json
import shlex
import sys

raw = sys.argv[1] if len(sys.argv) > 1 else ""
try:
    data = json.loads(raw)
except Exception:
    data = {}

job = data.get("job") if isinstance(data.get("job"), dict) else {}

values = {
    "status": data.get("status", ""),
    "claim_error": data.get("error", ""),
    "job_key": job.get("job_key", ""),
    "claim_id": job.get("claim_id", ""),
    "document_url": job.get("document_url", ""),
    "document_filename": job.get("document_filename", ""),
    "order_id": job.get("order_id", ""),
    "packing_url": job.get("packing_url", ""),
    "label_url": job.get("label_url", ""),
}

for key, value in values.items():
    if value is None:
        value = ""
    text = str(value).replace("\r", " ").replace("\n", " ")
    print(f"{key}={shlex.quote(text)}")
PY
)"
eval "${claim_assignments}"

if [[ "${status}" != "claimed" ]]; then
    if [[ "${status}" != "empty" ]]; then
    echo "Claim failed: status='${status}' error='${claim_error}'" >&2
    exit 1
  fi
  exit 0
fi

if [[ "${document_url}" != http://* && "${document_url}" != https://* ]]; then
  echo "Claim payload missing/invalid document_url: '${document_url}'" >&2
  if [[ -n "${job_key}" && -n "${claim_id}" ]]; then
    finish_job "${job_key}" "${claim_id}" "false" "Claim payload missing document_url"
  fi
  exit 1
fi

if [[ -z "${job_key}" || -z "${claim_id}" || -z "${document_url}" ]]; then
  if [[ -n "${job_key}" && -n "${claim_id}" ]]; then
    finish_job "${job_key}" "${claim_id}" "false" "Missing required claim fields."
  fi
  exit 1
fi

if [[ -z "${document_filename}" ]]; then
  document_filename="order-${order_id:-unknown}.pdf"
fi

safe_job_key="$(echo "${job_key}" | tr ':' '-' | tr -cd 'A-Za-z0-9._-')"
if [[ -z "${safe_job_key}" ]]; then
  safe_job_key="order-${order_id:-unknown}"
fi

download_pdf() {
  local source_url="$1"
  local target_path="$2"
  local doc_name="$3"
  local attempt
  local header
  if [[ -z "${source_url}" ]]; then
    return 1
  fi

  for ((attempt=1; attempt<=HTTP_RETRY_ATTEMPTS; attempt++)); do
    rm -f "${target_path}" || true
    if curl -fL -sS --connect-timeout 10 --max-time "${CURL_TIMEOUT_SECONDS}" "${source_url}" -o "${target_path}"; then
      if [[ ! -s "${target_path}" ]]; then
        echo "${doc_name} download is empty (attempt ${attempt}/${HTTP_RETRY_ATTEMPTS})." >&2
      else
        header="$(LC_ALL=C head -c 5 "${target_path}" 2>/dev/null || true)"
        if [[ "${header}" == "%PDF-" ]]; then
          return 0
        fi
        echo "${doc_name} download is not a valid PDF (attempt ${attempt}/${HTTP_RETRY_ATTEMPTS})." >&2
      fi
    fi

    rm -f "${target_path}" || true
    if [[ "${attempt}" -lt "${HTTP_RETRY_ATTEMPTS}" ]]; then
      sleep "${HTTP_RETRY_DELAY_SECONDS}"
    fi
  done

  return 1
}

detect_pdf_pages() {
  local file_path="$1"
  local value
  value="$(/usr/bin/python3 - "$file_path" <<'PY'
import re
import sys

path = sys.argv[1]
try:
    with open(path, "rb") as fh:
        data = fh.read()
except Exception:
    print("0")
    raise SystemExit(0)

# Count /Type /Page objects (not /Pages).
count = len(re.findall(rb"/Type\s*/Page(?!s)\b", data))
print(str(count if count > 0 else 0))
PY
)"
  if [[ "$value" =~ ^[0-9]+$ && "$value" -gt 0 ]]; then
    echo "$value"
    return 0
  fi

  # Finder metadata fallback (can be unavailable for temp files).
  value="$(/usr/bin/mdls -raw -name kMDItemNumberOfPages "$file_path" 2>/dev/null | tr -d '\r\n[:space:]' || true)"
  if [[ "$value" =~ ^[0-9]+$ && "$value" -gt 0 ]]; then
    echo "$value"
    return 0
  fi

  echo "0"
}

resolve_lp_media() {
  local requested="$1"
  /usr/bin/python3 - "$PRINTER_NAME" "$requested" "$LABEL_WIDTH_MM" "$LABEL_HEIGHT_MM" <<'PY'
import re
import subprocess
import sys

printer = sys.argv[1]
requested = (sys.argv[2] or "").strip()
label_width = (sys.argv[3] or "").strip()
label_height = (sys.argv[4] or "").strip()

def norm(v: str) -> str:
    return re.sub(r"\s+", " ", v.strip().lower())

def custom_media() -> str:
    return f"Custom.{label_width}x{label_height}mm"

if not requested:
    print(custom_media())
    raise SystemExit(0)

# If caller already passed a CUPS keyword, keep it.
if " " not in requested and "/" not in requested:
    print(requested)
    raise SystemExit(0)

try:
    proc = subprocess.run(
        ["lpoptions", "-p", printer, "-l"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    out = proc.stdout or ""
except Exception:
    print(custom_media())
    raise SystemExit(0)

target = norm(requested)
fallback_token = None

for raw_line in out.splitlines():
    line = raw_line.strip()
    if ":" not in line:
        continue
    key, rest = line.split(":", 1)
    key_low = key.lower()
    if "pagesize" not in key_low and not key_low.startswith("media"):
        continue

    for item in rest.strip().split():
        marked_default = item.startswith("*")
        token_display = item[1:] if marked_default else item
        if "/" in token_display:
            token, display = token_display.split("/", 1)
        else:
            token = token_display
            display = token_display

        token_n = norm(token)
        display_n = norm(display)
        if token == requested:
            print(token)
            raise SystemExit(0)
        if token_n == target or display_n == target:
            print(token)
            raise SystemExit(0)
        if target in display_n and fallback_token is None:
            fallback_token = token
        if marked_default and fallback_token is None:
            fallback_token = token

if fallback_token:
    print(fallback_token)
else:
    print(custom_media())
PY
}

rasterize_label_pdf() {
  local input_pdf="$1"
  local output_png="$2"
  local target_px
  local width_px
  local height_px
  target_px="$(/usr/bin/python3 - "${LABEL_WIDTH_MM}" "${LABEL_HEIGHT_MM}" "${LP_RASTER_DPI}" <<'PY'
import math
import sys

width_mm = float(sys.argv[1])
height_mm = float(sys.argv[2])
dpi = float(sys.argv[3])
width_px = max(1, int(round((width_mm / 25.4) * dpi)))
height_px = max(1, int(round((height_mm / 25.4) * dpi)))
print(f"{width_px}\t{height_px}")
PY
)"
  IFS=$'\t' read -r width_px height_px <<<"${target_px}"
  if [[ ! "${width_px}" =~ ^[0-9]+$ || ! "${height_px}" =~ ^[0-9]+$ ]]; then
    return 1
  fi
  # Render PNG to exact label pixel dimensions.
  if ! /usr/bin/sips -z "${height_px}" "${width_px}" -s format png "$input_pdf" --out "$output_png" >/dev/null 2>&1; then
    return 1
  fi
  if ! /usr/bin/sips -s dpiWidth "${LP_RASTER_DPI}" -s dpiHeight "${LP_RASTER_DPI}" "$output_png" >/dev/null 2>&1; then
    return 1
  fi
  echo "Raster target: ${width_px}x${height_px}px @ ${LP_RASTER_DPI}dpi (${LABEL_WIDTH_MM}x${LABEL_HEIGHT_MM}mm)."
  [[ -f "${output_png}" ]]
}

run_lp() {
  local print_path="$1"
  local page_range="${2:-}"
  local lp_options="${3:-$LP_EXTRA_OPTIONS}"
  /usr/bin/python3 - "$PRINTER_NAME" "$print_path" "$LP_TIMEOUT_SECONDS" "$LP_MEDIA_RESOLVED" "$lp_options" "$page_range" <<'PY'
import subprocess
import sys

printer = sys.argv[1]
path = sys.argv[2]
timeout_s = int(sys.argv[3])
media = sys.argv[4] if len(sys.argv) > 4 else ""
extra = sys.argv[5] if len(sys.argv) > 5 else ""
page_range = sys.argv[6] if len(sys.argv) > 6 else ""

cmd = ["lp", "-d", printer]
if media:
    cmd.extend(["-o", f"media={media}"])
    cmd.extend(["-o", f"PageSize={media}"])
cmd.extend(["-o", "page-set=all"])
cmd.extend(["-o", "outputorder=normal"])
options = []
for part in [segment.strip() for segment in extra.split(",") if segment.strip()]:
    # Explicitly avoid auto-shrink behavior.
    if part in ("fit-to-page", "fitplot"):
        continue
    options.append(part)

for opt in options:
    cmd.extend(["-o", opt])
if page_range:
    cmd.extend(["-o", f"page-ranges={page_range}"])
cmd.append(path)

sys.stderr.write("lp command: " + " ".join(cmd) + "\n")

try:
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        check=False,
    )
    output = (proc.stdout or "") + (proc.stderr or "")
    if output:
        sys.stdout.write(output)
    sys.exit(proc.returncode)
except subprocess.TimeoutExpired as exc:
    out = (exc.stdout or "") + (exc.stderr or "")
    if out:
        sys.stdout.write(out)
    sys.exit(124)
except Exception as exc:
    sys.stdout.write(str(exc))
    sys.exit(1)
PY
}

extract_lp_job_id() {
  local lp_output="$1"
  /usr/bin/python3 - "${lp_output}" <<'PY'
import re
import sys

text = sys.argv[1] if len(sys.argv) > 1 else ""
# Typical CUPS format: "request id is Zebra-123 (1 file(s))"
m = re.search(r"request id is [^-\\s]+-(\\d+)", text, re.IGNORECASE)
if m:
    print(m.group(1))
PY
}

extract_lp_job_block() {
  local queue_id="$1"
  local state="${2:-all}"
  lpstat -l -W "${state}" -o "${PRINTER_NAME}" 2>/dev/null | /usr/bin/awk -v id="${queue_id}" '
function is_job_header(line) {
  return line ~ /^[^ \t].*-[0-9]+[ \t]/
}
{
  if (is_job_header($0)) {
    if ($1 == id) {
      in_block = 1
    } else if (in_block) {
      exit
    } else {
      in_block = 0
    }
  }
  if (in_block) {
    print $0
  }
}
'
}

lp_job_status_summary() {
  local job_block="$1"
  local status_text
  local alerts_text
  status_text="$(printf '%s\n' "${job_block}" | sed -n 's/^[[:space:]]*Status:[[:space:]]*//p' | head -n 1)"
  alerts_text="$(printf '%s\n' "${job_block}" | sed -n 's/^[[:space:]]*Alerts:[[:space:]]*//p' | head -n 1)"

  if [[ -z "${status_text}" && -z "${alerts_text}" ]]; then
    echo "status=unknown"
    return 0
  fi
  if [[ -z "${status_text}" ]]; then
    status_text="(empty)"
  fi
  if [[ -z "${alerts_text}" ]]; then
    alerts_text="(empty)"
  fi

  echo "status=${status_text}; alerts=${alerts_text}"
}

lp_job_has_hard_error() {
  local job_block="$1"
  local status_text
  local alerts_text

  status_text="$(printf '%s\n' "${job_block}" | sed -n 's/^[[:space:]]*Status:[[:space:]]*//p' | head -n 1 | tr '[:upper:]' '[:lower:]')"
  alerts_text="$(printf '%s\n' "${job_block}" | sed -n 's/^[[:space:]]*Alerts:[[:space:]]*//p' | head -n 1 | tr '[:upper:]' '[:lower:]')"

  if [[ -n "${status_text}" ]] && printf '%s' "${status_text}" | grep -Eqi 'not responding|unreachable|unable|offline|timed out|connection refused|host is down|no route to host|could not'; then
    return 0
  fi

  if [[ -n "${alerts_text}" ]] && printf '%s' "${alerts_text}" | grep -Eqi 'printer-error|media-empty|media-jam|door-open|offline|paused|intervention|error'; then
    return 0
  fi

  return 1
}

lp_job_error_log_summary() {
  local job_id="$1"
  if [[ -z "${job_id}" || ! -f "/var/log/cups/error_log" ]]; then
    return 1
  fi

  local match
  match="$(rg -i -N "\\[Job ${job_id}\\].*(not responding|unreachable|unable|offline|timed out|connection refused|host is down|no route to host|could not|printer-error|media-empty|media-jam|door-open|paused|intervention|error)" /var/log/cups/error_log 2>/dev/null | tail -n 1 | sed 's/^[[:space:]]*//')"
  if [[ -z "${match}" ]]; then
    return 1
  fi

  echo "${match}"
  return 0
}

ipp_job_attributes() {
  local job_id="$1"
  if [[ -z "${job_id}" || ! -x "/usr/bin/python3" || ! -f "/usr/share/cups/ipptool/get-job-attributes.test" ]]; then
    return 0
  fi

  /usr/bin/python3 - "$job_id" <<'PY'
import os
import shlex
import subprocess
import sys

job_id = sys.argv[1] if len(sys.argv) > 1 else ""
if not job_id:
    raise SystemExit(0)

test_path = "/usr/share/cups/ipptool/get-job-attributes.test"
if not os.path.exists(test_path):
    raise SystemExit(0)

try:
    proc = subprocess.run(
        ["ipptool", "-tv", f"ipp://localhost/jobs/{job_id}", test_path],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
except Exception:
    raise SystemExit(0)

text = (proc.stdout or "") + "\n" + (proc.stderr or "")
fields = {
    "ipp_job_state": "",
    "ipp_job_state_reasons": "",
    "ipp_job_printer_state_message": "",
    "ipp_job_impressions_completed": "",
    "ipp_job_media_sheets_completed": "",
}

patterns = {
    "ipp_job_state": "job-state (enum) = ",
    "ipp_job_state_reasons": "job-state-reasons (keyword) = ",
    "ipp_job_printer_state_message": "job-printer-state-message (textWithoutLanguage) = ",
    "ipp_job_impressions_completed": "job-impressions-completed (integer) = ",
    "ipp_job_media_sheets_completed": "job-media-sheets-completed (integer) = ",
}

for raw_line in text.splitlines():
    line = raw_line.strip()
    for key, prefix in patterns.items():
        if line.startswith(prefix):
            fields[key] = line[len(prefix):].strip()

for key, value in fields.items():
    print(f"{key}={shlex.quote(value)}")
PY
}

ipp_job_has_hard_error() {
  local job_state="$1"
  local printer_message="$2"
  local state_reasons="${3:-}"

  local state_lc message_lc reasons_lc
  state_lc="$(printf '%s' "${job_state}" | tr '[:upper:]' '[:lower:]')"
  message_lc="$(printf '%s' "${printer_message}" | tr '[:upper:]' '[:lower:]')"
  reasons_lc="$(printf '%s' "${state_reasons}" | tr '[:upper:]' '[:lower:]')"

  if [[ -n "${state_lc}" ]] && printf '%s' "${state_lc}" | grep -Eqi 'canceled|aborted|stopped'; then
    return 0
  fi

  if [[ -n "${message_lc}" ]] && printf '%s' "${message_lc}" | grep -Eqi 'not responding|unreachable|unable|offline|timed out|connection refused|host is down|no route to host|could not|printer-error|media-empty|media-jam|door-open|paused|intervention|error'; then
    return 0
  fi

  if [[ -n "${reasons_lc}" ]] && printf '%s' "${reasons_lc}" | grep -Eqi 'job-canceled|job-aborted|job-stopped|printer-stopped|printer-error'; then
    return 0
  fi

  return 1
}

ipp_job_is_verified_success() {
  local job_state="$1"
  local printer_message="$2"
  local impressions_completed="${3:-}"
  local sheets_completed="${4:-}"

  if ipp_job_has_hard_error "${job_state}" "${printer_message}" ""; then
    return 1
  fi

  if [[ "${job_state}" != "completed" ]]; then
    return 1
  fi

  if [[ -n "${printer_message}" ]]; then
    return 1
  fi

  if [[ "${impressions_completed}" =~ ^[0-9]+$ && "${impressions_completed}" -gt 0 ]]; then
    return 0
  fi

  if [[ "${sheets_completed}" =~ ^[0-9]+$ && "${sheets_completed}" -gt 0 ]]; then
    return 0
  fi

  return 1
}

printer_queue_hard_error_summary() {
  local queue_dump
  local first_match
  queue_dump="$(lpstat -l -W not-completed -o "${PRINTER_NAME}" 2>/dev/null || true)"
  if [[ -z "${queue_dump}" ]]; then
    return 1
  fi

  first_match="$(
    printf '%s\n' "${queue_dump}" | grep -Eim1 \
      'Status:[[:space:]]*(.*(not responding|unreachable|unable|offline|timed out|connection refused|host is down|no route to host|could not))|Alerts:[[:space:]]*(.*(printer-error|media-empty|media-jam|door-open|offline|paused|intervention|error))' | sed 's/^[[:space:]]*//'
  )"
  if [[ -n "${first_match}" ]]; then
    echo "${first_match}"
    return 0
  fi
  return 1
}

verify_lp_submission() {
  local lp_output="$1"
  local stage_label="$2"

  if ! command -v lpstat >/dev/null 2>&1; then
    return 0
  fi

  local job_id
  job_id="$(extract_lp_job_id "${lp_output}")"
  if [[ -z "${job_id}" ]]; then
    # If we cannot parse job-id, accept lp success as best-effort fallback.
    set_print_needs_review "Kunne ikke lese CUPS job-id for ${stage_label}."
    return 0
  fi

  local stage_slug
  stage_slug="$(slugify_stage "${stage_label}")"
  record_cups_job "${stage_label}" "${job_id}"

  local queue_id="${PRINTER_NAME}-${job_id}"
  local end_ts
  end_ts=$(( $(date +%s) + LP_VERIFY_SECONDS ))
  local job_block
  local completed_block
  local status_summary
  local log_summary
  local ipp_assignments
  local ipp_job_state
  local ipp_job_state_reasons
  local ipp_job_printer_state_message
  local ipp_job_impressions_completed
  local ipp_job_media_sheets_completed

  while [[ $(date +%s) -le ${end_ts} ]]; do
    # If printer queue is disabled, treat as print failure.
    if lpstat -p "${PRINTER_NAME}" 2>/dev/null | grep -qi 'disabled'; then
      set_print_failure_meta "${stage_label}" "printer_disabled" "true"
      echo "printer_disabled (${stage_label})"
      return 1
    fi

    if log_summary="$(lp_job_error_log_summary "${job_id}")"; then
      set_print_failure_meta "${stage_label}" "spool_error_log" "true"
      echo "spool_error_log (${stage_label}, job=${queue_id}, ${log_summary})"
      return 1
    fi

    job_block="$(extract_lp_job_block "${queue_id}" "all" || true)"
    if [[ -n "${job_block}" ]] && lp_job_has_hard_error "${job_block}"; then
      status_summary="$(lp_job_status_summary "${job_block}")"
      set_print_failure_meta "${stage_label}" "spool_error" "true"
      echo "spool_error (${stage_label}, job=${queue_id}, ${status_summary})"
      return 1
    fi

    ipp_assignments="$(ipp_job_attributes "${job_id}" || true)"
    if [[ -n "${ipp_assignments}" ]]; then
      ipp_job_state=""
      ipp_job_state_reasons=""
      ipp_job_printer_state_message=""
      ipp_job_impressions_completed=""
      ipp_job_media_sheets_completed=""
      eval "${ipp_assignments}"

      if ipp_job_has_hard_error "${ipp_job_state}" "${ipp_job_printer_state_message}" "${ipp_job_state_reasons}"; then
        set_print_failure_meta "${stage_label}" "ipp_error" "true"
        echo "ipp_error (${stage_label}, job=${queue_id}, state=${ipp_job_state:-unknown}, reasons=${ipp_job_state_reasons:-unknown}, message=${ipp_job_printer_state_message:-unknown})"
        return 1
      fi

      if ipp_job_is_verified_success "${ipp_job_state}" "${ipp_job_printer_state_message}" "${ipp_job_impressions_completed}" "${ipp_job_media_sheets_completed}"; then
        set_print_verified "ipp_completed" "${stage_slug}:${job_id}"
        return 0
      fi
    fi

    completed_block="$(extract_lp_job_block "${queue_id}" "completed" || true)"
    if [[ -n "${completed_block}" ]] && lp_job_has_hard_error "${completed_block}"; then
      status_summary="$(lp_job_status_summary "${completed_block}")"
      set_print_failure_meta "${stage_label}" "completed_with_error" "true"
      echo "completed_with_error (${stage_label}, job=${queue_id}, ${status_summary})"
      return 1
    fi

    # Fallback for environments without IPP support: only accept success when the completed
    # job is still visible in CUPS history. This avoids false positives when a job disappears
    # from the active queue before CUPS has finalized its terminal state.
    if [[ -n "${completed_block}" && -z "${ipp_assignments}" ]]; then
      set_print_verified "cups_completed_history" "${stage_slug}:${job_id}"
      return 0
    fi

    sleep 2
  done

  if log_summary="$(lp_job_error_log_summary "${job_id}")"; then
    set_print_failure_meta "${stage_label}" "spool_error_log_timeout" "true"
    echo "spool_error_log_timeout (${stage_label}, job=${queue_id}, ${log_summary})"
    return 1
  fi

  job_block="$(extract_lp_job_block "${queue_id}" "all" || true)"
  if [[ -n "${job_block}" ]] && lp_job_has_hard_error "${job_block}"; then
    status_summary="$(lp_job_status_summary "${job_block}")"
    set_print_failure_meta "${stage_label}" "spool_error_timeout" "true"
    echo "spool_error_timeout (${stage_label}, job=${queue_id}, ${status_summary})"
    return 1
  fi

  ipp_assignments="$(ipp_job_attributes "${job_id}" || true)"
  if [[ -n "${ipp_assignments}" ]]; then
    ipp_job_state=""
    ipp_job_state_reasons=""
    ipp_job_printer_state_message=""
    ipp_job_impressions_completed=""
    ipp_job_media_sheets_completed=""
    eval "${ipp_assignments}"

    if ipp_job_has_hard_error "${ipp_job_state}" "${ipp_job_printer_state_message}" "${ipp_job_state_reasons}"; then
      set_print_failure_meta "${stage_label}" "ipp_error_timeout" "true"
      echo "ipp_error_timeout (${stage_label}, job=${queue_id}, state=${ipp_job_state:-unknown}, reasons=${ipp_job_state_reasons:-unknown}, message=${ipp_job_printer_state_message:-unknown})"
      return 1
    fi

    if ipp_job_is_verified_success "${ipp_job_state}" "${ipp_job_printer_state_message}" "${ipp_job_impressions_completed}" "${ipp_job_media_sheets_completed}"; then
      set_print_verified "ipp_completed" "${stage_slug}:${job_id}"
      return 0
    fi
  fi

  completed_block="$(extract_lp_job_block "${queue_id}" "completed" || true)"
  if [[ -n "${completed_block}" && -z "${ipp_assignments}" ]]; then
    set_print_verified "cups_completed_history" "${stage_slug}:${job_id}"
    return 0
  fi

  set_print_failure_meta "${stage_label}" "spool_timeout" "true"
  echo "spool_timeout (${stage_label}, job=${queue_id})"
  return 1
}

LP_MEDIA_RESOLVED="$(resolve_lp_media "$LP_MEDIA")"
if [[ -z "$LP_MEDIA_RESOLVED" ]]; then
  LP_MEDIA_RESOLVED="Custom.${LABEL_WIDTH_MM}x${LABEL_HEIGHT_MM}mm"
fi
echo "Resolved media: requested='${LP_MEDIA}' -> using='${LP_MEDIA_RESOLVED}'"

if queue_preflight_err="$(printer_queue_hard_error_summary)"; then
  finish_job "${job_key}" "${claim_id}" "false" "Printer queue not healthy: ${queue_preflight_err}"
  exit 1
fi

# Optional legacy mode: print source PDFs separately when URLs are present.
if [[ "${LP_FORCE_MERGED_JOB}" != "true" && -n "${packing_url:-}" && -n "${label_url:-}" ]]; then
  PRINT_META_CURRENT_MODE="direct"
  packing_path="${TMP_DIR}/${safe_job_key}-packing.pdf"
  packing_png_path="${TMP_DIR}/${safe_job_key}-packing.png"
  packing_print_path="${packing_path}"
  label_path="${TMP_DIR}/${safe_job_key}-label.pdf"
  echo "Claimed job: ${job_key} (order ${order_id}), downloading packing slip + shipping label..."
  if ! download_pdf "${packing_url}" "${packing_path}" "Packing slip"; then
    finish_job "${job_key}" "${claim_id}" "false" "Failed to download packing slip PDF."
    exit 1
  fi
  if ! download_pdf "${label_url}" "${label_path}" "Shipping label"; then
    echo "Direct label download failed, falling back to merged document mode..."
    rm -f "${packing_path}" "${packing_png_path}" "${label_path}" || true
    # Continue to merged fallback below.
  else
    if rasterize_label_pdf "${packing_path}" "${packing_png_path}"; then
      packing_print_path="${packing_png_path}"
      echo "Rasterized packing slip to PNG for Zebra compatibility."
    else
      echo "Packing slip rasterization failed; using original PDF."
    fi

    label_print_path="${label_path}"
    label_png_path="${TMP_DIR}/${safe_job_key}-label.png"
    label_raster_enabled="false"
    if [[ "${LP_RASTERIZE_LABEL}" == "1" || "${LP_RASTERIZE_LABEL}" == "true" || "${LP_RASTERIZE_LABEL}" == "yes" ]]; then
      label_raster_enabled="true"
    fi
    if [[ "${label_raster_enabled}" == "true" ]]; then
      if rasterize_label_pdf "${label_path}" "${label_png_path}"; then
        label_print_path="${label_png_path}"
        echo "Rasterized shipping label to PNG for stable sizing."
      else
        echo "Shipping label rasterization failed; using original PDF."
      fi
    fi

    echo "Downloaded direct PDFs, printing packing slip first..."
    packing_lp_options="${LP_EXTRA_OPTIONS}"
    if [[ "${packing_print_path}" == *.png ]]; then
      packing_lp_options="${LP_IMAGE_OPTIONS}"
    fi

    if ! lp_out_1="$(run_lp "${packing_print_path}" "" "${packing_lp_options}")"; then
      lp_exit=$?
      if [[ "${lp_exit}" -eq 142 || "${lp_exit}" -eq 124 ]]; then
        finish_job "${job_key}" "${claim_id}" "false" "lp timeout after ${LP_TIMEOUT_SECONDS}s (packing slip)"
      else
        finish_job "${job_key}" "${claim_id}" "false" "lp failed (code ${lp_exit}) packing slip: ${lp_out_1}"
      fi
      rm -f "${packing_path}" "${packing_png_path}" "${label_path}" "${label_png_path}" || true
      exit 1
    fi
    if ! verify_err="$(verify_lp_submission "${lp_out_1}" "packing slip")"; then
      finish_job "${job_key}" "${claim_id}" "false" "${verify_err}"
      rm -f "${packing_path}" "${packing_png_path}" "${label_path}" "${label_png_path}" || true
      exit 1
    fi
    sleep 1

    echo "Printing shipping label..."
    label_lp_options="${LP_EXTRA_OPTIONS}"
    if [[ "${label_print_path}" == *.png ]]; then
      label_lp_options="${LP_IMAGE_OPTIONS}"
    fi
    if ! lp_out_2="$(run_lp "${label_print_path}" "" "${label_lp_options}")"; then
      lp_exit=$?
      if [[ "${lp_exit}" -eq 142 || "${lp_exit}" -eq 124 ]]; then
        finish_job "${job_key}" "${claim_id}" "false" "lp timeout after ${LP_TIMEOUT_SECONDS}s (shipping label)"
      else
        finish_job "${job_key}" "${claim_id}" "false" "lp failed (code ${lp_exit}) shipping label: ${lp_out_2}"
      fi
      rm -f "${packing_path}" "${packing_png_path}" "${label_path}" "${label_png_path}" || true
      exit 1
    fi
    if ! verify_err="$(verify_lp_submission "${lp_out_2}" "shipping label")"; then
      finish_job "${job_key}" "${claim_id}" "false" "${verify_err}"
      rm -f "${packing_path}" "${packing_png_path}" "${label_path}" "${label_png_path}" || true
      exit 1
    fi

    finish_job "${job_key}" "${claim_id}" "true" ""
    rm -f "${packing_path}" "${packing_png_path}" "${label_path}" "${label_png_path}" || true
    echo "Printed direct PDFs: ${job_key} (packing: ${lp_out_1}; label: ${lp_out_2})"
    exit 0
  fi
fi

local_path="${TMP_DIR}/${document_filename}"
PRINT_META_CURRENT_MODE="merged"
echo "Claimed job: ${job_key} (order ${order_id}), downloading merged document..."
if ! download_pdf "${document_url}" "${local_path}" "Merged document"; then
  finish_job "${job_key}" "${claim_id}" "false" "Failed to download merged document."
  exit 1
fi

echo "Downloaded merged document: ${local_path}, sending to printer ${PRINTER_NAME}..."
pages="$(detect_pdf_pages "${local_path}")"
split_enabled="false"
if [[ "${LP_SPLIT_PAGES}" == "1" || "${LP_SPLIT_PAGES}" == "true" || "${LP_SPLIT_PAGES}" == "yes" ]]; then
  split_enabled="true"
fi
if [[ "${LP_FORCE_MERGED_JOB}" == "true" ]]; then
  echo "Single-job mode enabled; printing merged document as one CUPS job."
fi
if [[ "${split_enabled}" == "true" && "${pages}" == "0" ]]; then
  pages="2"
  echo "Page detection returned 0; forcing split print for pages 1 and 2."
fi

if [[ "${split_enabled}" == "true" && "${pages}" =~ ^[0-9]+$ && "${pages}" -ge 2 ]]; then
  PRINT_META_CURRENT_MODE="split"
  if ! lp_out_1="$(run_lp "${local_path}" "1")"; then
    lp_exit=$?
    if [[ "${lp_exit}" -eq 142 || "${lp_exit}" -eq 124 ]]; then
      finish_job "${job_key}" "${claim_id}" "false" "lp timeout after ${LP_TIMEOUT_SECONDS}s (page 1)"
    else
      finish_job "${job_key}" "${claim_id}" "false" "lp failed (code ${lp_exit}) page 1: ${lp_out_1}"
    fi
    exit 1
  fi
  if ! verify_err="$(verify_lp_submission "${lp_out_1}" "page 1")"; then
    finish_job "${job_key}" "${claim_id}" "false" "${verify_err}"
    exit 1
  fi
  sleep 1
  if ! lp_out_2="$(run_lp "${local_path}" "2")"; then
    lp_exit=$?
    if [[ "${lp_exit}" -eq 142 || "${lp_exit}" -eq 124 ]]; then
      finish_job "${job_key}" "${claim_id}" "false" "lp timeout after ${LP_TIMEOUT_SECONDS}s (page 2)"
    else
      finish_job "${job_key}" "${claim_id}" "false" "lp failed (code ${lp_exit}) page 2: ${lp_out_2}"
    fi
    exit 1
  fi
  if ! verify_err="$(verify_lp_submission "${lp_out_2}" "page 2")"; then
    finish_job "${job_key}" "${claim_id}" "false" "${verify_err}"
    exit 1
  fi
  finish_job "${job_key}" "${claim_id}" "true" ""
  rm -f "${local_path}" || true
  echo "Printed split pages: ${job_key} (p1: ${lp_out_1}; p2: ${lp_out_2})"
  exit 0
fi

if lp_out="$(run_lp "${local_path}")"; then
  if ! verify_err="$(verify_lp_submission "${lp_out}" "merged document")"; then
    finish_job "${job_key}" "${claim_id}" "false" "${verify_err}"
    exit 1
  fi
  finish_job "${job_key}" "${claim_id}" "true" ""
  rm -f "${local_path}" || true
  echo "Printed: ${job_key} (${lp_out})"
  exit 0
fi

lp_exit=$?
if [[ "${lp_exit}" -eq 142 || "${lp_exit}" -eq 124 ]]; then
  finish_job "${job_key}" "${claim_id}" "false" "lp timeout after ${LP_TIMEOUT_SECONDS}s"
else
  finish_job "${job_key}" "${claim_id}" "false" "lp failed (code ${lp_exit}): ${lp_out}"
fi
exit 1
