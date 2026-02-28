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
#   LP_MEDIA defaults to "Print label"
#   LP_EXTRA_OPTIONS comma-separated (defaults set for top-aligned label print)
#   LP_IMAGE_OPTIONS comma-separated (defaults set for raster/image print)
#   LP_SPLIT_PAGES defaults to true (print page 1 and 2 as separate jobs)
#   LP_RASTER_DPI defaults to 300
#   LABEL_WIDTH_MM defaults to 102.7
#   LABEL_HEIGHT_MM defaults to 190
#   LP_RASTERIZE_LABEL defaults to true
#   LP_VERIFY_SECONDS defaults to 45 (wait for CUPS queue acceptance/completion signal)
#   Note: when claim payload includes `packing_url` + `label_url`, agent prints them as two
#         independent print jobs (packing first, then label) to avoid multi-page PDF quirks.
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
LP_MEDIA="${LP_MEDIA:-Print label}"
# Force 1:1 print by default (no fit-to-page shrink). Keep top-left with zero margins.
LP_EXTRA_OPTIONS="${LP_EXTRA_OPTIONS:-print-scaling=none,position=top-left,scaling=100,number-up=1,sides=one-sided,page-top=0,page-bottom=0,page-left=0,page-right=0}"
# For rasterized images, use fit-to-page so CUPS/driver DPI assumptions do not shrink label width.
LP_IMAGE_OPTIONS="${LP_IMAGE_OPTIONS:-fit-to-page,position=top-left,number-up=1,sides=one-sided,page-top=0,page-bottom=0,page-left=0,page-right=0}"
LP_SPLIT_PAGES="${LP_SPLIT_PAGES:-true}"
LP_RASTER_DPI="${LP_RASTER_DPI:-300}"
LABEL_WIDTH_MM="${LABEL_WIDTH_MM:-102.7}"
LABEL_HEIGHT_MM="${LABEL_HEIGHT_MM:-190}"
LP_RASTERIZE_LABEL="${LP_RASTERIZE_LABEL:-true}"
LP_VERIFY_SECONDS="${LP_VERIFY_SECONDS:-45}"
LP_MEDIA_RESOLVED=""

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

finish_job() {
  local job_key="$1"
  local claim_id="$2"
  local success="$3"
  local error_message="${4:-}"
  local success_marker="__BOOL_FALSE__"
  if [[ "${success}" == "true" ]]; then
    success_marker="__BOOL_TRUE__"
  fi

  local payload
  payload="$(build_json "job_key=${job_key}" "claim_id=${claim_id}" "success=${success_marker}" "error=${error_message}")"

  curl -sS --connect-timeout 10 --max-time "${CURL_TIMEOUT_SECONDS}" -X POST "${FINISH_URL}" -H "X-NP-Print-Token: ${PRINT_TOKEN}" -H "Content-Type: application/json" --data "${payload}" >/dev/null || true
}

claim_payload="$(build_json "agent=${AGENT_NAME}")"
claim_tmp="$(/usr/bin/mktemp "${TMP_DIR}/claim.XXXXXX")"

curl -sS --connect-timeout 10 --max-time "${CURL_TIMEOUT_SECONDS}" -X POST "${CLAIM_URL}" -H "X-NP-Print-Token: ${PRINT_TOKEN}" -H "Content-Type: application/json" --data "${claim_payload}" -o "${claim_tmp}"

claim_data="$(/usr/bin/python3 - "${claim_tmp}" <<'PY'
import json
import sys

path = sys.argv[1]
try:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
except Exception:
    data = {}

status = str(data.get("status", ""))
error = str(data.get("error", ""))
job = data.get("job") if isinstance(data.get("job"), dict) else {}

parts = [
    status,
    error,
    str(job.get("job_key", "")),
    str(job.get("claim_id", "")),
    str(job.get("document_url", "")),
    str(job.get("document_filename", "")),
    str(job.get("order_id", "")),
    str(job.get("packing_url", "")),
    str(job.get("label_url", "")),
]
print("\t".join(p.replace("\t", " ").replace("\n", " ") for p in parts))
PY
)"

rm -f "${claim_tmp}"

IFS=$'\t' read -r status claim_error job_key claim_id document_url document_filename order_id packing_url label_url <<<"${claim_data}"

if [[ "${status}" != "claimed" ]]; then
  if [[ "${status}" != "empty" ]]; then
    echo "Claim failed: status='${status}' error='${claim_error}'" >&2
    exit 1
  fi
  exit 0
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
  local _name="$3"
  if [[ -z "${source_url}" ]]; then
    return 1
  fi
  if ! curl -fL -sS --connect-timeout 10 --max-time "${CURL_TIMEOUT_SECONDS}" "${source_url}" -o "${target_path}"; then
    return 1
  fi
  [[ -f "${target_path}" ]]
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
    return 0
  fi

  local queue_id="${PRINTER_NAME}-${job_id}"
  local end_ts
  end_ts=$(( $(date +%s) + LP_VERIFY_SECONDS ))

  while [[ $(date +%s) -le ${end_ts} ]]; do
    # If printer queue is disabled, treat as print failure.
    if lpstat -p "${PRINTER_NAME}" 2>/dev/null | grep -qi 'disabled'; then
      echo "printer_disabled (${stage_label})"
      return 1
    fi

    # Job still queued: keep waiting.
    if lpstat -W not-completed -o "${PRINTER_NAME}" 2>/dev/null | grep -q "${queue_id}"; then
      sleep 2
      continue
    fi

    # Job left queue; consider this successful handoff to printer.
    return 0
  done

  echo "spool_timeout (${stage_label}, job=${queue_id})"
  return 1
}

LP_MEDIA_RESOLVED="$(resolve_lp_media "$LP_MEDIA")"
if [[ -z "$LP_MEDIA_RESOLVED" ]]; then
  LP_MEDIA_RESOLVED="Custom.${LABEL_WIDTH_MM}x${LABEL_HEIGHT_MM}mm"
fi
echo "Resolved media: requested='${LP_MEDIA}' -> using='${LP_MEDIA_RESOLVED}'"

# Preferred mode: print source PDFs separately when URLs are present.
if [[ -n "${packing_url:-}" && -n "${label_url:-}" ]]; then
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
if [[ "${split_enabled}" == "true" && "${pages}" == "0" ]]; then
  pages="2"
  echo "Page detection returned 0; forcing split print for pages 1 and 2."
fi

if [[ "${split_enabled}" == "true" && "${pages}" =~ ^[0-9]+$ && "${pages}" -ge 2 ]]; then
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
