#!/usr/bin/env bash
# run_capture.sh — parallel tshark captures + OVS snapshots + run_meta.json (paper-grade)
#
# Usage:
#   sudo ./run_capture.sh <condition> <run_number> <duration_seconds>
# Example:
#   sudo ./run_capture.sh baseline 3 120
#
# Optional environment variables (for metadata):
#   ATTACK_TYPE="baseline|defense|fdi|dos|combined"     (default: <condition>)
#   ATTACKER_PLACEMENT="ATTACKER@DPSRS:5"              (default: empty)
#   RULESET_FILE="/home/sgsim/SmartGridSim/SGSIM_EXPERIMENTS/rules/zt_all_rules.sh"                 (sha256 recorded if file exists)
#   DEVIATIONS="warm-up restarted once"                (default: empty)
#   SIM_REPO_DIR="/path/to/sgsim/git/repo"             (git commit recorded if available)
#   IFACES_CSV="DPSRS-eth4,DPSRS-eth2,DPSRS-eth5,DPSRS-eth1,DPSHV-eth3" (override capture IF list)
#   DEST_ROOT="/home/sgsim/SGSIM_EXPERIMENTS/runs"   (override destination)
#   ALLOW_OVERWRITE="1"                                (allow overwriting existing run folder)

set -euo pipefail

COND="${1:-}"
RUNNO="${2:-}"
DUR="${3:-}"

if [[ -z "$COND" || -z "$RUNNO" || -z "$DUR" ]]; then
  echo "Usage: sudo $0 <condition> <run_number> <duration_seconds>"
  exit 1
fi

if ! [[ "$RUNNO" =~ ^[0-9]+$ ]]; then
  echo "ERROR: run_number must be an integer (got: $RUNNO)"
  exit 1
fi

if ! [[ "$DUR" =~ ^[0-9]+$ ]]; then
  echo "ERROR: duration_seconds must be an integer (got: $DUR)"
  exit 1
fi

# Pairable base ID + timestamp (timestamp stored in metadata, not embedded in base id)
RUNNO_PAD="$(printf "%03d" "$RUNNO")"
RUN_ID_BASE="${COND}_${RUNNO_PAD}"
TS_ISO="$(date -Iseconds)"
TS_TAG="$(date +%Y%m%d_%H%M%S)"

# Folder name: keep it pairable. Refuse overwrites unless explicitly allowed.
ROOT_TMP="/root/SGSIM_EXPERIMENTS_TMP"
OUTDIR="${ROOT_TMP}/${RUN_ID_BASE}"
PCAPDIR="${OUTDIR}/pcaps"
OVSDIR="${OUTDIR}/ovs"
LOGDIR="${OUTDIR}/logs"

if [[ -d "$OUTDIR" && "${ALLOW_OVERWRITE:-0}" != "1" ]]; then
  echo "ERROR: ${OUTDIR} already exists."
  echo "Choose another run_number or delete the folder, or set ALLOW_OVERWRITE=1."
  exit 1
fi

mkdir -p "$PCAPDIR" "$OVSDIR" "$LOGDIR"

echo "Temp run folder (root): $OUTDIR"
echo "Condition: $COND"
echo "Run number: $RUNNO_PAD"
echo "Duration: ${DUR}s"
echo "Timestamp: ${TS_ISO}"

# Optional metadata inputs
ATTACK_TYPE="${ATTACK_TYPE:-$COND}"
ATTACKER_PLACEMENT="${ATTACKER_PLACEMENT:-}"
RULESET_FILE="${RULESET_FILE:-}"
DEVIATIONS="${DEVIATIONS:-}"
SIM_REPO_DIR="${SIM_REPO_DIR:-.}"

# Tools sanity
for cmd in ovs-ofctl ovs-vsctl tshark sha256sum; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR: missing command: $cmd"; exit 1; }
done

# Interface list 
IFACES_DEFAULT=("DPSRS-eth4" "DPSRS-eth2" "DPSRS-eth5" "DPSRS-eth1" "DPSHV-eth3")

IFACES=()
if [[ -n "${IFACES_CSV:-}" ]]; then
  IFS=',' read -r -a IFACES <<< "${IFACES_CSV}"
else
  IFACES=("${IFACES_DEFAULT[@]}")
fi

# Host/version snapshot (debug + paper appendix)
{
  echo "timestamp_iso=${TS_ISO}"
  echo "uname=$(uname -a)"
  echo "tshark=$((tshark -v 2>/dev/null || true) | head -n 1)"
  echo "ovs-vsctl=$((ovs-vsctl --version 2>/dev/null || true) | head -n 1)"
  echo "ovs-ofctl=$((ovs-ofctl -V 2>/dev/null || true) | head -n 1)"
  command -v lscpu >/dev/null 2>&1 && lscpu || true
  command -v free  >/dev/null 2>&1 && free -h || true
} > "${LOGDIR}/host_versions.txt"

# Git commit (best effort)
SIM_GIT_COMMIT=""
if command -v git >/dev/null 2>&1 && git -C "$SIM_REPO_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  SIM_GIT_COMMIT="$(git -C "$SIM_REPO_DIR" rev-parse HEAD 2>/dev/null || true)"
fi

# Ruleset checksum (best effort)
RULESET_SHA256=""
RULESET_BASENAME=""

if [[ -n "$RULESET_FILE" && -f "$RULESET_FILE" ]]; then
  RULESET_SHA256="$(sha256sum "$RULESET_FILE" | awk '{print $1}')"
  RULESET_BASENAME="$(basename "$RULESET_FILE")"
fi

# -----------------------------
# OVS snapshots (PRE)
# -----------------------------
SWS=("DPSRS" "DPSGW" "DPSHV" "DPSMV" "CONTROLSW")

echo "Taking OVS snapshots (PRE)..."
for SW in "${SWS[@]}"; do
  if ovs-vsctl br-exists "$SW" >/dev/null 2>&1; then
    ovs-ofctl -O OpenFlow13 dump-ports-desc "$SW" > "${OVSDIR}/${SW}_ports_desc_pre.txt" || true
    ovs-ofctl -O OpenFlow13 dump-ports      "$SW" > "${OVSDIR}/${SW}_ports_pre.txt"      || true
    ovs-ofctl -O OpenFlow13 dump-flows    "$SW" > "${OVSDIR}/${SW}_flows_pre.txt"      || true
  else
    echo "WARN: bridge not found: $SW" | tee -a "${LOGDIR}/warnings.txt"
  fi
done

{
  echo "== ovs-vsctl show (pre) =="
  ovs-vsctl show || true
  echo
  echo "== controller/fail-mode (pre) =="
  for SW in "${SWS[@]}"; do
    if ovs-vsctl br-exists "$SW" >/dev/null 2>&1; then
      echo "-- ${SW}"
      echo -n "controller: " ; ovs-vsctl get-controller "$SW" 2>/dev/null || true
      echo -n "fail-mode:  " ; ovs-vsctl get-fail-mode  "$SW" 2>/dev/null || true
      echo
    fi
  done
} > "${OVSDIR}/ovs_state_pre.txt"

# -----------------------------
# run_meta.json (write early)
# -----------------------------

# Build JSON array for interfaces 
IFACES_JSON=""
for i in "${!IFACES[@]}"; do
  IFACES_JSON+="\"${IFACES[$i]}\""
  [[ $i -lt $((${#IFACES[@]} - 1)) ]] && IFACES_JSON+=","
done


# Minimal JSON writer (no extra deps)
cat > "${OUTDIR}/run_meta.json" <<EOF
{
  "run_id": "${RUN_ID_BASE}",
  "timestamp_iso": "${TS_ISO}",
  "simulator_git_commit": "${SIM_GIT_COMMIT}",
  "attack_type": "${ATTACK_TYPE}",
  "attacker_placement": "${ATTACKER_PLACEMENT}",
  "ruleset_file": "${RULESET_BASENAME}",
  "ruleset_sha256": "${RULESET_SHA256}",
  "capture_duration_seconds": ${DUR},
  "interfaces": [${IFACES_JSON}],
  "openflow_version": "OpenFlow13",
  "known_deviations": "${DEVIATIONS}"
}
EOF

# -----------------------------
# Start captures in parallel (with per-interface logs)
# -----------------------------
echo "Starting parallel captures..."
PIDS=()

for IF in "${IFACES[@]}"; do
  PCAP_OUT="${PCAPDIR}/${RUN_ID_BASE}_${IF}.pcapng"
  LOG_OUT="${LOGDIR}/tshark_${IF}.log"
  echo "Capturing on ${IF} -> ${PCAP_OUT}"
  # -n disables name resolution; -q reduces noise
  tshark -n -q -i "${IF}" -a "duration:${DUR}" -w "${PCAP_OUT}" >"${LOG_OUT}" 2>&1 &
  PIDS+=("$!")
done

FAIL=0
for pid in "${PIDS[@]}"; do
  if ! wait "$pid"; then
    FAIL=1
  fi
done

if [[ "$FAIL" -ne 0 ]]; then
  echo "ERROR: One or more tshark captures failed. Check ${LOGDIR}/tshark_*.log"
  exit 1
fi

echo "Capture finished."

# -----------------------------
# OVS snapshots (POST) — counters after run help “drop localization”
# -----------------------------
echo "Taking OVS snapshots (POST)..."
for SW in "${SWS[@]}"; do
  if ovs-vsctl br-exists "$SW" >/dev/null 2>&1; then
    ovs-ofctl -O OpenFlow13 dump-ports-desc "$SW" > "${OVSDIR}/${SW}_ports_desc_post.txt" || true
    ovs-ofctl -O OpenFlow13 dump-ports      "$SW" > "${OVSDIR}/${SW}_ports_post.txt"      || true
    ovs-ofctl -O OpenFlow13 dump-flows      "$SW" > "${OVSDIR}/${SW}_flows_post.txt"      || true
  fi
done
ovs-vsctl show > "${OVSDIR}/ovs_vsctl_show_post.txt" 2>/dev/null || true

# -----------------------------
# Manifest checksums for all artifacts
# -----------------------------
echo "Writing manifest.sha256..."
(
  cd "$OUTDIR"
  find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
) > "${OUTDIR}/manifest.sha256" || true

# -----------------------------
# Copy to Desktop experiments folder and fix owner
# -----------------------------
DEST_ROOT="${DEST_ROOT:-/home/sgsim/SmartGridSim/SGSIM_EXPERIMENTS/runs}"
mkdir -p "$DEST_ROOT"

cp -a "$OUTDIR" "$DEST_ROOT/"
chown -R sgsim:sgsim "$DEST_ROOT/$(basename "$OUTDIR")"
rm -r "$ROOT_TMP"
echo "Copied to: $DEST_ROOT/$(basename "$OUTDIR")"
echo "Done."
