#!/bin/bash
# run_bench.sh
# Orchestrates all four benchmark conditions (A, B, C, D).
# Must be run as root.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
DURATION=60
CGROUP_DEPTH="${CGROUP_DEPTH:-}"          # empty = auto-detect from /sys/fs/cgroup/cgroup.max.depth
SCX_LAVD="${SCX_LAVD_BIN:-/usr/bin/scx_lavd}"
SCX_LAVD_OPTS_C="${SCX_LAVD_OPTS_C:---performance --slice-min-us 3000 --slice-max-us 10000 --pinned-slice-us 3000}"
SCX_LAVD_OPTS="${SCX_LAVD_OPTS:---performance --slice-min-us 3000 --slice-max-us 10000 --pinned-slice-us 3000 --enable-cpu-bw}"
SCX_LAVD_PID=""
SCX_LAVD_CURRENT_OPTS=""

# Worker count: defaults to 2x nproc (fully overloaded — hits quota each period).
# Set to nproc/2 for underloaded (quota never hit, measures accounting-only overhead).
NCPUS="$(nproc)"
NWORKERS="${NWORKERS:-$(( NCPUS * 2 ))}"

# Compute human-readable label (e.g. "2x", "0.5x") from NWORKERS/NCPUS ratio.
_tenths=$(( NWORKERS * 10 / NCPUS ))
if (( _tenths % 10 == 0 )); then
    NWORKERS_LABEL="$(( _tenths / 10 ))x"
else
    NWORKERS_LABEL="$(( _tenths / 10 )).$(( _tenths % 10 ))x"
fi

RESULTS_DIR="$SCRIPT_DIR/results/${NWORKERS_LABEL}"

log() { printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }

require_root() {
    [[ $EUID -eq 0 ]] || { echo "Run as root."; exit 1; }
}

require_tools() {
    for t in perf stress-ng; do
        command -v "$t" &>/dev/null || { echo "Missing tool: $t"; exit 1; }
    done
    [[ -x "$SCX_LAVD" ]] || { echo "scx_lavd not found at $SCX_LAVD (set SCX_LAVD_BIN)"; exit 1; }
}

# Check if a sched_ext scheduler is currently active.
scx_is_active() {
    [[ "$(cat /sys/kernel/sched_ext/state 2>/dev/null)" == "enabled" ]]
}

# Ensure EEVDF is the active scheduler. Stops scx_lavd if running.
ensure_eevdf() {
    if [[ -n "$SCX_LAVD_PID" ]]; then
        log "Stopping scx_lavd (PID $SCX_LAVD_PID)..."
        kill "$SCX_LAVD_PID" 2>/dev/null || true
        wait "$SCX_LAVD_PID" 2>/dev/null || true
        SCX_LAVD_PID=""
    fi
    if scx_is_active; then
        log "scx scheduler still active; killing stray scx_lavd..."
        pkill -x scx_lavd 2>/dev/null || true
        local i
        for i in $(seq 10); do
            scx_is_active || break
            sleep 1
        done
        if scx_is_active; then
            log "ERROR: could not deactivate scx scheduler"
            exit 1
        fi
    fi
    sleep 1  # let kernel settle back to EEVDF
    log "EEVDF is active."
}

# Ensure scx_lavd is running with the given opts. Restarts if not active or opts differ.
ensure_scx_lavd() {
    local opts="$1"
    if scx_is_active && [[ -n "$SCX_LAVD_PID" ]] && [[ "$opts" == "$SCX_LAVD_CURRENT_OPTS" ]]; then
        log "scx_lavd already running (PID $SCX_LAVD_PID)."
        return
    fi
    # Stop any running instance before (re)starting with new opts.
    ensure_eevdf
    log "Starting scx_lavd $opts ..."
    # shellcheck disable=SC2086
    "$SCX_LAVD" $opts &
    SCX_LAVD_PID=$!
    SCX_LAVD_CURRENT_OPTS="$opts"
    local i
    for i in $(seq 10); do
        scx_is_active && break
        sleep 1
    done
    if ! scx_is_active; then
        log "ERROR: scx_lavd failed to become active"
        exit 1
    fi
    log "scx_lavd running (PID $SCX_LAVD_PID)."
}

run_condition() {
    local cond="$1"      # A B C D
    local scheduler="$2" # eevdf scx_lavd
    local cpumax="$3"    # on off
    local out="$RESULTS_DIR/$cond"
    mkdir -p "$out"

    log "=== Condition $cond: scheduler=$scheduler cpu.max=$cpumax nworkers=$NWORKERS ==="

    # Setup cgroup hierarchy
    "$SCRIPT_DIR/setup_cgroup.sh" "$cpumax" ${CGROUP_DEPTH:+"$CGROUP_DEPTH"}

    # perf stat run (no background hooks — keeps measurement clean)
    log "Running perf stat (${DURATION}s)..."
    "$SCRIPT_DIR/perf/stat.sh" "$out" "$DURATION" "$NWORKERS"

    # Teardown cgroup hierarchy
    "$SCRIPT_DIR/teardown_cgroup.sh"
    log "Condition $cond complete. Results in $out/"
    sleep 5
}

require_root
require_tools

log "Worker configuration: NWORKERS=$NWORKERS (${NWORKERS_LABEL}), NCPUS=$NCPUS"
log "Results directory: $RESULTS_DIR"

mkdir -p "$RESULTS_DIR"/{A,B,C,D}
printf "ncpus %d\nduration_s %d\nnworkers %d\nnworkers_label %s\n" \
    "$NCPUS" "$DURATION" "$NWORKERS" "$NWORKERS_LABEL" > "$RESULTS_DIR/bench_params.txt"

# Condition A: EEVDF baseline (no cpu.max)
ensure_eevdf
run_condition A eevdf off

# Condition B: EEVDF + cpu.max
ensure_eevdf
run_condition B eevdf on

# Condition C: scx_lavd baseline (no cpu.max, no cgroup_bw)
ensure_scx_lavd "$SCX_LAVD_OPTS_C"
run_condition C scx_lavd off

# Condition D: scx_lavd + cpu.max (cgroup_bw enabled)
ensure_scx_lavd "$SCX_LAVD_OPTS"
run_condition D scx_lavd on

ensure_eevdf

log "All conditions complete. Generating report..."
"$SCRIPT_DIR/results/report.sh" "$RESULTS_DIR"
