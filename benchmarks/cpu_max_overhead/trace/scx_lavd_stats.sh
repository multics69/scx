#!/bin/bash
# trace/scx_lavd_stats.sh
# Measures per-BPF-program execution stats for the four scx_lavd ops that
# call cgroup_bw APIs, using kernel.bpf_stats_enabled (same mechanism as
# bpftop by Netflix).
#
# How it works:
#   kernel.bpf_stats_enabled=1 makes the kernel accumulate run_time_ns and
#   run_cnt for every loaded BPF program. We snapshot those counters before
#   and after the measurement window, then compute:
#     avg_latency_ns = delta(run_time_ns) / delta(run_cnt)
#
# Run under both condition C (scx_lavd, cpu.max off) and D (cpu.max on).
# The latency difference isolates the cgroup_bw enforcement overhead.
#
# Usage: sudo ./trace/scx_lavd_stats.sh <duration_sec> [output_file]
set -euo pipefail

DURATION="${1:?Usage: scx_lavd_stats.sh <duration_sec> [output_file]}"
OUTPUT="${2:-}"

FUNCS=(lavd_enqueue lavd_dispatch lavd_tick lavd_stopping)

[[ $EUID -eq 0 ]] || { echo "Run as root."; exit 1; }
command -v bpftool &>/dev/null || { echo "Missing tool: bpftool"; exit 1; }
command -v jq      &>/dev/null || { echo "Missing tool: jq"; exit 1; }

# Enable BPF stats; restore original value on exit.
BPF_STATS_ORIG="$(sysctl -n kernel.bpf_stats_enabled)"
sysctl -qw kernel.bpf_stats_enabled=1
trap 'sysctl -qw kernel.bpf_stats_enabled="$BPF_STATS_ORIG"' EXIT

# Return "run_time_ns run_cnt" for the named BPF program.
get_stats() {
    local name="$1"
    bpftool prog show --json 2>/dev/null | \
        jq -r --arg n "$name" \
           '.[] | select(.name == $n) | "\(.run_time_ns) \(.run_cnt)"' | \
        head -1
}

# Verify all target programs are visible.
for func in "${FUNCS[@]}"; do
    if [[ -z "$(get_stats "$func")" ]]; then
        echo "ERROR: BPF program '$func' not found — is scx_lavd running?"
        exit 1
    fi
done

# Snapshot baseline.
declare -A snap_before
for func in "${FUNCS[@]}"; do
    snap_before[$func]="$(get_stats "$func")"
done

echo "Sampling scx_lavd BPF stats for ${DURATION}s..."
sleep "$DURATION"

# Snapshot final.
declare -A snap_after
for func in "${FUNCS[@]}"; do
    snap_after[$func]="$(get_stats "$func")"
done

# Print results.
{
    printf "\n%-20s %14s %16s %14s\n" \
        "Program" "calls" "total_time_ns" "avg_ns/call"
    printf '%s\n' "$(printf '─%.0s' {1..68})"
    for func in "${FUNCS[@]}"; do
        read -r t0 c0 <<< "${snap_before[$func]}"
        read -r t1 c1 <<< "${snap_after[$func]}"
        dc=$(( c1 - c0 ))
        dt=$(( t1 - t0 ))
        avg=$(( dc > 0 ? dt / dc : 0 ))
        printf "%-20s %14d %16d %14d\n" "$func" "$dc" "$dt" "$avg"
    done

    printf "\nNote: avg_ns/call includes all work in each op, not only\n"
    printf "cgroup_bw calls. Compare C vs D to isolate enforcement overhead.\n"
    printf "\nCgroup_bw call paths:\n"
    printf "  lavd_enqueue:  scx_cgroup_bw_throttled (direct)\n"
    printf "  lavd_dispatch: scx_cgroup_bw_throttled + scx_cgroup_bw_consume (via consume_prev)\n"
    printf "  lavd_tick:     scx_cgroup_bw_throttled + scx_cgroup_bw_consume (direct)\n"
    printf "  lavd_stopping: scx_cgroup_bw_consume (via update_stat_for_stopping)\n"
} | tee "${OUTPUT:-/dev/stdout}"
