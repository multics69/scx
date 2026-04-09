#!/bin/bash
# results/report.sh [results_dir]
# Reads {results_dir}/{A,B,C,D}/perf.stat.txt and prints a summary comparison table.
# results_dir defaults to the directory containing this script.
set -euo pipefail

RESULTS_DIR="$(cd "${1:-$(dirname "$0")}" && pwd)"

parse_perf_stat() {
    local file="$1"
    local cycles cycles_k
    cycles=$(grep -oP '[\d,]+(?=\s+cycles\b)' "$file" | tr -d ',' | head -1 || true)
    cycles_k=$(grep -oP '[\d,]+(?=\s+cycles:k)' "$file" | tr -d ',' | head -1 || true)
    echo "${cycles:-0} ${cycles_k:-0}"
}

parse_bogo_ops() {
    local file="$1"
    # stress-ng --metrics-brief table (written to stderr):
    #   metrc: [...] stressor   bogo ops  real time  usr time  sys time  bogo ops/s  bogo ops/s
    #   metrc: [...]                        (secs)     (secs)    (secs)  (real time) (usr+sys time)
    #   metrc: [...] cpu          10570      3.00       5.98      0.00     3523.31       1765.64
    # Last column is bogo ops/s (usr+sys time).
    grep 'metrc:' "$file" 2>/dev/null \
        | grep -v 'stressor\|(secs)' \
        | awk '/\bcpu\b/{print $NF}' \
        | head -1 || true
}

_ncpus="$(awk '/^ncpus/{print $2}' "$RESULTS_DIR/bench_params.txt" 2>/dev/null || nproc)"
_nworkers="$(awk '/^nworkers /{print $2}' "$RESULTS_DIR/bench_params.txt" 2>/dev/null || echo '?')"
_label="$(awk '/^nworkers_label/{print $2}' "$RESULTS_DIR/bench_params.txt" 2>/dev/null || echo '?')"

printf "\n=== cpu.max Enforcement Overhead: EEVDF vs. scx_lavd ===\n"
printf "ncpus=%s  nworkers=%s (%s)  results=%s\n\n" \
    "$_ncpus" "$_nworkers" "$_label" "$RESULTS_DIR"

# cpu_equiv = (cycles:k / cycles) * nproc
# Fraction of all CPU cycles spent in kernel mode, scaled to number of CPUs.
# Uses measured all-mode cycles as denominator — no assumed clock frequency,
# no sensitivity to turbo boost or frequency scaling.

cpu_equiv() {
    local cycles_k="$1" cycles_all="$2"
    awk "BEGIN { printf \"%.3f\", ($cycles_k / $cycles_all) * $_ncpus }"
}

printf "%-5s %-10s %-8s %-18s %-18s %-14s %-16s\n" \
    "Cond" "Scheduler" "cpu.max" "cycles (all)" "cycles:k" "cpu_equiv (k)" "bogo ops/s"
printf '%s\n' "$(printf '─%.0s' {1..95})"

for cond in A B C D; do
    statfile="$RESULTS_DIR/$cond/perf.stat.txt"
    if [[ ! -f "$statfile" ]]; then
        printf "%-5s  (no data)\n" "$cond"
        continue
    fi
    read -r _cy _cyk <<< "$(parse_perf_stat "$statfile")"
    case $cond in
        A) sched="EEVDF";    cpumax="off" ;;
        B) sched="EEVDF";    cpumax="on"  ;;
        C) sched="scx_lavd"; cpumax="off" ;;
        D) sched="scx_lavd"; cpumax="on"  ;;
    esac
    _equiv_k="$(cpu_equiv "$_cyk" "$_cy")"
    _bogo="$(parse_bogo_ops "$RESULTS_DIR/$cond/stress_ng.txt" 2>/dev/null || true)"
    printf "%-5s %-10s %-8s %-18s %-18s %-14s %-16s\n" \
        "$cond" "$sched" "$cpumax" "$_cy" "$_cyk" "$_equiv_k" "${_bogo:-(n/a)}"
done

printf '\n=== cpu.max Enforcement Cost ===\n'
printf 'Extra kernel-mode CPU-equivalents when cpu.max is on vs off.\n'
printf 'cpu_equiv(k) = (cycles:k / cycles) * nproc — frequency-independent.\n'
printf 'Captures all enforcement paths: accounting, throttle, unthrottle, timer callbacks.\n\n'

for pair in "EEVDF:B:A" "scx_lavd:D:C"; do
    IFS=: read -r _name _on _off <<< "$pair"
    _f_on="$RESULTS_DIR/$_on/perf.stat.txt"
    _f_off="$RESULTS_DIR/$_off/perf.stat.txt"
    if [[ -f "$_f_on" && -f "$_f_off" ]]; then
        read -r _cy_on  _cyk_on  <<< "$(parse_perf_stat "$_f_on")"
        read -r _cy_off _cyk_off <<< "$(parse_perf_stat "$_f_off")"
        _equiv_on="$(cpu_equiv  "$_cyk_on"  "$_cy_on")"
        _equiv_off="$(cpu_equiv "$_cyk_off" "$_cy_off")"
        _delta="$(awk "BEGIN { printf \"%.3f\", $_equiv_on - $_equiv_off }")"
        printf "%s: +%s CPU-equiv enforcing cpu.max\n" "$_name" "$_delta"
        printf "    kernel cpu_equiv: %s (on) - %s (off) = %s\n" \
            "$_equiv_on" "$_equiv_off" "$_delta"
    fi
done

printf "\nNote: cycles:k includes all enforcement paths — per-tick accounting,\n"
printf "throttle/unthrottle calls, and periodic timer callbacks.\n"
