# cpu.max Enforcement Overhead Benchmark Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement the benchmark scripts described in `docs/plans/2026-04-10-cpu-max-overhead-measurement-design.md` — a shell + bpftrace + perf benchmark comparing cpu.max enforcement overhead between EEVDF and scx_lavd at cgroup depth=20 on a 192-CPU machine.

**Architecture:** A shell orchestrator (`run_bench.sh`) drives four conditions (A–D) in sequence, calling modular helper scripts for cgroup setup, perf stat, perf record, and bpftrace. Results land in per-condition directories under `results/`. A final `report.sh` parses raw outputs into a summary table.

**Tech Stack:** bash, bpftrace (kprobe/kretprobe + fentry/fexit), perf (stat + record), stress-ng, FlameGraph tools (stackcollapse-perf.pl + flamegraph.pl), scx_lavd binary.

---

## Prerequisites

All scripts run as root. Required tools on PATH: `bpftrace`, `perf`, `stress-ng`, `scx_lavd`, `stackcollapse-perf.pl`, `flamegraph.pl`.

The machine must run a kernel with `CONFIG_DEBUG_INFO_BTF=y` (required for fentry/fexit on BPF programs). Verify with:
```bash
grep CONFIG_DEBUG_INFO_BTF /boot/config-$(uname -r)
# Expected: CONFIG_DEBUG_INFO_BTF=y
```

cgroup v2 must be the unified hierarchy:
```bash
mount | grep cgroup2
# Expected: cgroup2 on /sys/fs/cgroup type cgroup2 ...
```

---

## Task 1: Directory skeleton

**Files:**
- Create: `benchmarks/cpu_max_overhead/setup_cgroup.sh`
- Create: `benchmarks/cpu_max_overhead/teardown_cgroup.sh`
- Create: `benchmarks/cpu_max_overhead/run_bench.sh`
- Create: `benchmarks/cpu_max_overhead/perf/stat.sh`
- Create: `benchmarks/cpu_max_overhead/perf/record.sh`
- Create: `benchmarks/cpu_max_overhead/trace/eevdf_hotpath.bt`
- Create: `benchmarks/cpu_max_overhead/trace/eevdf_accounting.bt`
- Create: `benchmarks/cpu_max_overhead/trace/eevdf_throttle.bt`
- Create: `benchmarks/cpu_max_overhead/trace/scx_lavd.bt`
- Create: `benchmarks/cpu_max_overhead/results/report.sh`

**Step 1: Create directories**

```bash
mkdir -p benchmarks/cpu_max_overhead/{perf,trace,results}
```

**Step 2: Verify**

```bash
find benchmarks/cpu_max_overhead -type d
# Expected:
# benchmarks/cpu_max_overhead
# benchmarks/cpu_max_overhead/perf
# benchmarks/cpu_max_overhead/trace
# benchmarks/cpu_max_overhead/results
```

**Step 3: Commit**

```bash
git add benchmarks/
git commit -m "bench/cpu_max_overhead: Add directory skeleton

Signed-off-by: Changwoo Min <changwoo@igalia.com>"
```

---

## Task 2: setup_cgroup.sh

Creates a depth-20 linear cgroup v2 hierarchy under `/sys/fs/cgroup/bench/`.
Accepts one argument: `on` (set cpu.max quota) or `off` (set cpu.max to unlimited).

**Files:**
- Create: `benchmarks/cpu_max_overhead/setup_cgroup.sh`

**Step 1: Write the script**

```bash
#!/bin/bash
# setup_cgroup.sh <on|off>
# Creates /sys/fs/cgroup/bench/l01/l02/.../l20/
# on:  sets cpu.max = "9600000 100000" at every level (96 CPUs, 100ms period)
# off: sets cpu.max = "max 100000" at every level (unlimited)
set -euo pipefail

MODE="${1:-on}"
BENCH_ROOT="/sys/fs/cgroup/bench"
DEPTH=20
QUOTA_ON="9600000 100000"
QUOTA_OFF="max 100000"

if [[ "$MODE" == "on" ]]; then
    QUOTA="$QUOTA_ON"
else
    QUOTA="$QUOTA_OFF"
fi

# Enable cpu controller at the root cgroup
echo "+cpu" > /sys/fs/cgroup/cgroup.subtree_control

# Create bench root
mkdir -p "$BENCH_ROOT"
echo "+cpu" > /sys/fs/cgroup/cgroup.subtree_control

CURRENT="$BENCH_ROOT"
for i in $(seq -w 1 $DEPTH); do
    NEXT="$CURRENT/l$i"
    mkdir -p "$NEXT"
    # Enable cpu subtree control so children can use it
    echo "+cpu" > "$CURRENT/cgroup.subtree_control" 2>/dev/null || true
    echo "$QUOTA" > "$NEXT/cpu.max"
    CURRENT="$NEXT"
done

LEAF="$CURRENT"
echo "Hierarchy ready. Leaf: $LEAF  cpu.max: $QUOTA"
echo "$LEAF" > /tmp/cpu_max_bench_leaf
```

**Step 2: Make executable and verify syntax**

```bash
chmod +x benchmarks/cpu_max_overhead/setup_cgroup.sh
bash -n benchmarks/cpu_max_overhead/setup_cgroup.sh
# Expected: no output (no syntax errors)
```

**Step 3: Smoke-test as root**

```bash
sudo benchmarks/cpu_max_overhead/setup_cgroup.sh on
# Expected: "Hierarchy ready. Leaf: /sys/fs/cgroup/bench/l20  cpu.max: 9600000 100000"
cat /sys/fs/cgroup/bench/l05/cpu.max
# Expected: 9600000 100000
cat /tmp/cpu_max_bench_leaf
# Expected: /sys/fs/cgroup/bench/l01/l02/.../l20
```

---

## Task 3: teardown_cgroup.sh

Removes the cgroup hierarchy cleanly after moving any remaining tasks back to root.

**Files:**
- Create: `benchmarks/cpu_max_overhead/teardown_cgroup.sh`

**Step 1: Write the script**

```bash
#!/bin/bash
# teardown_cgroup.sh
# Removes /sys/fs/cgroup/bench/ and all children.
set -euo pipefail

BENCH_ROOT="/sys/fs/cgroup/bench"

if [[ ! -d "$BENCH_ROOT" ]]; then
    echo "Nothing to tear down."
    exit 0
fi

# Move all tasks back to root cgroup
find "$BENCH_ROOT" -name "cgroup.procs" | while read -r f; do
    while IFS= read -r pid; do
        [[ -n "$pid" ]] && echo "$pid" > /sys/fs/cgroup/cgroup.procs 2>/dev/null || true
    done < "$f"
done

# Remove directories bottom-up (deepest first)
find "$BENCH_ROOT" -depth -mindepth 1 -type d | while read -r d; do
    rmdir "$d" 2>/dev/null || true
done
rmdir "$BENCH_ROOT" 2>/dev/null || true

rm -f /tmp/cpu_max_bench_leaf
echo "Teardown complete."
```

**Step 2: Make executable and verify syntax**

```bash
chmod +x benchmarks/cpu_max_overhead/teardown_cgroup.sh
bash -n benchmarks/cpu_max_overhead/teardown_cgroup.sh
```

**Step 3: Smoke-test as root**

```bash
sudo benchmarks/cpu_max_overhead/teardown_cgroup.sh
# Expected: "Teardown complete."
ls /sys/fs/cgroup/bench 2>/dev/null || echo "removed"
# Expected: "removed"
```

**Step 4: Commit**

```bash
git add benchmarks/cpu_max_overhead/setup_cgroup.sh \
        benchmarks/cpu_max_overhead/teardown_cgroup.sh
git commit -m "bench/cpu_max_overhead: Add cgroup setup/teardown scripts

Creates a depth-20 linear cgroup v2 hierarchy with cpu.max = 9600000/100000
(96 CPUs, 100ms period) at every level. Teardown moves tasks back to root
before removing directories.

Signed-off-by: Changwoo Min <changwoo@igalia.com>"
```

---

## Task 4: perf/stat.sh

Runs `perf stat` system-wide for one condition, saves output to `results/<condition>/perf.stat.txt`.

**Files:**
- Create: `benchmarks/cpu_max_overhead/perf/stat.sh`

**Step 1: Write the script**

```bash
#!/bin/bash
# perf/stat.sh <output_dir> <duration_sec>
# Runs stress-ng under perf stat, saves to <output_dir>/perf.stat.txt
set -euo pipefail

OUTPUT_DIR="${1:?Usage: stat.sh <output_dir> <duration_sec>}"
DURATION="${2:-60}"
LEAF="$(cat /tmp/cpu_max_bench_leaf)"
OUTFILE="$OUTPUT_DIR/perf.stat.txt"

mkdir -p "$OUTPUT_DIR"

echo "Running perf stat for ${DURATION}s → $OUTFILE"

# Move stress-ng into the leaf cgroup via wrapper
perf stat -a \
    -e cycles:k \
    -e instructions:k \
    -e sched:sched_switch \
    -o "$OUTFILE" \
    -- bash -c "echo \$\$ > ${LEAF}/cgroup.procs && \
                exec stress-ng --cpu 192 --timeout ${DURATION}s --metrics-brief"

echo "perf stat saved to $OUTFILE"
```

**Step 2: Make executable and verify syntax**

```bash
chmod +x benchmarks/cpu_max_overhead/perf/stat.sh
bash -n benchmarks/cpu_max_overhead/perf/stat.sh
```

---

## Task 5: perf/record.sh

Runs `perf record` system-wide for one condition, saves `perf.data` and generates a flamegraph SVG.

**Files:**
- Create: `benchmarks/cpu_max_overhead/perf/record.sh`

**Step 1: Write the script**

```bash
#!/bin/bash
# perf/record.sh <output_dir> <duration_sec>
# Runs stress-ng under perf record, generates flamegraph.svg
set -euo pipefail

OUTPUT_DIR="${1:?Usage: record.sh <output_dir> <duration_sec>}"
DURATION="${2:-60}"
LEAF="$(cat /tmp/cpu_max_bench_leaf)"
PERF_DATA="$OUTPUT_DIR/perf.data"
FLAMEGRAPH="$OUTPUT_DIR/flamegraph.svg"

mkdir -p "$OUTPUT_DIR"

echo "Running perf record for ${DURATION}s → $PERF_DATA"

perf record -a -g \
    -e cycles:k \
    -o "$PERF_DATA" \
    -- bash -c "echo \$\$ > ${LEAF}/cgroup.procs && \
                exec stress-ng --cpu 192 --timeout ${DURATION}s --metrics-brief"

echo "Generating flamegraph → $FLAMEGRAPH"
perf script -i "$PERF_DATA" \
    | stackcollapse-perf.pl \
    | flamegraph.pl > "$FLAMEGRAPH"

echo "Flamegraph saved to $FLAMEGRAPH"
```

**Step 2: Make executable and verify syntax**

```bash
chmod +x benchmarks/cpu_max_overhead/perf/record.sh
bash -n benchmarks/cpu_max_overhead/perf/record.sh
```

**Step 3: Commit**

```bash
git add benchmarks/cpu_max_overhead/perf/
git commit -m "bench/cpu_max_overhead: Add perf stat and record scripts

perf/stat.sh: system-wide perf stat (cycles:k, instructions:k, sched_switch)
perf/record.sh: system-wide perf record + flamegraph generation

Signed-off-by: Changwoo Min <changwoo@igalia.com>"
```

---

## Task 6: trace/eevdf_hotpath.bt

Measures per-call latency of `throttled_hierarchy()` — the O(depth) check performed on every task pick under EEVDF with cpu.max enabled.

**Files:**
- Create: `benchmarks/cpu_max_overhead/trace/eevdf_hotpath.bt`

**Step 1: Write the script**

```bpftrace
#!/usr/bin/bpftrace
// trace/eevdf_hotpath.bt
// Measures per-call latency of throttled_hierarchy() (EEVDF hot path).
// Run under condition B (EEVDF + cpu.max).

BEGIN {
    printf("Tracing throttled_hierarchy — hit Ctrl-C to print results.\n");
}

kprobe:throttled_hierarchy
{
    @start[tid] = nsecs;
}

kretprobe:throttled_hierarchy
/@start[tid]/
{
    @latency_ns = hist(nsecs - @start[tid]);
    @calls_total++;
    delete(@start[tid]);
}

interval:s:1
{
    printf("throttled_hierarchy calls/sec: %lld\n", @calls_total);
    @calls_total = 0;
}

END
{
    clear(@start);
    printf("\nthrottled_hierarchy latency histogram (ns):\n");
    print(@latency_ns);
}
```

**Step 2: Verify the kernel symbol exists**

```bash
grep -w throttled_hierarchy /proc/kallsyms | head -3
# Expected: one or more lines with the symbol
```

**Step 3: Verify bpftrace can attach (dry-run)**

```bash
sudo bpftrace -l 'kprobe:throttled_hierarchy'
# Expected: kprobe:throttled_hierarchy
```

---

## Task 7: trace/eevdf_accounting.bt

Measures call rate of `__account_cfs_rq_runtime()` — the per-tick synchronous accounting function that drives EEVDF's global lock acquisitions.

**Files:**
- Create: `benchmarks/cpu_max_overhead/trace/eevdf_accounting.bt`

**Step 1: Write the script**

```bpftrace
#!/usr/bin/bpftrace
// trace/eevdf_accounting.bt
// Measures call rate of __account_cfs_rq_runtime() (EEVDF synchronous accounting).
// Run under condition B (EEVDF + cpu.max).

BEGIN {
    printf("Tracing __account_cfs_rq_runtime — hit Ctrl-C to print results.\n");
}

kprobe:__account_cfs_rq_runtime
{
    @calls_total++;
}

interval:s:1
{
    printf("__account_cfs_rq_runtime calls/sec: %lld\n", @calls_total);
    @rate_per_sec = lhist(@calls_total, 0, 10000000, 100000);
    @calls_total = 0;
}

END
{
    printf("\n__account_cfs_rq_runtime call rate distribution (calls/sec):\n");
    print(@rate_per_sec);
}
```

**Step 2: Verify the kernel symbol exists**

```bash
grep -w __account_cfs_rq_runtime /proc/kallsyms | head -3
# Expected: one or more lines
```

---

## Task 8: trace/eevdf_throttle.bt

Measures per-call latency of `throttle_cfs_rq()` and `unthrottle_cfs_rq()` — the O(depth) throttle/unthrottle propagation paths.

**Files:**
- Create: `benchmarks/cpu_max_overhead/trace/eevdf_throttle.bt`

**Step 1: Write the script**

```bpftrace
#!/usr/bin/bpftrace
// trace/eevdf_throttle.bt
// Measures throttle_cfs_rq and unthrottle_cfs_rq latency (EEVDF throttle path).
// Run under condition B (EEVDF + cpu.max).

BEGIN {
    printf("Tracing throttle/unthrottle_cfs_rq — hit Ctrl-C to print results.\n");
}

kprobe:throttle_cfs_rq
{
    @throttle_start[tid] = nsecs;
    @throttle_calls++;
}

kretprobe:throttle_cfs_rq
/@throttle_start[tid]/
{
    @throttle_latency_ns = hist(nsecs - @throttle_start[tid]);
    delete(@throttle_start[tid]);
}

kprobe:unthrottle_cfs_rq
{
    @unthrottle_start[tid] = nsecs;
    @unthrottle_calls++;
}

kretprobe:unthrottle_cfs_rq
/@unthrottle_start[tid]/
{
    @unthrottle_latency_ns = hist(nsecs - @unthrottle_start[tid]);
    delete(@unthrottle_start[tid]);
}

interval:s:1
{
    printf("throttle/sec: %lld  unthrottle/sec: %lld\n",
           @throttle_calls, @unthrottle_calls);
    @throttle_calls = 0;
    @unthrottle_calls = 0;
}

END
{
    clear(@throttle_start);
    clear(@unthrottle_start);
    printf("\nthrottle_cfs_rq latency (ns):\n");
    print(@throttle_latency_ns);
    printf("\nunthrottle_cfs_rq latency (ns):\n");
    print(@unthrottle_latency_ns);
}
```

**Step 2: Verify kernel symbols**

```bash
grep -wE 'throttle_cfs_rq|unthrottle_cfs_rq' /proc/kallsyms | head -5
```

**Step 3: Commit**

```bash
git add benchmarks/cpu_max_overhead/trace/eevdf_hotpath.bt \
        benchmarks/cpu_max_overhead/trace/eevdf_accounting.bt \
        benchmarks/cpu_max_overhead/trace/eevdf_throttle.bt
git commit -m "bench/cpu_max_overhead: Add bpftrace scripts for EEVDF enforcement functions

eevdf_hotpath.bt:   kprobe/kretprobe on throttled_hierarchy (hot-path latency)
eevdf_accounting.bt: kprobe on __account_cfs_rq_runtime (call rate)
eevdf_throttle.bt:  kprobe/kretprobe on throttle/unthrottle_cfs_rq (latency)

Signed-off-by: Changwoo Min <changwoo@igalia.com>"
```

---

## Task 9: trace/scx_lavd.bt

Measures per-call latency of scx_lavd's cgroup_bw functions using `fentry`/`fexit`.
BPF-to-BPF function tracing requires the kernel to be built with `CONFIG_DEBUG_INFO_BTF=y`
and scx_lavd to be running when bpftrace attaches.

**Files:**
- Create: `benchmarks/cpu_max_overhead/trace/scx_lavd.bt`

**Step 1: Identify available fentry targets while scx_lavd is running**

```bash
# Start scx_lavd in a separate terminal first, then:
sudo bpftrace -l 'fentry:*' 2>/dev/null | grep -E 'cgroup_bw|cbw_'
# Expected: lines like:
#   fentry:scx_cgroup_bw_throttled
#   fentry:scx_cgroup_bw_consume
#   fentry:cbw_update_runtime_total_sloppy
#   fentry:cbw_throttle_cgroups
# If names differ, adjust the script below to match.
```

**Step 2: Write the script**

```bpftrace
#!/usr/bin/bpftrace
// trace/scx_lavd.bt
// Measures per-call latency of scx_lavd cgroup_bw functions via fentry/fexit.
// scx_lavd must be running before attaching. Run under condition D.

BEGIN {
    printf("Tracing scx_lavd cgroup_bw functions — hit Ctrl-C to print results.\n");
    printf("NOTE: scx_lavd must already be running.\n");
}

fentry:scx_cgroup_bw_throttled
{
    @throttled_start[tid] = nsecs;
    @throttled_calls++;
}

fexit:scx_cgroup_bw_throttled
/@throttled_start[tid]/
{
    @throttled_latency_ns = hist(nsecs - @throttled_start[tid]);
    delete(@throttled_start[tid]);
}

fentry:scx_cgroup_bw_consume
{
    @consume_start[tid] = nsecs;
    @consume_calls++;
}

fexit:scx_cgroup_bw_consume
/@consume_start[tid]/
{
    @consume_latency_ns = hist(nsecs - @consume_start[tid]);
    delete(@consume_start[tid]);
}

fentry:cbw_update_runtime_total_sloppy
{
    @update_start[tid] = nsecs;
}

fexit:cbw_update_runtime_total_sloppy
/@update_start[tid]/
{
    @update_latency_ns = hist(nsecs - @update_start[tid]);
    delete(@update_start[tid]);
}

fentry:cbw_throttle_cgroups
{
    @throttle_cgroups_start[tid] = nsecs;
}

fexit:cbw_throttle_cgroups
/@throttle_cgroups_start[tid]/
{
    @throttle_cgroups_latency_ns = hist(nsecs - @throttle_cgroups_start[tid]);
    delete(@throttle_cgroups_start[tid]);
}

interval:s:1
{
    printf("throttled_checks/sec: %lld  consume_calls/sec: %lld\n",
           @throttled_calls, @consume_calls);
    @throttled_calls = 0;
    @consume_calls = 0;
}

END
{
    clear(@throttled_start);
    clear(@consume_start);
    clear(@update_start);
    clear(@throttle_cgroups_start);

    printf("\nscx_cgroup_bw_throttled latency (ns):\n");
    print(@throttled_latency_ns);
    printf("\nscx_cgroup_bw_consume latency (ns):\n");
    print(@consume_latency_ns);
    printf("\ncbw_update_runtime_total_sloppy latency (ns):\n");
    print(@update_latency_ns);
    printf("\ncbw_throttle_cgroups latency (ns):\n");
    print(@throttle_cgroups_latency_ns);
}
```

**Step 3: Commit**

```bash
git add benchmarks/cpu_max_overhead/trace/scx_lavd.bt
git commit -m "bench/cpu_max_overhead: Add bpftrace script for scx_lavd cgroup_bw functions

Uses fentry/fexit to trace BPF functions: scx_cgroup_bw_throttled,
scx_cgroup_bw_consume, cbw_update_runtime_total_sloppy, cbw_throttle_cgroups.
scx_lavd must be running when bpftrace attaches.

Signed-off-by: Changwoo Min <changwoo@igalia.com>"
```

---

## Task 10: results/report.sh

Parses `perf.stat.txt` from all four condition directories, computes `cycles:k / sched_switch`, and prints a comparison table alongside bpftrace histogram summaries.

**Files:**
- Create: `benchmarks/cpu_max_overhead/results/report.sh`

**Step 1: Write the script**

```bash
#!/bin/bash
# results/report.sh
# Reads results/{A,B,C,D}/perf.stat.txt and results/{B,D}/bpftrace.txt
# Prints a summary comparison table.
set -euo pipefail

RESULTS_DIR="$(cd "$(dirname "$0")" && pwd)"

parse_perf_stat() {
    local file="$1"
    local cycles instructions switches
    cycles=$(grep -oP '[\d,]+(?=\s+cycles:k)' "$file" | tr -d ',' | head -1)
    instructions=$(grep -oP '[\d,]+(?=\s+instructions:k)' "$file" | tr -d ',' | head -1)
    switches=$(grep -oP '[\d,]+(?=\s+sched:sched_switch)' "$file" | tr -d ',' | head -1)
    echo "${cycles:-0} ${instructions:-0} ${switches:-0}"
}

compute_ratio() {
    local numerator="$1" denominator="$2"
    if [[ "$denominator" -eq 0 ]]; then echo "N/A"; return; fi
    echo $(( numerator / denominator ))
}

printf "\n=== cpu.max Enforcement Overhead: EEVDF vs. scx_lavd ===\n\n"
printf "%-5s %-10s %-8s %-16s %-20s %-20s\n" \
    "Cond" "Scheduler" "cpu.max" "cycles:k" "cycles:k/switch" "instructions:k/switch"
printf '%s\n' "$(printf '─%.0s' {1..80})"

for cond in A B C D; do
    statfile="$RESULTS_DIR/$cond/perf.stat.txt"
    if [[ ! -f "$statfile" ]]; then
        printf "%-5s  (no data)\n" "$cond"
        continue
    fi
    read -r cycles instructions switches <<< "$(parse_perf_stat "$statfile")"
    case $cond in
        A) sched="EEVDF";    cpumax="off" ;;
        B) sched="EEVDF";    cpumax="on"  ;;
        C) sched="scx_lavd"; cpumax="off" ;;
        D) sched="scx_lavd"; cpumax="on"  ;;
    esac
    cycles_per_sw=$(compute_ratio "$cycles" "$switches")
    instr_per_sw=$(compute_ratio "$instructions" "$switches")
    printf "%-5s %-10s %-8s %-16s %-20s %-20s\n" \
        "$cond" "$sched" "$cpumax" "$cycles" "$cycles_per_sw" "$instr_per_sw"
done

printf '\n'

# Enforcement overhead (delta)
for pair in "EEVDF:B:A" "scx_lavd:D:C"; do
    IFS=: read -r name cond_on cond_off <<< "$pair"
    f_on="$RESULTS_DIR/$cond_on/perf.stat.txt"
    f_off="$RESULTS_DIR/$cond_off/perf.stat.txt"
    if [[ -f "$f_on" && -f "$f_off" ]]; then
        read -r cy_on  _ sw_on  <<< "$(parse_perf_stat "$f_on")"
        read -r cy_off _ sw_off <<< "$(parse_perf_stat "$f_off")"
        ratio_on=$(compute_ratio  "$cy_on"  "$sw_on")
        ratio_off=$(compute_ratio "$cy_off" "$sw_off")
        delta=$(( ratio_on - ratio_off ))
        printf "%s enforcement overhead: %s cycles/switch (on=%s off=%s)\n" \
            "$name" "$delta" "$ratio_on" "$ratio_off"
    fi
done

printf '\n=== bpftrace Histograms ===\n'
for cond in B D; do
    btfile="$RESULTS_DIR/$cond/bpftrace.txt"
    if [[ -f "$btfile" ]]; then
        printf "\n--- Condition %s ---\n" "$cond"
        cat "$btfile"
    fi
done
```

**Step 2: Make executable and verify syntax**

```bash
chmod +x benchmarks/cpu_max_overhead/results/report.sh
bash -n benchmarks/cpu_max_overhead/results/report.sh
```

**Step 3: Commit**

```bash
git add benchmarks/cpu_max_overhead/results/report.sh
git commit -m "bench/cpu_max_overhead: Add results/report.sh summary script

Parses perf.stat.txt from all four conditions, computes cycles:k/switch
and instructions:k/switch, prints enforcement overhead delta, and appends
raw bpftrace histograms.

Signed-off-by: Changwoo Min <changwoo@igalia.com>"
```

---

## Task 11: run_bench.sh — main orchestrator

Runs all four conditions in sequence, invoking helper scripts and saving results.

**Files:**
- Create: `benchmarks/cpu_max_overhead/run_bench.sh`

**Step 1: Write the script**

```bash
#!/bin/bash
# run_bench.sh
# Orchestrates all four benchmark conditions (A, B, C, D).
# Must be run as root.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
DURATION=60
SCX_LAVD="${SCX_LAVD_BIN:-/usr/bin/scx_lavd}"
SCX_LAVD_PID=""

log() { printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }

require_root() {
    [[ $EUID -eq 0 ]] || { echo "Run as root."; exit 1; }
}

require_tools() {
    for t in bpftrace perf stress-ng stackcollapse-perf.pl flamegraph.pl; do
        command -v "$t" &>/dev/null || { echo "Missing tool: $t"; exit 1; }
    done
    [[ -x "$SCX_LAVD" ]] || { echo "scx_lavd not found at $SCX_LAVD (set SCX_LAVD_BIN)"; exit 1; }
}

start_scx_lavd() {
    log "Starting scx_lavd..."
    "$SCX_LAVD" &
    SCX_LAVD_PID=$!
    sleep 2  # wait for scheduler to load
    log "scx_lavd running (PID $SCX_LAVD_PID)"
}

stop_scx_lavd() {
    if [[ -n "$SCX_LAVD_PID" ]]; then
        log "Stopping scx_lavd (PID $SCX_LAVD_PID)..."
        kill "$SCX_LAVD_PID" 2>/dev/null || true
        wait "$SCX_LAVD_PID" 2>/dev/null || true
        SCX_LAVD_PID=""
        sleep 2  # wait for kernel to switch back to EEVDF
    fi
}

run_condition() {
    local cond="$1"      # A B C D
    local scheduler="$2" # eevdf scx_lavd
    local cpumax="$3"    # on off
    local out="$RESULTS_DIR/$cond"
    mkdir -p "$out"

    log "=== Condition $cond: scheduler=$scheduler cpu.max=$cpumax ==="

    # Setup cgroup hierarchy
    "$SCRIPT_DIR/setup_cgroup.sh" "$cpumax"

    # Start bpftrace in background (conditions B and D only)
    local bt_pid=""
    if [[ "$cond" == "B" ]]; then
        bpftrace "$SCRIPT_DIR/trace/eevdf_hotpath.bt"   > "$out/bt_hotpath.txt"   2>&1 &
        bpftrace "$SCRIPT_DIR/trace/eevdf_accounting.bt" > "$out/bt_accounting.txt" 2>&1 &
        bpftrace "$SCRIPT_DIR/trace/eevdf_throttle.bt"  > "$out/bt_throttle.txt"  2>&1 &
        bt_pid="$(jobs -p)"
        sleep 1  # let probes attach
    elif [[ "$cond" == "D" ]]; then
        bpftrace "$SCRIPT_DIR/trace/scx_lavd.bt" > "$out/bpftrace.txt" 2>&1 &
        bt_pid=$!
        sleep 1
    fi

    # perf stat run
    log "Running perf stat (${DURATION}s)..."
    "$SCRIPT_DIR/perf/stat.sh" "$out" "$DURATION"

    # perf record run (B and D only)
    if [[ "$cond" == "B" || "$cond" == "D" ]]; then
        log "Running perf record (${DURATION}s)..."
        "$SCRIPT_DIR/perf/record.sh" "$out" "$DURATION"
    fi

    # Stop bpftrace
    if [[ -n "$bt_pid" ]]; then
        sleep 2
        kill $bt_pid 2>/dev/null || true
        wait $bt_pid 2>/dev/null || true
        # Merge bpftrace outputs for condition B
        if [[ "$cond" == "B" ]]; then
            cat "$out"/bt_*.txt > "$out/bpftrace.txt"
        fi
    fi

    # Teardown cgroup hierarchy
    "$SCRIPT_DIR/teardown_cgroup.sh"
    log "Condition $cond complete. Results in $out/"
    sleep 5
}

require_root
require_tools

mkdir -p "$RESULTS_DIR"/{A,B,C,D}

# Condition A: EEVDF baseline (no cpu.max)
stop_scx_lavd
run_condition A eevdf off

# Condition B: EEVDF + cpu.max
stop_scx_lavd
run_condition B eevdf on

# Condition C: scx_lavd baseline (no cpu.max)
start_scx_lavd
run_condition C scx_lavd off
stop_scx_lavd

# Condition D: scx_lavd + cpu.max
start_scx_lavd
run_condition D scx_lavd on
stop_scx_lavd

log "All conditions complete. Generating report..."
"$RESULTS_DIR/report.sh"
```

**Step 2: Make executable and verify syntax**

```bash
chmod +x benchmarks/cpu_max_overhead/run_bench.sh
bash -n benchmarks/cpu_max_overhead/run_bench.sh
```

**Step 3: Dry-run check (without running as root)**

```bash
bash -x benchmarks/cpu_max_overhead/run_bench.sh 2>&1 | head -20
# Expected: fails at require_root check, not a syntax error
# Output should include: "Run as root."
```

**Step 4: Commit**

```bash
git add benchmarks/cpu_max_overhead/run_bench.sh
git commit -m "bench/cpu_max_overhead: Add run_bench.sh main orchestrator

Runs all four conditions (A-D) in sequence: EEVDF baseline, EEVDF+cpu.max,
scx_lavd baseline, scx_lavd+cpu.max. Invokes perf stat, perf record, and
bpftrace helpers per condition. Generates summary report on completion.

Signed-off-by: Changwoo Min <changwoo@igalia.com>"
```

---

## Task 12: End-to-end validation

**Step 1: Verify the full directory tree**

```bash
find benchmarks/cpu_max_overhead -type f | sort
# Expected:
# benchmarks/cpu_max_overhead/perf/record.sh
# benchmarks/cpu_max_overhead/perf/stat.sh
# benchmarks/cpu_max_overhead/results/report.sh
# benchmarks/cpu_max_overhead/run_bench.sh
# benchmarks/cpu_max_overhead/setup_cgroup.sh
# benchmarks/cpu_max_overhead/teardown_cgroup.sh
# benchmarks/cpu_max_overhead/trace/eevdf_accounting.bt
# benchmarks/cpu_max_overhead/trace/eevdf_hotpath.bt
# benchmarks/cpu_max_overhead/trace/eevdf_throttle.bt
# benchmarks/cpu_max_overhead/trace/scx_lavd.bt
```

**Step 2: Verify all scripts are executable**

```bash
find benchmarks/cpu_max_overhead -name '*.sh' | xargs ls -l | grep -v '^-rwx'
# Expected: no output (all .sh files are executable)
```

**Step 3: Verify all shell scripts have no syntax errors**

```bash
find benchmarks/cpu_max_overhead -name '*.sh' -exec bash -n {} \; -print
# Expected: all filenames printed, no error messages
```

**Step 4: Verify bpftrace scripts parse cleanly**

```bash
for f in benchmarks/cpu_max_overhead/trace/*.bt; do
    sudo bpftrace --dry-run "$f" 2>&1 | grep -i error && echo "ERROR in $f" || echo "OK: $f"
done
```

**Step 5: Run a short smoke test (as root, 10s)**

```bash
sudo DURATION=10 benchmarks/cpu_max_overhead/run_bench.sh
# Expected: conditions A-D complete, results/ directories populated,
#           summary table printed at the end.
```

**Step 6: Run the full benchmark (as root, 60s per condition)**

```bash
sudo benchmarks/cpu_max_overhead/run_bench.sh
```

**Step 7: Final commit**

```bash
git add benchmarks/
git commit -m "bench/cpu_max_overhead: All scripts complete and validated

Signed-off-by: Changwoo Min <changwoo@igalia.com>"
```
