# cpu.max Enforcement Overhead Measurement Design

**Date:** 2026-04-10
**Machine:** CachyOS, 192 CPUs
**Goal:** Compare the cpu.max enforcement overhead of EEVDF (kernel CFS bandwidth controller)
vs. scx_lavd (BPF lib/cgroup_bw) using a synthetic workload, a depth-20 cgroup hierarchy,
and a combination of perf and bpftrace instrumentation.

---

## 1. Motivation

The kernel's EEVDF scheduler enforces cpu.max synchronously on every tick and context switch,
acquiring a global `cfs_b->lock` for per-CPU slice replenishment. The lib/cgroup_bw library
used by scx_lavd decouples enforcement from the scheduling hot path via an async accounting
timer and an O(1) `is_throttled` flag read. Prior work (scx_flatcg case study) shows ~10%
throughput improvement over CFS with the CPU controller enabled in a 4-level cgroup hierarchy.
This benchmark quantifies the difference at depth=20 on a 192-CPU machine — a more extreme
case not covered by existing literature.

---

## 2. Experiment Matrix

Four conditions, all using a depth-20 cgroup hierarchy:

| Condition | Scheduler | cpu.max | Purpose |
|-----------|-----------|---------|---------|
| A | EEVDF | disabled | EEVDF baseline |
| B | EEVDF | enabled | EEVDF enforcement overhead |
| C | scx_lavd | disabled | scx_lavd baseline |
| D | scx_lavd | enabled | scx_lavd enforcement overhead |

Enforcement overhead:
- EEVDF: (B − A) cycles/switch
- scx_lavd: (D − C) cycles/switch

---

## 3. Cgroup Hierarchy Setup

A linear chain of 20 cgroup v2 directories under a benchmark root:

```
/sys/fs/cgroup/bench/l01/l02/.../l20/
```

- `cpu.max` is set at **every level** to maximally stress EEVDF's O(depth) paths
  (`throttled_hierarchy()`, `tg_throttle_down()`, `tg_unthrottle_up()`).
- **cpu.max value per level:** `9600000 100000`
  - Period: 100,000 µs (100 ms)
  - Quota: 9,600,000 µs = 96 CPU-equivalents (50% of 192 CPUs)
- The effective quota is the minimum across all 20 levels (`hierarchical_quota`).
- Workload processes are moved into the leaf cgroup (`l20`) before the benchmark starts.

With `stress-ng --cpu 192`, throttling fires after ~50 ms into each 100 ms period,
giving ~600 throttle/unthrottle cycles in a 60-second run.

---

## 4. Workload

```
stress-ng --cpu 192 --timeout 60
```

- CPU-bound, no I/O noise.
- Uses all 192 CPUs to saturate quota quickly and guarantee regular throttling.
- Each benchmark run: 60 seconds → ~600 throttle cycles per condition.

---

## 5. Measurement Strategy

### 5.1 perf stat

```
perf stat -a -e cycles:k,instructions:k,sched:sched_switch \
    -- stress-ng --cpu 192 --timeout 60
```

Run for all four conditions. Key derived metric:

```
cost per scheduling event = cycles:k / sched:sched_switch
```

This normalizes for the different CPU utilization between enabled/disabled conditions
and makes EEVDF and scx_lavd directly comparable.

### 5.2 perf record

```
perf record -a -g -e cycles:k -o perf.data -- stress-ng --cpu 192 --timeout 60
```

Run for conditions B and D. Post-process into flamegraphs:

```
perf script | stackcollapse-perf.pl | flamegraph.pl > flamegraph.svg
```

Flamegraphs show enforcement functions (`throttle_cfs_rq`, `throttled_hierarchy`,
`__account_cfs_rq_runtime` for EEVDF; BPF JIT frames for scx_lavd) as a fraction
of total kernel CPU time.

### 5.3 bpftrace

**Conditions A and C:** no bpftrace (baselines).

**Condition B — EEVDF + cpu.max** (`trace/eevdf_hotpath.bt`, `trace/eevdf_accounting.bt`,
`trace/eevdf_throttle.bt`):

| Script | Probes | Captures |
|--------|--------|----------|
| `eevdf_hotpath.bt` | `kprobe/kretprobe:throttled_hierarchy` | per-call latency histogram |
| `eevdf_accounting.bt` | `kprobe:__account_cfs_rq_runtime` | call rate (calls/sec) |
| `eevdf_throttle.bt` | `kprobe/kretprobe:throttle_cfs_rq`, `kretprobe:unthrottle_cfs_rq` | latency histograms, call rate |

**Condition D — scx_lavd + cpu.max** (`trace/scx_lavd.bt`):

Uses `fentry`/`fexit` to attach to BPF programs (supported since Linux 5.5):

| Probe | Captures |
|-------|----------|
| `fentry/fexit:scx_cgroup_bw_throttled` | hot-path flag-read latency histogram |
| `fentry/fexit:scx_cgroup_bw_consume` | per-dispatch accounting latency histogram |
| `fentry/fexit:cbw_update_runtime_total_sloppy` | async timer bottom-up aggregation latency |
| `fentry/fexit:cbw_throttle_cgroups` | async timer top-down propagation latency |

---

## 6. Script Structure

```
benchmarks/cpu_max_overhead/
├── setup_cgroup.sh          # create depth-20 hierarchy, set cpu.max at every level
├── teardown_cgroup.sh       # cleanup in reverse order
├── run_bench.sh             # main orchestrator: runs all 4 conditions, collects results
├── perf/
│   ├── record.sh            # perf record -a -g -e cycles:k
│   └── stat.sh              # perf stat -a -e cycles:k,instructions:k,sched:sched_switch
├── trace/
│   ├── eevdf_hotpath.bt     # kprobe/kretprobe: throttled_hierarchy
│   ├── eevdf_accounting.bt  # kprobe: __account_cfs_rq_runtime
│   ├── eevdf_throttle.bt    # kprobe/kretprobe: throttle_cfs_rq, unthrottle_cfs_rq
│   └── scx_lavd.bt          # fentry/fexit: cgroup_bw functions
└── results/
    ├── A/  B/  C/  D/       # one directory per condition
    └── report.sh            # generate summary table from collected data
```

`run_bench.sh` sequence per condition:
1. Load or unload scx_lavd (switch scheduler).
2. Enable or disable cpu.max on the hierarchy.
3. Start bpftrace scripts in background (conditions B and D only).
4. Run `perf stat` wrapping `stress-ng --cpu 192 --timeout 60`.
5. Run `perf record` for a second 60-second run (conditions B and D only).
6. Stop bpftrace, save all outputs to `results/<condition>/`.
7. Teardown cgroup hierarchy; pause before next condition.

---

## 7. Output and Reporting

**Raw outputs per condition directory:**

| File | Source |
|------|--------|
| `perf.stat.txt` | `perf stat` output |
| `perf.data` | `perf record` binary (conditions B, D) |
| `flamegraph.svg` | generated from `perf.data` (conditions B, D) |
| `bpftrace.txt` | bpftrace histogram output (conditions B, D) |

**`report.sh` summary table:**

```
Condition  Scheduler  cpu.max  cycles:k/switch  instructions:k/switch
A          EEVDF      off      ...              ...
B          EEVDF      on       ...              ...
C          scx_lavd   off      ...              ...
D          scx_lavd   on       ...              ...

EEVDF enforcement overhead:    (B - A) cycles/switch
scx_lavd enforcement overhead: (D - C) cycles/switch

--- EEVDF per-call latency (bpftrace, condition B) ---
throttled_hierarchy:       latency histogram (ns)
throttle_cfs_rq:           latency histogram (ns)
unthrottle_cfs_rq:         latency histogram (ns)
__account_cfs_rq_runtime:  call rate (calls/sec)

--- scx_lavd per-call latency (bpftrace, condition D) ---
scx_cgroup_bw_throttled:           latency histogram (ns)
scx_cgroup_bw_consume:             latency histogram (ns)
cbw_update_runtime_total_sloppy:   latency histogram (ns)
cbw_throttle_cgroups:              latency histogram (ns)
```

---

## 8. Prior Art

| Source | Finding |
|--------|---------|
| Turner et al., OLS 2010 — "CPU Bandwidth Control for CFS" | Original design; acknowledges `cfs_b->lock` contention, introduces per-CPU silo model |
| danluu.com — "The Container Throttling Problem" | Twitter: services fail at ~50% quota due to bursty throttling; 2x capacity after fix |
| Indeed Engineering, 2019 — "Unthrottled" | 88-core machines strand up to 87ms/period due to global lock thundering herd |
| Ugedal et al., SBAC-PAD 2022 — "Mitigating Unnecessary Throttling in Linux CFS Bandwidth Control" | Measures unnecessary throttling; evaluates mitigation techniques |
| scx_flatcg case study | ~10% throughput gain over CFS with CPU controller at cgroup depth=4 |
| LPC 2024 — "Priority Inheritance for CFS Bandwidth Control" | CFS throttling causes priority inversion and application timeouts at scale |

No published benchmark measures raw `throttled_hierarchy()` latency vs. depth or
`cfs_b->lock` contention at 192 CPUs and depth=20. This benchmark fills that gap.
