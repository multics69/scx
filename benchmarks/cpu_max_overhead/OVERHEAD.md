# cpu.max Enforcement Overhead: Analysis Approach

This document explains how the benchmark measures `cpu.max` enforcement overhead
and why the chosen methodology gives a fair, complete comparison between EEVDF and
scx_lavd.

## Goal

Quantify how much CPU time each scheduler spends enforcing `cpu.max` bandwidth
limits, expressed as a percentage of total wall-clock CPU time:

> "For this workload, EEVDF spends X% of CPU time enforcing cpu.max;
> scx_lavd spends Y%."

## The Four Conditions

The benchmark runs four conditions to isolate enforcement overhead from baseline
scheduling cost:

| Condition | Scheduler | cpu.max | Purpose |
|-----------|-----------|---------|---------|
| A | EEVDF | off | EEVDF baseline (no enforcement) |
| B | EEVDF | on  | EEVDF with enforcement |
| C | scx_lavd | off | scx_lavd baseline (no enforcement) |
| D | scx_lavd | on  | scx_lavd with enforcement |

**Enforcement overhead** is the extra kernel-mode CPU cycles consumed when
`cpu.max` is on versus off:

- **EEVDF overhead** = `(B − A)` kernel cycles
- **scx_lavd overhead** = `(D − C)` kernel cycles

Both deltas are normalized by total wall-clock CPU cycles
(`ncpus × duration × cpu_freq_GHz`) to yield a percentage.

## Workload Design

All four conditions run the same workload: `stress-ng --cpu N` with
`N = 2 × nproc` CPU workers. The cgroup hierarchy has `cpu.max` quota set to
`nproc × 100 ms`, i.e., 100% of all CPUs per 100 ms period.

With 2×nproc workers sharing nproc CPUs, the CPU consumption rate equals exactly
nproc CPUs — which is also the quota. The cgroup exhausts its quota precisely at
each period boundary and is throttled for a negligible window before the next
period begins. In practice all CPUs are saturated at 100% for the full measurement
window in all four conditions.

This makes A and B (and C and D) directly comparable: the scheduler faces the same
load in both the baseline and enforcement conditions. The B−A and D−C kernel cycle
deltas isolate the enforcement overhead without the confound of differing amounts of
scheduling work.

## Measurement: `cycles:k`

The primary metric is `perf stat -e cycles:k`, which counts hardware PMU
cycles spent in kernel mode across all CPUs for the duration of the run.

**Why kernel cycles?**

Enforcement overhead lives entirely in kernel mode:

- **EEVDF** (CFS bandwidth controller): `__account_cfs_rq_runtime` (called on
  every scheduler tick for every throttled entity), `throttle_cfs_rq` (quota
  exhausted), `unthrottle_cfs_rq` (period timer fires), `sched_cfs_period_timer`
  (the periodic replenishment timer).
- **scx_lavd** (lib/cgroup_bw): struct_ops callbacks (`lavd_enqueue`,
  `lavd_dispatch`, `lavd_tick`, `lavd_stopping`) that call `scx_cgroup_bw_*`
  helpers, plus BPF timer callbacks (`replenish_timerfn`, `accounting_timerfn`)
  registered via `bpf_timer_set_callback`.

The hardware PMU counts all of these unconditionally. No instrumentation is
needed; the counter is always running.

**Why not per-function tracing?**

Function-level tracing (bpftrace kprobes, `bpf_stats_enabled`) is incomplete:

- For EEVDF, `__account_cfs_rq_runtime` (the dominant cost, called once per
  scheduler tick per runnable entity) accounts for the vast majority of
  enforcement CPU time. It is inlined in some kernel builds, and even when
  traceable, instrumenting it adds probe overhead that distorts the measurement.
  Tracing only `throttle_cfs_rq` and `unthrottle_cfs_rq` captures perhaps 5% of
  the real enforcement cost.
- For scx_lavd, `kernel.bpf_stats_enabled` tracks `run_time_ns` per BPF program,
  but only for programs invoked via `bpf_prog_run`. BPF timer callbacks
  registered through `bpf_timer_set_callback` are called directly by the kernel
  timer subsystem — they have no `bpf_prog` accounting entry and are invisible
  to `bpftool prog show`.

`cycles:k` avoids both problems: it captures all kernel-mode cycles including
BPF JIT code, BPF timer callbacks, softirq handlers, and every enforcement path.

## Supplementary Data

### EEVDF: throttle/unthrottle time (condition B)

`trace/eevdf_enforce_time.bt` attaches kprobes to `throttle_cfs_rq` and
`unthrottle_cfs_rq`, accumulating total CPU-nanoseconds spent in those two
functions. This is **supplementary and incomplete** — it measures only the
throttle/unthrottle paths, not `__account_cfs_rq_runtime` or timer callbacks.
It appears in the report as context, not as the primary overhead number.

### scx_lavd: per-op BPF stats (conditions C and D)

`trace/scx_lavd_stats.sh` uses `kernel.bpf_stats_enabled=1` to snapshot
`run_time_ns` and `run_cnt` for the four struct_ops programs before and after
the measurement window, computing `avg_ns/call` for each. Comparing C (cpu.max
off) versus D (cpu.max on) shows the per-call cost added by cgroup_bw. This is
also supplementary — BPF timer callbacks (`replenish_timerfn`,
`accounting_timerfn`) are not captured here; their cost is included in the
`cycles:k` metric.

### CPU utilization plot (conditions B and D)

`trace/cgroup_cpu_util.sh` samples `cpu.stat usage_usec` every second to compute
utilization relative to total CPU capacity. `results/plot_cpu_util.py` plots
conditions B and D together with the quota limit line, showing how quickly and
tightly each scheduler enforces the limit.

## Why Not Measure cycles/sched_switch?

An earlier approach normalized kernel cycles by `sched:sched_switch` count
(cycles per context switch). This is misleading because enabling `cpu.max`
dramatically increases context switch count — throttled tasks are descheduled
and rescheduled at period boundaries, inflating the switch count in conditions B
and D relative to A and C. Dividing by a larger denominator makes the overhead
appear negative or negligible even when real enforcement cost is significant.

The correct denominator is fixed wall-clock CPU cycles, independent of scheduler
behavior.

## Reading the Report

`results/report.sh` prints:

1. **Raw table** — `cycles:k` and `sched_switch` counts per condition.
2. **cpu.max Enforcement Cost** — the primary result: overhead as % of total
   wall-clock CPU, with the raw cycle delta shown for transparency.
3. **EEVDF bpftrace detail** — throttle/unthrottle time only (supplementary).
4. **scx_lavd BPF program stats** — per-op avg latency, C vs D delta
   (supplementary; excludes timer callbacks).
5. **CPU utilization plot** — time series of utilization under quota (B vs D).
