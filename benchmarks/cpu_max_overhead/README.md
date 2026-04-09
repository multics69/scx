# cpu.max Enforcement Overhead Benchmark

Measures the scheduling overhead of `cpu.max` enforcement in EEVDF (kernel CFS bandwidth
controller) versus scx_lavd (BPF-based `lib/cgroup_bw`) using a configurable-depth cgroup
hierarchy (default: system max from `cgroup.max.depth`, or 16) on a many-CPU machine.

## Experiment Matrix

| Condition | Scheduler | cpu.max | Purpose |
|-----------|-----------|---------|---------|
| A | EEVDF | off | EEVDF baseline |
| B | EEVDF | on | EEVDF enforcement overhead |
| C | scx_lavd | off | scx_lavd baseline |
| D | scx_lavd | on | scx_lavd enforcement overhead |

Enforcement overhead = `(B − A)` for EEVDF, `(D − C)` for scx_lavd, expressed as
`cpu_equiv(k)` — kernel-mode CPU-equivalents, frequency-independent.

## Prerequisites

### Arch Linux / CachyOS

```bash
sudo pacman -S perf stress-ng
```

### Ubuntu 24.04 LTS

```bash
sudo apt install linux-tools-$(uname -r) stress-ng
```

### scx_lavd

You need `scx_lavd` built and available as a binary. If not packaged, build from this
repository:

```bash
cargo build --release -p scx_lavd
# binary is at: target/release/scx_lavd
```

## Running the Benchmark

```bash
cd benchmarks/cpu_max_overhead
sudo ./run_bench.sh
```

If `scx_lavd` is not at `/usr/bin/scx_lavd`, set `SCX_LAVD_BIN`:

```bash
sudo SCX_LAVD_BIN=./target/release/scx_lavd ./run_bench.sh
```

The full run takes roughly 10 minutes (4× 60 s perf stat + scheduler switch pauses).

## Worker Configurations

The benchmark supports two workload configurations controlled by `NWORKERS`:

| Configuration | NWORKERS | Behavior |
|---------------|----------|----------|
| 2x (default) | `2 × nproc` | Demand exceeds quota; cgroup hits limit each period and is throttled. Measures full enforcement cost (accounting + throttle/unthrottle). |
| 0.5x | `nproc / 2` | Demand is below quota; cgroup never hits the limit. Measures baseline accounting-only overhead without throttling. |

The quota is always set to 100% of all CPUs (`nproc × 100 ms` per 100 ms period).
Results are stored in separate directories per configuration.

Run both configurations:

```bash
# 2x overloaded (default) — results in results/2x/
sudo ./run_bench.sh

# 0.5x underloaded — results in results/0.5x/
sudo NWORKERS=$(( $(nproc) / 2 )) ./run_bench.sh
```

View reports:

```bash
./results/report.sh results/2x
./results/report.sh results/0.5x
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SCX_LAVD_BIN` | `/usr/bin/scx_lavd` | Path to the scx_lavd binary |
| `NWORKERS` | `nproc × 2` | Number of stress-ng CPU workers |
| `SCX_LAVD_OPTS_C` | `--performance --slice-min-us 3000 --slice-max-us 10000 --pinned-slice-us 3000` | Options for condition C (scx_lavd baseline, no cgroup_bw) |
| `SCX_LAVD_OPTS` | `--performance --slice-min-us 3000 --slice-max-us 10000 --pinned-slice-us 3000 --enable-cpu-bw` | Options for condition D (scx_lavd + cpu.max, cgroup_bw enabled) |
| `CGROUP_DEPTH` | system max or 16 | cgroup hierarchy depth |

## Results

After all conditions finish, the report is printed automatically. Re-run it any time:

```bash
./results/report.sh results/2x
```

Output files per condition:

```
results/
├── 2x/
│   ├── bench_params.txt          # ncpus, duration, nworkers, label
│   ├── A/
│   │   ├── perf.stat.txt         # cycles, cycles:k
│   │   └── stress_ng.txt         # stress-ng metrics (bogo ops/s)
│   ├── B/
│   │   ├── perf.stat.txt
│   │   └── stress_ng.txt
│   ├── C/
│   │   ├── perf.stat.txt
│   │   └── stress_ng.txt
│   └── D/
│       ├── perf.stat.txt
│       └── stress_ng.txt
└── 0.5x/
    └── ...
```

## Running Individual Pieces

```bash
# Create the hierarchy at the system max depth, cpu.max enabled (100% of CPUs, 100 ms period)
sudo ./setup_cgroup.sh on

# Create the hierarchy without cpu.max (unlimited)
sudo ./setup_cgroup.sh off

# Override depth explicitly (e.g., depth 10)
sudo ./setup_cgroup.sh on 10

# perf stat only (saves to /tmp/test/, 30-second run, 2×nproc workers)
sudo ./perf/stat.sh /tmp/test 30

# Tear down cgroup hierarchy
sudo ./teardown_cgroup.sh
```

## Metric: cpu_equiv(k)

The primary metric is `cpu_equiv(k) = (cycles:k / cycles) × nproc`, where:

- `cycles:k` — hardware PMU cycles spent in kernel mode across all CPUs (system-wide)
- `cycles` — total hardware PMU cycles across all CPUs (all modes)
- `nproc` — number of CPUs

This gives a frequency-independent measure of kernel CPU consumption expressed as
"equivalent CPUs worth of kernel time". It captures all enforcement paths regardless
of execution context: timer interrupt handlers, throttle/unthrottle calls, BPF timer
callbacks (`replenish_timerfn`, `accounting_timerfn`), and per-tick accounting.

Note: `cycles:k` is system-wide and includes baseline scheduler overhead (timer ticks,
CFS updates) in addition to enforcement cost. The B−A and D−C deltas isolate enforcement
by subtracting out the common baseline.

## Known Issues

### cgroup v2 must be the default hierarchy

The benchmark requires cgroup v2 (unified hierarchy). Verify:

```bash
mount | grep cgroup2
# should show: cgroup2 on /sys/fs/cgroup type cgroup2
```

On systems still using the hybrid or legacy hierarchy, add `systemd.unified_cgroup_hierarchy=1`
to the kernel command line.

### CPU count, quota, and cgroup depth are derived automatically

`setup_cgroup.sh` sets the quota to `nproc × 100000` µs per 100 ms period (100% of all
CPUs). With `NWORKERS = 2 × nproc` workers competing for `nproc` CPUs, the cgroup
exhausts its quota at each period boundary and is throttled briefly before the next
period. All CPUs are saturated at 100% throughout the measurement window, making the
scheduler load directly comparable between the baseline (A, C) and enforcement (B, D)
conditions.

The cgroup hierarchy depth defaults to the system maximum from
`/sys/fs/cgroup/cgroup.max.depth`. If that file says `max` (no limit configured),
the depth falls back to 16. Override via `CGROUP_DEPTH` or the second argument to
`setup_cgroup.sh`:

```bash
sudo ./setup_cgroup.sh on 10
```
