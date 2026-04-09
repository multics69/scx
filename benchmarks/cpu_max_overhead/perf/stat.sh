#!/bin/bash
# perf/stat.sh <output_dir> <duration_sec>
# Runs stress-ng under perf stat, saves to <output_dir>/perf.stat.txt
set -euo pipefail

OUTPUT_DIR="${1:?Usage: stat.sh <output_dir> <duration_sec> [nworkers]}"
DURATION="${2:-60}"
NWORKERS="${3:-$(( $(nproc) * 2 ))}"
LEAF="$(cat /tmp/cpu_max_bench_leaf)"
OUTFILE="$OUTPUT_DIR/perf.stat.txt"

mkdir -p "$OUTPUT_DIR"

echo "Running perf stat for ${DURATION}s → $OUTFILE"

# Move stress-ng into the leaf cgroup via wrapper
perf stat -a \
    -e cycles \
    -e cycles:k \
    -o "$OUTFILE" \
    -- bash -c "echo \$\$ > ${LEAF}/cgroup.procs && \
                stress-ng --cpu ${NWORKERS} --timeout ${DURATION}s --metrics-brief" \
    2>"${OUTPUT_DIR}/stress_ng.txt"

echo "perf stat saved to $OUTFILE"
