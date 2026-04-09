#!/bin/bash
# perf/record.sh <output_dir> <duration_sec>
# Runs stress-ng under perf record.
# Set FLAMEGRAPH=1 to also generate flamegraph.svg (slow on many-CPU machines).
set -euo pipefail

OUTPUT_DIR="${1:?Usage: record.sh <output_dir> <duration_sec>}"
DURATION="${2:-60}"
FLAMEGRAPH="${FLAMEGRAPH:-0}"
LEAF="$(cat /tmp/cpu_max_bench_leaf)"
PERF_DATA="$OUTPUT_DIR/perf.data"

mkdir -p "$OUTPUT_DIR"

echo "Running perf record for ${DURATION}s → $PERF_DATA"

perf record -a -g \
    -e cycles:k \
    -o "$PERF_DATA" \
    -- bash -c "echo \$\$ > ${LEAF}/cgroup.procs && \
                exec stress-ng --cpu $(( $(nproc) * 2 )) --timeout ${DURATION}s --metrics-brief"

if [[ "$FLAMEGRAPH" == "1" ]]; then
    FG="$OUTPUT_DIR/flamegraph.svg"
    echo "Generating flamegraph → $FG"
    perf script -i "$PERF_DATA" \
        | stackcollapse-perf.pl \
        | flamegraph.pl > "$FG"
    echo "Flamegraph saved to $FG"
else
    echo "Flamegraph skipped (set FLAMEGRAPH=1 to enable)."
fi
