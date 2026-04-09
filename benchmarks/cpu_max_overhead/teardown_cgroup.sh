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
