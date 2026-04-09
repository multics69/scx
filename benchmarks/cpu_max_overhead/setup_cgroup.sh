#!/bin/bash
# setup_cgroup.sh <on|off> [depth]
# Creates /sys/fs/cgroup/bench/l01/l02/.../l<depth>/
# on:  sets cpu.max = "<ncpus * 100000> 100000" at every level (100% of CPUs, 100ms period)
# off: sets cpu.max = "max 100000" at every level (unlimited)
#
# depth defaults to the system's maximum cgroup depth
# (from /sys/fs/cgroup/cgroup.max.depth). If the system has no depth limit
# ("max"), defaults to 16.
set -euo pipefail

MODE="${1:-on}"
BENCH_ROOT="/sys/fs/cgroup/bench"

# Determine default depth from system limit.
_sys_max="$(cat /sys/fs/cgroup/cgroup.max.depth 2>/dev/null || echo max)"
if [[ "$_sys_max" == "max" ]]; then
    _default_depth=16
else
    _default_depth="$_sys_max"
fi
DEPTH="${2:-$_default_depth}"

NCPUS="$(nproc)"
QUOTA_ON="$(( NCPUS * 100000 )) 100000"
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
echo "Hierarchy ready. depth=$DEPTH  Leaf: $LEAF  cpu.max: $QUOTA"
echo "$LEAF" > /tmp/cpu_max_bench_leaf
