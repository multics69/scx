#!/bin/bash
# trace/cgroup_cpu_util.sh <cgroup_path> <duration_sec> <output_csv>
# Samples cpu.stat usage_usec every second and logs normalized CPU utilization.
#
# Output columns:
#   time_s     — elapsed seconds since start
#   util_pct   — CPU utilization as % of all CPUs (delta usage_usec / (ncpus * 1e6) * 100)
#   limit_pct  — cpu.max quota expressed as the same % of all CPUs
#
# util_pct approaches limit_pct when the cgroup is fully throttled.
set -euo pipefail

CGROUP="${1:?Usage: cgroup_cpu_util.sh <cgroup_path> <duration_sec> <output_csv>}"
DURATION="${2:?}"
OUTPUT="${3:?}"

NCPUS="$(nproc)"

# Parse cpu.max: "quota_us period_us" or "max period_us"
read -r quota period < "$CGROUP/cpu.max"
if [[ "$quota" == "max" ]]; then
    limit_pct="100.00"
else
    limit_pct="$(awk "BEGIN { printf \"%.2f\", $quota / $period / $NCPUS * 100 }")"
fi

get_usage_usec() {
    awk '/^usage_usec/ { print $2 }' "$CGROUP/cpu.stat"
}

{
    echo "# cgroup: $CGROUP"
    echo "# ncpus: $NCPUS"
    echo "# cpu.max: $quota $period  (limit: ${limit_pct}% of all CPUs)"
    echo "time_s,util_pct,limit_pct"
} > "$OUTPUT"

t=0
prev="$(get_usage_usec)"

while [[ $t -lt $DURATION ]]; do
    sleep 1
    t=$(( t + 1 ))
    curr="$(get_usage_usec)"
    delta=$(( curr - prev ))
    util_pct="$(awk "BEGIN { printf \"%.2f\", $delta / ($NCPUS * 1000000) * 100 }")"
    echo "$t,$util_pct,$limit_pct" >> "$OUTPUT"
    prev="$curr"
done
