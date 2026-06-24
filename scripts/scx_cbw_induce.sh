#!/bin/bash
# Induce cbw throttling + cgroup churn to exercise scx_lavd --enable-cpu-bw stall path.
# Level-1 throttled cgroups (direct children of /sys/fs/cgroup), busy single-thread
# workers, NO affinity churn (let lavd migrate across LLCs). Churn = cgroup
# create/destroy + move workers BETWEEN groups (per user direction). CPU-bounded by the
# sum of quotas, so it won't starve prod. Self-cleans on exit.
#   usage: scx_cbw_induce.sh [N_cgroups] [M_workers] [quota_us] [dur_s] [churn 0/1] [ramp_s]
set -u

N=${1:-64}        # number of cgroups
M=${2:-12}        # busy workers per cgroup
QUOTA=${3:-5000}  # cpu.max quota in us (period is 100000us)
DUR=${4:-2000}    # run duration in seconds
CHURN=${5:-1}     # enable cgroup/worker churn (0/1)
RAMP=${6:-0}      # per-worker/per-cgroup ramp delay in seconds (0 = no ramp)

R=/sys/fs/cgroup
PFX=cbwtest

# Enable the cpu controller on the root subtree so cpu.max works on our cgroups.
grep -qw cpu $R/cgroup.subtree_control 2>/dev/null || \
    echo +cpu > $R/cgroup.subtree_control 2>/dev/null

cleanup() {
    for d in $R/${PFX}_*; do
        [ -d "$d" ] || continue
        for p in $(cat "$d/cgroup.procs" 2>/dev/null); do
            kill -9 "$p" 2>/dev/null
        done
    done
    sleep 0.3
    for d in $R/${PFX}_*; do
        rmdir "$d" 2>/dev/null
    done
}
trap 'cleanup; exit' TERM INT EXIT

# Spawn one busy single-thread worker; print its pid.
spawn() {
    bash -c 'while :; do :; done' >/dev/null 2>&1 &
    echo $!
}

# Create cgroup $1 with QUOTA and M busy workers.
mkcg() {
    local c=$R/${PFX}_$1 j p
    mkdir -p "$c" 2>/dev/null || return 1
    echo "$QUOTA 100000" > "$c/cpu.max" 2>/dev/null
    for j in $(seq 1 "$M"); do
        p=$(spawn)
        echo "$p" > "$c/cgroup.procs" 2>/dev/null
        # gradual ramp: avoid startup thundering-herd stall
        [ "$RAMP" != 0 ] && sleep "$RAMP"
    done
}

# Initial population.
for i in $(seq 1 "$N"); do
    mkcg "$i"
    [ "$RAMP" != 0 ] && sleep "$RAMP"
done

echo "[induce] $N cgroups x $M workers quota=$QUOTA/100000us churn=$CHURN ramp=$RAMP start $(date)"

lo=1
hi=$N
t0=$SECONDS
while [ $((SECONDS - t0)) -lt "$DUR" ]; do
    if [ "$CHURN" = 1 ]; then
        # Move up to 3 workers between two random live cgroups.
        span=$((hi - lo + 1))
        x=$((lo + RANDOM % span))
        y=$((lo + RANDOM % span))
        A=$R/${PFX}_$x
        B=$R/${PFX}_$y
        if [ -d "$A" ] && [ -d "$B" ] && [ "$x" != "$y" ]; then
            for p in $(head -3 "$A/cgroup.procs" 2>/dev/null); do
                echo "$p" > "$B/cgroup.procs" 2>/dev/null
            done
        fi

        # Destroy the oldest cgroup, then create a fresh one at the top.
        D=$R/${PFX}_$lo
        if [ -d "$D" ]; then
            for p in $(cat "$D/cgroup.procs" 2>/dev/null); do
                kill -9 "$p" 2>/dev/null
            done
            sleep 0.2
            rmdir "$D" 2>/dev/null
        fi
        lo=$((lo + 1))
        hi=$((hi + 1))
        mkcg "$hi"
    fi
    sleep 1
done
