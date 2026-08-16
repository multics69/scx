#!/bin/bash
# scx_cbw_massdeath.sh - reproduce the scx_lavd --enable-cpu-bw stall that shows up
# when many throttled cgroups die at the same time.
#
# Each "generation" creates N tight-quota cgroups, each running M busy single-thread
# workers, and lets them settle long enough to get throttled and parked in their
# per-LLC BTQs. It then kills every worker across all N cgroups in ONE batched SIGKILL
# and removes all N cgroups in a tight burst, so the task exit storm and the cgroup
# exit / BTQ-teardown work (cbw_free_llc_ctx moving parked tasks to the root BTQ) land
# concurrently -- the "lots of cgroups dying at the same time" case. Repeats until
# lavd dies or DUR elapses; on lavd death it captures diagnostics and stops.
#
# CPU-bounded by the sum of quotas (~ N * quota/period CPUs), so it won't starve prod.
# Self-cleans on exit. Requires scx_lavd --enable-cpu-bw to be running.
#
#   usage: scx_cbw_massdeath.sh [N_cgroups] [M_workers] [quota_us] [dur_s] [settle_s] [lavd_pat]
set -u

N=${1:-64}              # cgroups per generation
M=${2:-12}              # busy workers per cgroup
QUOTA=${3:-5000}        # cpu.max quota in us (period is 100000us)
DUR=${4:-2000}          # total run duration in seconds
SETTLE=${5:-3}          # seconds to let a generation get throttled before mass death
LAVD_PAT=${6:-scx_lavd} # process-name pattern used to detect lavd death

R=/sys/fs/cgroup
PFX=cbwmd
PIDS=()                 # workers of the current generation

# Enable the cpu controller on the root subtree so cpu.max works on our cgroups.
grep -qw cpu $R/cgroup.subtree_control 2>/dev/null || \
    echo +cpu > $R/cgroup.subtree_control 2>/dev/null

cleanup() {
    [ ${#PIDS[@]} -gt 0 ] && kill -9 "${PIDS[@]}" 2>/dev/null
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

# True while the scheduler is still attached. scx_lavd's userspace process exits when
# the BPF scheduler aborts (e.g. watchdog stall), so its disappearance is the signal.
lavd_alive() {
    pgrep -f "$LAVD_PAT" >/dev/null 2>&1
}

# Spawn one busy single-thread worker; print its pid.
spawn() {
    bash -c 'while :; do :; done' >/dev/null 2>&1 &
    echo $!
}

# Build one generation: N cgroups x M throttled workers. Records pids in PIDS.
build_generation() {
    PIDS=()
    local i j c p
    for i in $(seq 1 "$N"); do
        c=$R/${PFX}_$i
        mkdir -p "$c" 2>/dev/null || continue
        echo "$QUOTA 100000" > "$c/cpu.max" 2>/dev/null
        for j in $(seq 1 "$M"); do
            p=$(spawn)
            echo "$p" > "$c/cgroup.procs" 2>/dev/null
            PIDS+=("$p")
        done
    done
}

# Kill every worker at once, then race cgroup removal against the exits so the
# cgroup-free work lands while tasks are still exiting/parked.
mass_death() {
    [ ${#PIDS[@]} -gt 0 ] && kill -9 "${PIDS[@]}" 2>/dev/null
    PIDS=()
    local tries=0 left
    while :; do
        left=0
        for d in $R/${PFX}_*; do
            [ -d "$d" ] || continue
            rmdir "$d" 2>/dev/null || left=$((left + 1))
        done
        [ "$left" = 0 ] && break
        tries=$((tries + 1))
        [ "$tries" -ge 50 ] && break   # ~1s cap; stragglers reused next gen / at cleanup
        sleep 0.02
    done
}

# Capture diagnostics when lavd dies, then stop.
capture_and_stop() {
    echo "[massdeath] lavd appears to have died at $(date)"
    echo "[massdeath] --- dmesg tail ---"
    dmesg 2>/dev/null | tail -50
    echo "[massdeath] Also grab the scx_lavd log for the SCX DEBUG DUMP (exit kind 1026)"
    echo "[massdeath] and the stalled task's '\\_ ddsp_dsq_id:' line: 0x8000000000000000"
    echo "[massdeath] is SCX_DSQ_INVALID (normal); any other value confirms the kernel"
    echo "[massdeath] stale direct-dispatch bug (commit 7e0ffb72de8a)."
    exit 1
}

echo "[massdeath] N=$N M=$M quota=$QUOTA/100000us settle=${SETTLE}s dur=${DUR}s start $(date)"

t0=$SECONDS
gen=0
while [ $((SECONDS - t0)) -lt "$DUR" ]; do
    lavd_alive || capture_and_stop
    gen=$((gen + 1))
    build_generation
    sleep "$SETTLE"          # let workers get throttled and parked in BTQs
    lavd_alive || capture_and_stop
    mass_death               # batched SIGKILL + burst rmdir == simultaneous death
    echo "[massdeath] gen=$gen: $N cgroups died $(date +%H:%M:%S)"
done
