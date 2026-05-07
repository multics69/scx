#!/bin/bash
# R3: Sleep/wake churn at the bw refresh boundary (targets H2 refill/wakeup race).
# Moderate cgroup bw; SIGSTOP/SIGCONT cycles at ~bw period to maximize the chance
# of an enqueue landing in the refill window.
set -e

CG=/sys/fs/cgroup/test_bw_stop
WORKERS=${WORKERS:-100}
DURATION=${DURATION:-180}
PERIOD_MS=${PERIOD_MS:-150}
TS=$(date +%Y%m%d-%H%M%S)
LOG=$HOME/claude-tmp/r3-stop-bw-$TS.log
DMESG_POST=$HOME/claude-tmp/r3-stop-bw-$TS.dmesg.post
MARK="R3-STOP-BW-$TS"

cleanup() {
    echo "=== Cleaning up ===" | tee -a $LOG
    # CONT first — pkill -9 on a STOPPED group hangs.
    pkill -CONT -P $$ yes 2>/dev/null || true
    sleep 0.2
    pkill -9 -P $$ yes 2>/dev/null || true
    sleep 1
    rmdir $CG 2>/dev/null || true
    dmesg > $DMESG_POST
    echo "=== Stall hits in window ===" | tee -a $LOG
    awk "/$MARK-START/,/$MARK-END/" $DMESG_POST | grep -E "scx|sched_ext|stall|BUG|WARN" | tee -a $LOG || true
    echo "Logs: $LOG  $DMESG_POST" | tee -a $LOG
}
trap cleanup EXIT

mkdir -p $HOME/claude-tmp
exec > >(tee -a $LOG) 2>&1

echo "[$(date +%T)] === R3 stop/cont churn reproducer ==="
pgrep -a scx_lavd || { echo "WARN: scx_lavd not running"; }

echo "$MARK-START" > /dev/kmsg

mkdir -p $CG
echo "200000 100000" > $CG/cpu.max  # 2 CPU equiv
echo "[$(date +%T)] cgroup $CG cpu.max=$(cat $CG/cpu.max)"

# `yes > /dev/null` is a tight CPU loop that ignores SIGSTOP gracefully and
# has no internal completion counter (unlike stress-ng, which interprets STOP
# cycles as completed bogo-ops and exits).
declare -a YES_PIDS
for i in $(seq 1 $WORKERS); do
    yes >/dev/null &
    YES_PIDS[$i]=$!
done
sleep 1
COUNT=0
for pid in "${YES_PIDS[@]}"; do
    if echo $pid > $CG/cgroup.procs 2>/dev/null; then
        COUNT=$((COUNT + 1))
    fi
done
echo "[$(date +%T)] $COUNT workers placed in $CG (comm=yes)"

# 0.PERIOD_MS — bash decimal sleep.
PERIOD=$(printf "0.%03d" $PERIOD_MS)
END=$(( $(date +%s) + DURATION ))
CYCLES=0
while [ $(date +%s) -lt $END ]; do
    # Send signals only to our `yes` workers, identified by ppid being this script.
    pkill -STOP -P $$ yes 2>/dev/null || true
    sleep $PERIOD
    pkill -CONT -P $$ yes 2>/dev/null || true
    sleep $PERIOD
    CYCLES=$((CYCLES + 1))
    if (( CYCLES % 50 == 0 )); then
        HITS=$(dmesg | awk "/$MARK-START/,0" | grep -c "runnable task stall" || true)
        ALIVE=$(pgrep -c -P $$ yes 2>/dev/null || echo 0)
        echo "[$(date +%T)] cycles=$CYCLES stall_hits=$HITS alive_yes=$ALIVE"
    fi
done

echo "$MARK-END" > /dev/kmsg
echo "[$(date +%T)] === Test window closed (cycles=$CYCLES) ==="
