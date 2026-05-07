#!/bin/bash
# Reproducer for pcie-error-log stall under scx_lavd --enable-cpu-bw
#
# Root cause hypothesis:
# - pcie-error-log runs in fb-pcie-error-log.service cgroup with cpu.max=100000/100000
# - It's a periodic timer service that sleeps most of the time
# - When it wakes up, it gets a very small slice (slice=1 observed in traces)
# - The accounting_timerfn/replenish_timerfn fail to fetch the root cgroup pointer
#   intermittently, which breaks bandwidth replenishment
# - Without proper replenishment, the task stays "not throttled" but doesn't
#   actually get scheduled, leading to a 30-40s stall that triggers the watchdog
#
# This reproducer simulates a periodic timer-based task in a bandwidth-limited
# cgroup, similar to how pcie-error-log.service behaves.

set -e

BINARY="${1:-/data/users/davidai/scx/target/release/scx_lavd}"
CG=/sys/fs/cgroup/test_pcie_repro
DURATION=${DURATION:-300}
TS=$(date +%Y%m%d-%H%M%S)
LOG=$HOME/claude-tmp/pcie-repro-$TS.log
MARK="PCIE-REPRO-$TS"

cleanup() {
    echo "=== Cleaning up ===" | tee -a $LOG
    pkill -CONT -P $$ 2>/dev/null || true
    sleep 0.2
    pkill -9 -P $$ 2>/dev/null || true
    sleep 1
    rmdir $CG 2>/dev/null || true
    echo "=== dmesg check ===" | tee -a $LOG
    dmesg | grep -E "sched_ext|stall|lavd" | tail -10 | tee -a $LOG
    echo "=== ftrace check ===" | tee -a $LOG
    cat /sys/kernel/tracing/trace | grep -E "pcie-debug|ERROR|stall" | tail -20 | tee -a $LOG
    echo "Log: $LOG" | tee -a $LOG
}
trap cleanup EXIT

mkdir -p $HOME/claude-tmp
exec > >(tee -a $LOG) 2>&1

echo "[$(date +%T)] === PCIE stall reproducer ==="

# Verify lavd is running with --enable-cpu-bw
if ! pgrep -a scx_lavd | grep -q enable-cpu-bw; then
    echo "Starting scx_lavd with --enable-cpu-bw..."
    echo > /sys/kernel/tracing/trace
    nohup $BINARY --performance --slice-min-us 3000 --slice-max-us 10000 --enable-cpu-bw > /tmp/lavd_repro.log 2>&1 &
    LAVD_PID=$!
    sleep 3
    if ! kill -0 $LAVD_PID 2>/dev/null; then
        echo "FATAL: scx_lavd failed to start"
        tail -5 /tmp/lavd_repro.log
        exit 1
    fi
    echo "scx_lavd started (pid=$LAVD_PID)"
else
    echo "scx_lavd already running with --enable-cpu-bw"
fi

echo "$MARK-START" > /dev/kmsg

# Create a cgroup with tight bandwidth (1 CPU, like fb-pcie-error-log.service)
mkdir -p $CG
echo "100000 100000" > $CG/cpu.max
echo "[$(date +%T)] cgroup $CG cpu.max=$(cat $CG/cpu.max)"

# Simulate pcie-error-log behavior:
# - It's a periodic service that runs briefly then sleeps
# - The key pattern is: sleep -> wake -> do brief work -> sleep
# - Use multiple workers doing this pattern to stress the bw accounting
WORKERS=${WORKERS:-10}
echo "[$(date +%T)] Starting $WORKERS periodic workers..."

for i in $(seq 1 $WORKERS); do
    (
        while true; do
            # Brief CPU burst (simulating log collection)
            dd if=/dev/zero of=/dev/null bs=4k count=100 2>/dev/null
            # Sleep for a timer-like interval (100-500ms)
            sleep 0.$(( (RANDOM % 4 + 1) ))
        done
    ) &
    echo $! > $CG/cgroup.procs 2>/dev/null
done

echo "[$(date +%T)] Workers placed in $CG"

# Also add some SIGSTOP/SIGCONT churn like the r3 reproducer
# This targets the refill window race
(
    while true; do
        pkill -STOP -P $$ dd 2>/dev/null || true
        sleep 0.1
        pkill -CONT -P $$ dd 2>/dev/null || true
        sleep 0.1
    done
) &
CHURN_PID=$!

# Monitor for stalls
END=$(( $(date +%s) + DURATION ))
CYCLES=0
while [ $(date +%s) -lt $END ]; do
    sleep 5
    CYCLES=$((CYCLES + 1))

    # Check if lavd is still running
    OPS=$(cat /sys/kernel/sched_ext/root/ops 2>/dev/null || echo "NO_SCHED_EXT")
    if [ "$OPS" = "NO_SCHED_EXT" ]; then
        echo "[$(date +%T)] STALL DETECTED - scheduler exited!"
        echo "[$(date +%T)] Last lavd output:"
        tail -5 /tmp/lavd_repro.log 2>/dev/null || tail -5 /tmp/h6h_nohup.log 2>/dev/null
        echo "[$(date +%T)] Saving trace..."
        cp /sys/kernel/tracing/trace $HOME/claude-tmp/pcie-repro-trace-$TS.txt
        echo "[$(date +%T)] dmesg stall entries:"
        dmesg | grep -E "stall|sched_ext" | tail -5
        break
    fi

    HITS=$(dmesg | grep -c "runnable task stall" 2>/dev/null || echo 0)
    FTRACE_ERRS=$(grep -c "Failed to fetch the root cgroup" /sys/kernel/tracing/trace 2>/dev/null || echo 0)
    echo "[$(date +%T)] check=$CYCLES ops=$OPS stall_hits=$HITS ftrace_errs=$FTRACE_ERRS"
done

echo "$MARK-END" > /dev/kmsg
kill $CHURN_PID 2>/dev/null || true
echo "[$(date +%T)] === Done (cycles=$CYCLES) ==="
