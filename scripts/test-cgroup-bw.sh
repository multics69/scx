#!/usr/bin/env bash
# test-cgroup-bw.sh -- two-container cgroup-v2 CPU bandwidth stress test.
#
#   Container A (cbw-tight): cpu.max = 2 CPUs, 4 compute threads.
#   Container B (cbw-loose): cpu.max = 20 CPUs, 40 compute threads.
#
# In each container, thread #0 keeps calling sched_setaffinity() on itself
# with a random CPU so the scheduler has to migrate it constantly. All other
# threads sit in a tight integer loop.
#
# Requires: podman or docker; gcc with static libc.
#   Fedora:    sudo dnf install podman gcc glibc-static
#   Ubuntu:    sudo apt install docker.io build-essential
#   Arch:      sudo pacman -S docker gcc
# Cgroup v2 is the default on Fedora 31+, Ubuntu 22.04+, and Arch.

set -euo pipefail

NAME_TIGHT="cbw-tight"
NAME_LOOSE="cbw-loose"
IMAGE="${IMAGE:-ubuntu:24.04}"
INTERVAL="${INTERVAL:-5}"
TIGHT_CPUS="${TIGHT_CPUS:-2}"
LOOSE_CPUS="${LOOSE_CPUS:-20}"
TIGHT_THREADS="${TIGHT_THREADS:-$((TIGHT_CPUS * 2))}"
LOOSE_THREADS="${LOOSE_THREADS:-$((LOOSE_CPUS * 2))}"

# Pick a container runtime: podman is the Fedora default, docker is the Ubuntu default.
CONTAINER_CMD="${CONTAINER_CMD:-}"
if [[ -z "$CONTAINER_CMD" ]]; then
	for cmd in podman docker; do
		if command -v "$cmd" >/dev/null 2>&1; then
			CONTAINER_CMD="$cmd"
			break
		fi
	done
fi
if [[ -z "$CONTAINER_CMD" ]]; then
	echo "error: neither podman nor docker found" >&2
	echo "  Fedora: sudo dnf install podman" >&2
	echo "  Ubuntu: sudo apt install docker.io" >&2
	echo "  Arch:   sudo pacman -S docker" >&2
	exit 1
fi

if ! $CONTAINER_CMD info >/dev/null 2>&1; then
	echo "error: $CONTAINER_CMD daemon not reachable" >&2
	echo "  start it: sudo systemctl enable --now docker" >&2
	echo "  (or add yourself to the 'docker' group and re-login)" >&2
	exit 1
fi

WORK_DIR="$(mktemp -d -t cbw-test-XXXXXX)"
cleanup() {
	set +e
	$CONTAINER_CMD rm -f "$NAME_TIGHT" "$NAME_LOOSE" >/dev/null 2>&1
	rm -rf "$WORK_DIR"
}
trap cleanup EXIT INT TERM

if ! command -v gcc >/dev/null 2>&1; then
	echo "error: gcc not found" >&2
	echo "  Fedora: sudo dnf install gcc glibc-static" >&2
	echo "  Ubuntu: sudo apt install build-essential" >&2
	echo "  Arch:   sudo pacman -S gcc" >&2
	exit 1
fi

cat > "$WORK_DIR/busy.c" <<'EOF'
/*
 * busy.c -- N pthreads in a tight compute loop; thread 0 churns its own
 * CPU affinity at random.
 *
 *   usage: busy <n_threads>
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>

static long ncpus;

static void *busy(void *arg)
{
	long id = (long)(intptr_t)arg;
	unsigned int seed = (unsigned int)(id ^ getpid() ^ (unsigned)time(NULL));
	pid_t tid = (pid_t)syscall(SYS_gettid);
	unsigned long iters = 0;
	volatile unsigned long x = (unsigned long)id + 1;
	cpu_set_t set;

	for (;;) {
		x = x * 1103515245UL + 12345UL;
		if (id == 0 && (++iters & ((1UL << 22) - 1)) == 0) {
			int cpu = (int)((unsigned)rand_r(&seed) % (unsigned)ncpus);
			CPU_ZERO(&set);
			CPU_SET(cpu, &set);
			(void)sched_setaffinity(tid, sizeof(set), &set);
		}
	}
	return NULL;
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "usage: %s n_threads\n", argv[0]);
		return 1;
	}
	int n = atoi(argv[1]);
	if (n <= 0) {
		fprintf(stderr, "n_threads must be positive\n");
		return 1;
	}
	ncpus = sysconf(_SC_NPROCESSORS_ONLN);
	fprintf(stderr, "busy: %d threads, %ld CPUs visible, pid %d\n",
		n, ncpus, getpid());
	pthread_t *ts = calloc((size_t)n, sizeof(*ts));
	if (!ts) {
		perror("calloc");
		return 1;
	}
	for (long i = 0; i < n; i++) {
		if (pthread_create(&ts[i], NULL, busy, (void *)(intptr_t)i) != 0) {
			perror("pthread_create");
			return 1;
		}
	}
	for (int i = 0; i < n; i++)
		pthread_join(ts[i], NULL);
	return 0;
}
EOF

echo "compiling busy ..."
gcc -O2 -pthread -static -o "$WORK_DIR/busy" "$WORK_DIR/busy.c"

echo "pulling $IMAGE ..."
$CONTAINER_CMD pull "$IMAGE" >/dev/null

start_one() {
	local name="$1" cpus="$2" threads="$3"
	$CONTAINER_CMD rm -f "$name" >/dev/null 2>&1 || true
	$CONTAINER_CMD run -d --rm --name "$name" \
		--cpus="$cpus" \
		-v "$WORK_DIR":/work:ro \
		"$IMAGE" /work/busy "$threads" >/dev/null
	echo "started $name on $CONTAINER_CMD: --cpus=$cpus, threads=$threads"
}

start_one "$NAME_TIGHT" "$TIGHT_CPUS" "$TIGHT_THREADS"
start_one "$NAME_LOOSE" "$LOOSE_CPUS" "$LOOSE_THREADS"

echo
echo "running. ^C to stop. polling cpu.stat every ${INTERVAL}s ..."
echo

while true; do
	sleep "$INTERVAL"
	printf -- "--- %(%Y-%m-%d %H:%M:%S)T ---\n" -1
	for name in "$NAME_TIGHT" "$NAME_LOOSE"; do
		printf "[%s] pids.current=%s\n" "$name" \
			"$($CONTAINER_CMD exec "$name" cat /sys/fs/cgroup/pids.current 2>/dev/null || echo '?')"
		$CONTAINER_CMD exec "$name" cat /sys/fs/cgroup/cpu.stat 2>/dev/null \
			| sed 's/^/  /'
	done
done
