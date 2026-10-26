/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 * Author: Changwoo Min <changwoo@igalia.com>
 */

/*
 * The queues lavd holds tasks in: one steady and one turbulent queue per
 * compute domain, and one queue per core when per-CPU queues are in use. Each
 * is a CTQ. Callers identify a queue by a DSQ-style 64-bit id (cpdom_to_dsq()
 * and friends), and every operation on the queues goes through here.
 */
#include <scx/common.bpf.h>
#include <bpf_arena_common.bpf.h>
#include <lib/arena_map.h>
#include "intf.h"
#include "lavd.bpf.h"
#include "util.bpf.h"
#include "queue.bpf.h"
#include <errno.h>
#include <stdbool.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* set by userspace for SCX_OPS_TID_TO_TASK, see lib/ctq.bpf.c */
extern const volatile bool ctq_tid_to_task;

/*
 * The CTQs by id: the per-CPU ones by primary CPU id, sized by nr_cpu_ids,
 * and the steady and turbulent ones by compute domain id, sized by nr_cpdoms.
 * A table is NULL if lavd's options do not use its queues, and an entry is
 * NULL if its queue does not exist. See queue_lib_init() for where the queues
 * live.
 */
static struct ctq __arena * __arena *queue_cpu_ctqs;
static struct ctq __arena * __arena *queue_cpdom_ctqs;
static struct ctq __arena * __arena *queue_turb_ctqs;

/*
 * The CTQ of @dsq_id, or NULL if lavd did not create it. A program may touch
 * arena memory only if it references the arena, and a program can reach the
 * queues with no other arena access, so reference it here.
 */
static __always_inline
struct ctq __arena *queue_ctq(u64 dsq_id)
{
	u32 id = dsq_id & LAVD_DSQ_ID_MASK;
	struct ctq __arena * __arena *tbl;
	u32 nr;

	scx_arena_subprog_init();

	switch (dsq_type(dsq_id)) {
	case LAVD_DSQ_TYPE_CPU:
		tbl = queue_cpu_ctqs;
		nr = nr_cpu_ids;
		break;
	case LAVD_DSQ_TYPE_CPDOM:
		tbl = queue_cpdom_ctqs;
		nr = nr_cpdoms;
		break;
	case LAVD_DSQ_TYPE_CPDOM_TURB:
		tbl = queue_turb_ctqs;
		nr = nr_cpdoms;
		break;
	default:
		return NULL;
	}

	return tbl && id < nr ? tbl[id] : NULL;
}

static __always_inline
task_ctx *queue_node_task_ctx(struct ctq_node __arena *n)
{
	return (task_ctx *)((u64)n - offsetof(struct task_ctx, ctq));
}

/*
 * Allocate the tables lavd's options use as one, all NULL, to share pages and
 * cache lines: the steady and turbulent tables first, then the per-CPU one.
 */
static
int queue_alloc_tables(void)
{
	u32 nr_cpdom = use_cpdom_dsq() ? nr_cpdoms : 0;
	u32 nr_cpu = use_per_cpu_dsq() ? nr_cpu_ids : 0;
	u32 nr = 2 * nr_cpdom + nr_cpu, pages, i;
	struct ctq __arena * __arena *tbl;

	if (!nr)
		return 0;

	pages = div_round_up(nr * sizeof(*tbl), PAGE_SIZE);
	tbl = bpf_arena_alloc_pages(&arena, NULL, pages, NUMA_NO_NODE, 0);
	if (unlikely(!tbl))
		return -ENOMEM;

	bpf_for(i, 0, nr)
		WRITE_ONCE(tbl[i], NULL);

	if (nr_cpdom) {
		queue_cpdom_ctqs = tbl;
		queue_turb_ctqs = tbl + nr_cpdom;
	}
	if (nr_cpu)
		queue_cpu_ctqs = tbl + 2 * nr_cpdom;

	return 0;
}

/* @nr CTQs in whole pages, cache-line aligned, on NUMA domain @numa. */
static
struct ctq __arena *queue_alloc_ctqs(u32 nr, s32 numa)
{
	u32 pages = div_round_up(nr * sizeof(struct ctq), PAGE_SIZE);
	struct ctq __arena *ctqs;
	u32 i;

	ctqs = bpf_arena_alloc_pages(&arena, NULL, pages, numa, 0);
	if (unlikely(!ctqs))
		return NULL;

	bpf_for(i, 0, nr) {
		if (ctq_init(&ctqs[i]))
			return NULL;
	}

	return ctqs;
}

/* The NUMA domain of compute domain @id, or -ENOENT if it is unused. */
static
s32 queue_cpdom_numa(u64 id)
{
	struct cpdom_ctx *cpdomc = MEMBER_VPTR(cpdom_ctxs, [id]);

	return cpdomc && cpdomc->is_valid ? cpdomc->numa_id : -ENOENT;
}

/*
 * Place the queues of NUMA domain @numa in @ctqs, one after another, and
 * return how many there are. With @ctqs NULL, only count them.
 *
 * Its queues are the steady and turbulent queues of its compute domains, and
 * the per-CPU queues of its primary CPUs. cpu_to_dsq() names only primary
 * CPUs, so the other SMT siblings get none.
 *
 * Global, so that the verifier checks it once on its own. Inlined, the count
 * it returns sizes an allocation, which makes the verifier track it exactly
 * and walk its loops once per possible value.
 */
__weak
u32 queue_place_numa(s32 numa, struct ctq __arena *ctqs __arg_arena)
{
	struct cpu_ctx *cpuc;
	u32 id, cpu, nr = 0;

	if (use_cpdom_dsq()) {
		bpf_for(id, 0, nr_cpdoms) {
			if (queue_cpdom_numa(id) != numa)
				continue;
			if (ctqs) {
				queue_cpdom_ctqs[id] = &ctqs[nr];
				queue_turb_ctqs[id] = &ctqs[nr + 1];
			}
			nr += 2;
		}
	}

	if (use_per_cpu_dsq()) {
		bpf_for(cpu, 0, nr_cpu_ids) {
			cpuc = get_cpu_ctx_id(cpu);
			if (!cpuc || get_primary_cpu(cpu) != cpu ||
			    queue_cpdom_numa(cpuc->cpdom_id) != numa)
				continue;
			if (ctqs)
				queue_cpu_ctqs[cpu] = &ctqs[nr];
			nr++;
		}
	}

	return nr;
}

/*
 * Create the queues lavd's options use, after the compute domains are set up.
 * As in cid_idle, the queues of each NUMA domain share one allocation in
 * that domain: count them, allocate, then place them in the tables.
 */
__hidden
int queue_lib_init(void)
{
	struct ctq __arena *ctqs;
	s32 numa, nr_numas = 0;
	u32 id, nr;
	int err;

	err = ctq_lib_init();
	if (unlikely(err))
		return err;

	err = queue_alloc_tables();
	if (unlikely(err))
		return err;

	bpf_for(id, 0, nr_cpdoms) {
		numa = queue_cpdom_numa(id);
		if (numa >= nr_numas)
			nr_numas = numa + 1;
	}

	bpf_for(numa, 0, nr_numas) {
		nr = queue_place_numa(numa, NULL);
		if (!nr)
			continue;

		ctqs = queue_alloc_ctqs(nr, numa);
		if (unlikely(!ctqs))
			return -ENOMEM;

		queue_place_numa(numa, ctqs);
	}

	return 0;
}

/*
 * An online CPU that the task of @n may run on, in the compute domain of its
 * queue, or -ENOENT. Only for a report whose chosen CPU and task_cpu() are
 * both offline, see queue_reserve_cpu(), so look the task up for its mask.
 * cpdom_cpumask holds the CPUs lavd sees online.
 */
static __noinline
s32 queue_pick_online_cpu(struct ctq_node __arena *n, task_ctx *taskc)
{
	const struct task_struct *q;
	struct bpf_cpumask *cd_mask;
	struct task_struct *p;
	s32 cpu = -ENOENT;

	cd_mask = MEMBER_VPTR(cpdom_cpumask, [taskc->cpdom_id]);
	if (!cd_mask)
		return -ENOENT;

	if (ctq_tid_to_task) {
		p = scx_bpf_tid_to_task(n->tid);
		if (p)
			cpu = bpf_cpumask_any_and_distribute(cast_mask(cd_mask),
							     p->cpus_ptr);
	} else {
		/* A pid can be reused, so check the task is the queued one. */
		q = bpf_core_cast((void *)n->task, struct task_struct);
		p = bpf_task_from_pid(q->pid);
		if (!p)
			return -ENOENT;
		if ((u64)p == n->task)
			cpu = bpf_cpumask_any_and_distribute(cast_mask(cd_mask),
							     p->cpus_ptr);
		bpf_task_release(p);
	}

	return cpu >= 0 && cpu < nr_cpu_ids ? cpu : -ENOENT;
}

/*
 * Give up @taskc's CPU reservation, if it holds one. Most tasks hold none, so
 * test before the atomic. The test can miss a reservation made concurrently,
 * which then stays until the task's next release (see queue_reserve_cpu()).
 */
static __always_inline
void queue_release_cpu(task_ctx *taskc)
{
	struct cpu_ctx *cpuc;
	s32 cpu;

	if (likely(READ_ONCE(taskc->resv_cpu_id) < 0))
		return;

	cpu = __sync_lock_test_and_set(&taskc->resv_cpu_id, -ENOENT);
	if (unlikely(cpu < 0))
		return;

	cpuc = get_cpu_ctx_id(cpu);
	if (likely(cpuc))
		__sync_fetch_and_sub(&cpuc->nr_resv_tasks, 1);
}

/* Make @cpu @taskc's reservation, replacing the one it holds, if any. */
static __always_inline
void queue_hold_cpu(task_ctx *taskc, struct cpu_ctx *cpuc, s32 cpu)
{
	struct cpu_ctx *held_cpuc;
	s32 held;

	/* Count first, so that a release never underflows the count. */
	__sync_fetch_and_add(&cpuc->nr_resv_tasks, 1);
	held = __sync_lock_test_and_set(&taskc->resv_cpu_id, cpu);
	if (unlikely(held >= 0) && (held_cpuc = get_cpu_ctx_id(held)))
		__sync_fetch_and_sub(&held_cpuc->nr_resv_tasks, 1);
}

static __always_inline
int queue_link(struct task_struct *p, task_ctx *taskc, u64 dsq_id, u64 vtime,
	       bool parked)
{
	struct ctq __arena *q = queue_ctq(dsq_id);
	int ret;

	if (unlikely(!q)) {
		scx_bpf_error("no queue for DSQ id 0x%llx", dsq_id);
		return -ENOENT;
	}

	/* Drop a reservation left by an earlier enqueue. */
	queue_release_cpu(taskc);

	if (unlikely(parked))
		ret = ctq_insert_parked(q, p, &taskc->ctq, vtime);
	else
		ret = ctq_insert(q, p, &taskc->ctq, vtime);

	/*
	 * ops.enqueue() dispatches a task in flight directly, and a task in
	 * flight is never parked, so only a cancelled move is expected.
	 */
	if (unlikely(ret && ret != CTQ_ERR_PARK_CANCELLED))
		scx_bpf_error("failed to queue pid %d: %d", p->pid, ret);
	return ret;
}

/* Returns 0 if @p was queued. */
__hidden
int queue_insert_vtime(struct task_struct *p, task_ctx __arg_arena *taskc,
		       u64 dsq_id, u64 vtime)
{
	return queue_link(p, taskc, dsq_id, vtime, false);
}

/*
 * Insert a task moved in from a queue it was parked in, such as a BTQ.
 * Returns 0 if @p was queued, and CTQ_ERR_PARK_CANCELLED if its dequeue
 * cancelled the move, in which case the caller drops it.
 */
__hidden
int queue_insert_vtime_parked(struct task_struct *p,
			      task_ctx __arg_arena *taskc, u64 dsq_id,
			      u64 vtime)
{
	return queue_link(p, taskc, dsq_id, vtime, true);
}

/*
 * A consume reports each task it walks past, once per enqueue: a task the
 * consuming CPU may not run. A CPU outside the active and overflow sets does
 * not consume, so a reported task needs a CPU that does and may run it.
 *
 * Reserve the CPU its enqueue chose, which lies in its mask and consumes its
 * queue, until it runs or leaves the queue. The reservation keeps the CPU in
 * the overflow set (see power.bpf.c), and a kick brings it in if it is idle.
 * A snapshot of the active and overflow sets would not do: they may shrink
 * before the task runs, and no later walk reports it again.
 *
 * The task's CPU releases the reservation in ops.running() or ops.dequeue(),
 * after the task has left the queue. A report can race with that, so the
 * reserving CPU checks the node is still queued after publishing the
 * reservation and otherwise releases it itself. The release tests for a
 * reservation without ordering the test after the removal, so both can miss
 * the other. The reservation then outlives the enqueue and keeps the CPU in
 * the overflow set until the task's next insert, run, dequeue or exit
 * releases it.
 *
 * The kernel tracks a queued task only on its own CPU, task_cpu(), so the
 * CPU its enqueue chose can go offline with the task queued and holding a
 * reservation. queue_cpu_offline() has the queues report their tasks again,
 * and a report of a task whose chosen CPU is offline reserves task_cpu()
 * instead. task_cpu() lies in the task's mask and holds while the task is
 * queued, since the kernel dequeues a task before moving it, also off a CPU
 * going offline.
 *
 * Kernels without d35a535d3e3e ("sched_ext: Fix CPU hotplug hang when a dying
 * CPU's tasks sit in the BPF scheduler") leave the task on the CPU going
 * offline and wait for the BPF scheduler to move it, so task_cpu() can be
 * offline too. Then reserve an online CPU of the task's mask in its compute
 * domain. A pinned or migration-disabled task has none and is left to the
 * kernel.
 *
 * The CPU picked is not checked for being online. If it is offline, or goes
 * offline later, its queue_cpu_offline() advances the report generation. A
 * walk then reports the task again, and the report comes back here and picks
 * again from the CPUs then online.
 */
__weak
int queue_reserve_cpu(struct ctq_node __arena *n __arg_arena)
{
	task_ctx *taskc = queue_node_task_ctx(n);
	struct bpf_cpumask *active, *ovrflw;
	const struct task_struct *p;
	struct cpu_ctx *cpuc;
	s32 cpu;

	cpu = READ_ONCE(n->forced_id);
	if (likely(cpu < 0))
		cpu = READ_ONCE(taskc->suggested_cpu_id);

	cpuc = get_cpu_ctx_id(cpu);
	if (unlikely(!cpuc))
		return 0;

	queue_hold_cpu(taskc, cpuc, cpu);

	/*
	 * The exchange in queue_hold_cpu() orders the walk's read of the
	 * report generation before this read, so a report made after a CPU
	 * went offline sees it offline. See queue_cpu_offline().
	 */
	if (unlikely(!READ_ONCE(cpuc->is_online))) {
		p = bpf_core_cast((void *)n->task, struct task_struct);
		cpu = p->thread_info.cpu;
		cpuc = get_cpu_ctx_id(cpu);
		if (unlikely(cpuc && !READ_ONCE(cpuc->is_online))) {
			/* Not checked for being online, see above. */
			cpu = queue_pick_online_cpu(n, taskc);
			cpuc = get_cpu_ctx_id(cpu);
		}
		if (unlikely(!cpuc)) {
			queue_release_cpu(taskc);
			return 0;
		}
		queue_hold_cpu(taskc, cpuc, cpu);
	}

	if (unlikely(!READ_ONCE(n->ctq))) {
		queue_release_cpu(taskc);
		return 0;
	}

	bpf_rcu_read_lock();
	active = active_cpumask;
	ovrflw = ovrflw_cpumask;
	if (active && ovrflw && !bpf_cpumask_test_cpu(cpu, cast_mask(active)))
		ovrflw_test_and_set(ovrflw, cpu);
	bpf_rcu_read_unlock();

	scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
	return 0;
}

/*
 * This CPU's earlier ops.dispatch() calls have been flushed, which ends the
 * DISPATCHING state of the tasks they consumed. See ctq_cpu_flushed().
 */
__hidden
void queue_cpu_flushed(void)
{
	scx_arena_subprog_init();
	ctq_cpu_flushed();
}

/*
 * @cpu went offline, after cpu_ctx_init_offline() marked it so. Have the
 * queues report their tasks again, and kick the online CPUs so that their
 * walks run. ctq_cpu_offline() orders the mark before the reports. See
 * queue_reserve_cpu().
 */
__hidden
void queue_cpu_offline(s32 cpu)
{
	struct cpu_ctx *cpuc;
	u32 i;

	ctq_cpu_offline(cpu);

	bpf_for(i, 0, nr_cpu_ids) {
		cpuc = get_cpu_ctx_id(i);
		if (i != cpu && cpuc && READ_ONCE(cpuc->is_online))
			scx_bpf_kick_cpu(i, SCX_KICK_IDLE);
	}
}

/*
 * Move the first task @cpu may run from @dsq_id to @cpu's local DSQ, and
 * reserve CPUs for the tasks walked past. Returns false if nothing was moved
 * to @cpu: no task may run on @cpu, the one picked has left meanwhile, or it
 * is migration-disabled on another CPU and went there. If it left, its next
 * enqueue kicks a CPU for it.
 */
__weak
bool queue_move_to_local(u64 dsq_id, s32 cpu, u64 enq_flags)
{
	const struct ctq_consume_res __arena *res;
	struct ctq_node __arena *n;
	struct ctq __arena *q;
	int i;

	q = queue_ctq(dsq_id);
	if (unlikely(!q))
		return false;

	res = ctq_move_to_local(q, cpu, enq_flags);
	if (unlikely(!res))
		return false;

	for (i = 0; i < CTQ_MAX_REPORTS; i++) {
		n = res->reports[i];
		if (!n)
			break;
		queue_reserve_cpu(n);
	}

	return res->picked;
}

__hidden
s32 queue_nr_queued(u64 dsq_id)
{
	struct ctq __arena *q = queue_ctq(dsq_id);

	return q ? ctq_nr_queued(q) : 0;
}

/* The head task's vtime, or U64_MAX if the queue is empty. */
__hidden
u64 queue_peek_vtime(u64 dsq_id)
{
	struct ctq __arena *q = queue_ctq(dsq_id);
	u64 vtime;

	if (!q || ctq_peek_key(q, &vtime))
		return U64_MAX;
	return vtime;
}

/* The head task's load, or 0 if the queue is empty. */
u64 __attribute__((noinline)) queue_peek_load(u64 dsq_id)
{
	struct ctq __arena *q = queue_ctq(dsq_id);
	struct ctq_node __arena *n;

	if (!q || !(n = ctq_peek(q)))
		return 0;
	return task_load_metric(queue_node_task_ctx(n));
}

/* Called after a fork copies the parent's context. */
__hidden
void queue_task_init(task_ctx __arg_arena *taskc)
{
	ctq_task_init(&taskc->ctq);
	WRITE_ONCE(taskc->resv_cpu_id, -ENOENT);
}

__hidden
void queue_task_fini(task_ctx __arg_arena *taskc)
{
	ctq_task_fini(&taskc->ctq);
	queue_release_cpu(taskc);
}

__hidden
bool queue_task_in_flight(task_ctx __arg_arena *taskc)
{
	return ctq_task_dispatching(&taskc->ctq) ||
	       (enable_cpu_bw && READ_ONCE(taskc->atq.common.holdcnt));
}

/* Called before parking a task in a BTQ. */
__hidden
void queue_task_park(task_ctx __arg_arena *taskc)
{
	ctq_task_park(&taskc->ctq);
}

__hidden
void queue_task_running(task_ctx __arg_arena *taskc)
{
	ctq_task_running(&taskc->ctq);
	queue_release_cpu(taskc);
}

__hidden
void queue_task_dequeue(task_ctx __arg_arena *taskc)
{
	ctq_remove(&taskc->ctq);
	queue_release_cpu(taskc);
}

/*
 * Name the queue @q in @type and @id: "cpu", "cpdom" or "turb", or "?" if it
 * is none of lavd's.
 */
static void queue_name(struct ctq __arena *q, const char **type, s32 *id)
{
	s32 i;

	*type = "?";
	*id = -1;
	bpf_for(i, 0, nr_cpdoms) {
		if (queue_cpdom_ctqs && queue_cpdom_ctqs[i] == q) {
			*type = "cpdom";
			*id = i;
			return;
		}
		if (queue_turb_ctqs && queue_turb_ctqs[i] == q) {
			*type = "turb";
			*id = i;
			return;
		}
	}
	bpf_for(i, 0, nr_cpu_ids) {
		if (queue_cpu_ctqs && queue_cpu_ctqs[i] == q) {
			*type = "cpu";
			*id = i;
			return;
		}
	}
}

/*
 * Where @taskc's task is in lavd's queues. A QUEUED task in no queue whose
 * node is not DISPATCHING is in BPF custody but nowhere a CPU can find it.
 */
__hidden
void queue_dump_task(task_ctx __arg_arena *taskc)
{
	struct ctq_node __arena *n = &taskc->ctq;
	struct ctq __arena *q = READ_ONCE(n->ctq);
	const char *type = "none";
	s32 id = -1, pop_cpu = n->pop_cpu;

	scx_arena_subprog_init();

	if (q)
		queue_name(q, &type, &id);

	scx_bpf_dump("  \\_ queue: %s[%d]   node flags: 0x%x   park: %u   forced: %d   resv_cpu: %d\n",
		     type, id, n->flags, n->park, n->forced_id,
		     READ_ONCE(taskc->resv_cpu_id));
	scx_bpf_dump("  \\_ pop_cpu: %d   pop_round: %llu   pop_cpu round now: 0x%llx\n",
		     pop_cpu, n->pop_round, ctq_cpu_round(pop_cpu));
}

/* How many tasks each queue of compute domain @cpdom_id holds. */
__hidden
void queue_dump_cpdom(u64 cpdom_id)
{
	scx_bpf_dump("  steady: %d   turb: %d\n",
		     queue_nr_queued(cpdom_to_dsq(cpdom_id)),
		     queue_nr_queued(cpdom_to_turb_dsq(cpdom_id)));
}
