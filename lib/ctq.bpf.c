/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 * Author: Changwoo Min <changwoo@igalia.com>
 */
#include <scx/common.bpf.h>
#include <bpf/bpf_core_read.h>
#include <lib/sdt_task.h>
#include <lib/spinlock.h>
#include <lib/ctq.h>

extern const volatile u32 nr_cpu_ids;

/* set by userspace when the scheduler enables SCX_OPS_TID_TO_TASK (v7.2+) */
const volatile bool ctq_tid_to_task;

/* the state of each CPU, one cache line each */
struct ctq_cpu {
	/* the dispatch round, see ctq_cpu_flushed() */
	u64			round;
	/* the result of the CPU's last consume */
	struct ctq_consume_res	res;
} __attribute__((aligned(SCX_CACHELINE_SIZE)));

_Static_assert(sizeof(struct ctq_cpu) == SCX_CACHELINE_SIZE,
	       "ctq_cpu must be one cache line");

static struct ctq_cpu __arena *ctq_cpus;

__weak
int ctq_lib_init(void)
{
	ctq_cpus = scx_static_alloc(nr_cpu_ids * sizeof(*ctq_cpus),
				    SCX_CACHELINE_SIZE);
	return ctq_cpus ? 0 : -ENOMEM;
}

__weak
int ctq_init(struct ctq __arena *q __arg_arena)
{
	WRITE_ONCE(q->lock.val.counter, 0);

	return rb_init(&q->tree, RB_NOALLOC, RB_DUPLICATE);
}

__weak
int ctq_task_init(struct ctq_node __arena *n __arg_arena)
{
	WRITE_ONCE(n->ctq, NULL);
	WRITE_ONCE(n->flags, 0);
	WRITE_ONCE(n->park, CTQ_PARK_NONE);
	WRITE_ONCE(n->forced_id, -1);
	WRITE_ONCE(n->pop_cpu, -1);
	WRITE_ONCE(n->task, 0);
	WRITE_ONCE(n->tid, 0);
	WRITE_ONCE(n->pop_round, 0);

	return 0;
}

/*
 * How long a consumed task stays DISPATCHING.
 *
 * The kernel cannot move a task when ops.dispatch() calls scx_bpf_dsq_insert().
 * The move may have to wait for the task's enqueue to finish or switch rq
 * locks, and doing either inside ops.dispatch() could invert the lock order
 * and deadlock. Instead, the insert records the task and its qseq, the number
 * of the task's current enqueue, in a per-CPU buffer. After ops.dispatch()
 * returns, the kernel flushes the buffer and moves each task that is still
 * QUEUED under the recorded qseq. That opens a window between the insert and
 * the move.
 *
 * The consuming CPU holds only its own rq lock, so the task's CPU can dequeue
 * and enqueue the task again at any time after the consume. The kernel gives
 * the new enqueue its qseq before it calls ops.enqueue(), and an insert made
 * in between records the new qseq:
 *
 *   consuming CPU                      task's CPU
 *   consume                            dequeue
 *                                      enqueue, new qseq, ops.enqueue() starts
 *   scx_bpf_dsq_insert(), new qseq
 *                                      ops.enqueue() queues the task again
 *   flush: qseq matches, task runs here while it is still queued
 *
 * DISPATCHING therefore lasts until the consuming CPU's flush, not until its
 * insert or until the task runs: a stalled consuming CPU can insert after the
 * task ran elsewhere and was queued again. An enqueue that finds the flush
 * possibly pending dispatches the task directly. That never makes the task
 * QUEUED, so the flush drops the insert whatever qseq it recorded. The flush
 * cannot be waited for instead, since a flush that meets the task in
 * ops.enqueue() waits for the enqueue itself.
 *
 * BPF cannot observe the flush, so each CPU counts rounds and bumps the count
 * where its flush is known to be done. ops.running() is such a point: a CPU
 * picks the next task only after its ops.dispatch() calls have returned and
 * been flushed. A consume records the CPU and its round. While that CPU's
 * count is unchanged, its flush may still be pending.
 *
 * All consumes of one ops.dispatch() call record the same round, and the
 * kernel flushes all inserts of the call together, so the next bump comes
 * after every one of them. Once the flush has moved a task to a local DSQ,
 * the task is out of BPF custody and no stale insert can act on it, so the
 * round may move on before the task runs, behind other tasks on that DSQ.
 */
__weak
int ctq_cpu_flushed(void)
{
	u32 cpu = bpf_get_smp_processor_id();
	struct ctq_cpu __arena *c;

	if (unlikely(cpu >= nr_cpu_ids)) {
		scx_bpf_error("ctq: invalid CPU %u", cpu);
		return -EINVAL;
	}
	c = &ctq_cpus[cpu];

	/* The flush happens before the bump that reports it. */
	smp_store_release(&c->round, c->round + 1);

	return 0;
}

/*
 * Is the consume of @n possibly not flushed yet? Ends DISPATCHING when the
 * consuming CPU's round has moved on. Called from the task's enqueue and
 * ops.running(), which its rq lock serializes, and no consume touches a node
 * that is off the queue, so the flags have no other writer here.
 */
static __always_inline
bool ctq_pop_pending(struct ctq_node __arena *n)
{
	u32 flags = READ_ONCE(n->flags);
	u32 cpu;

	if (likely(!(flags & CTQ_NODE_DISPATCHING)))
		return false;

	cpu = n->pop_cpu;
	if (unlikely(cpu >= nr_cpu_ids) ||
	    smp_load_acquire(&ctq_cpus[cpu].round) == n->pop_round)
		return true;

	WRITE_ONCE(n->flags, flags & ~CTQ_NODE_DISPATCHING);
	return false;
}

__weak
int ctq_task_dispatching(struct ctq_node __arena *n __arg_arena)
{
	return ctq_pop_pending(n);
}

__weak
int ctq_task_running(struct ctq_node __arena *n __arg_arena)
{
	int ret;

	ret = ctq_cpu_flushed();
	ctq_pop_pending(n);

	return ret;
}

__weak
int ctq_task_fini(struct ctq_node __arena *n __arg_arena)
{
	if (unlikely(READ_ONCE(n->ctq))) {
		scx_bpf_error("ctq: freeing a queued node");
		return -EBUSY;
	}

	return 0;
}

/*
 * May @cpu run the task of @n? Most tasks may run anywhere, and a pinned or
 * migration-disabled task names its one CPU. Otherwise read the bit from
 * p->cpus_ptr. The kernel's bitmap word is unsigned long, 64 bits on every
 * target with arena support.
 */
static __always_inline
bool ctq_task_allowed(struct ctq_node __arena *n, s32 cpu)
{
	const struct task_struct *p;
	u64 word;

	if (likely(n->flags & CTQ_NODE_ALL_CPUS))
		return true;

	if (n->forced_id >= 0)
		return cpu == n->forced_id;

	if (unlikely(cpu < 0 || cpu >= nr_cpu_ids))
		return false;

	p = bpf_core_cast((void *)n->task, struct task_struct);
	word = (u64)p->cpus_ptr + (cpu / 64) * sizeof(u64);

	return (bpf_core_cast((void *)word, struct cpumask)->bits[0] >> (cpu % 64)) & 1;
}

static __always_inline
int ctq_link(struct ctq __arena *q, struct task_struct *p,
	     struct ctq_node __arena *n, u64 key, bool parked)
{
	s32 forced_id = -1;
	u64 tid = 0;
	u32 flags;
	int ret;

	/*
	 * A node being inserted is in no queue. The task's enqueue is serialized
	 * against its dequeue and other enqueues, and no enqueue inserts the
	 * task while a move of it is in flight.
	 */
	if (unlikely(READ_ONCE(n->ctq))) {
		scx_bpf_error("ctq: pid %d inserted twice", p->pid);
		return -EALREADY;
	}

	if (unlikely(ctq_pop_pending(n)))
		return CTQ_ERR_INSERT_BYPASS;

	/*
	 * A migration-disabled task must stay on its CPU. Migrate-disable is what
	 * points p->cpus_ptr away from &p->cpus_mask, so check both: the counter
	 * covers the window before cpus_ptr is narrowed, and the pointer covers
	 * the current task, whose counter is ambiguous. Otherwise p->cpus_ptr is
	 * &p->cpus_mask.
	 */
	if (is_migration_disabled(p) ||
	    (u64)p->cpus_ptr != (u64)&p->cpus_mask)
		forced_id = scx_bpf_task_cpu(p);
	else if (p->nr_cpus_allowed == 1)
		forced_id = bpf_cpumask_first(&p->cpus_mask);

	if (bpf_core_field_exists(p->scx.tid))
		tid = p->scx.tid;

	scx_spin_lock(&q->lock);

	/*
	 * A parked task is moved here by another CPU without the task's rq
	 * lock, e.g., when cgroup_bw drains a throttled task from its queue
	 * after the cgroup gets its budget back. After the task leaves the
	 * parking queue and before it is linked into this CTQ, its dequeue
	 * finds it in neither and its next enqueue places it anew. A late link
	 * would then put the task here as well as where that enqueue placed
	 * it.
	 *
	 * To close the race between the move (parking queue -> CTQ) and the
	 * task's dequeue and enqueue, the node has a park word, so exactly one
	 * of them owns the task. The dequeue changes PARKED to CANCELLED and
	 * the mover changes PARKED to NONE, both by cmpxchg. The mover
	 * publishes n->ctq first, so a dequeue that loses finds the link and
	 * removes it under the lock. A mover that loses drops the task. The
	 * task's enqueue neither parks nor inserts it while a move is in
	 * flight, which it can tell from the hold the parking queue takes on
	 * the task, so the word cannot become PARKED again.
	 */
	if (parked) {
		WRITE_ONCE(n->ctq, q);
		if (cmpxchg(&n->park, CTQ_PARK_PARKED, CTQ_PARK_NONE) !=
		    CTQ_PARK_PARKED) {
			WRITE_ONCE(n->ctq, NULL);
			scx_spin_unlock(&q->lock);
			return CTQ_ERR_PARK_CANCELLED;
		}
	} else {
		WRITE_ONCE(n->park, CTQ_PARK_NONE);
	}

	flags = n->flags & ~(CTQ_NODE_REPORTED | CTQ_NODE_ALL_CPUS);
	if (forced_id < 0 && p->nr_cpus_allowed == nr_cpu_ids)
		flags |= CTQ_NODE_ALL_CPUS;

	n->forced_id = forced_id;
	n->task = (u64)p;
	n->tid = tid;
	n->flags = flags;
	n->rb.key = key;

	ret = rb_insert_node(&q->tree, &n->rb);
	WRITE_ONCE(n->ctq, ret ? NULL : q);

	scx_spin_unlock(&q->lock);

	return ret;
}

__weak
int ctq_insert(struct ctq __arena *q __arg_arena, struct task_struct *p __arg_trusted,
	       struct ctq_node __arena *n __arg_arena, u64 key)
{
	return ctq_link(q, p, n, key, false);
}

__weak
int ctq_insert_parked(struct ctq __arena *q __arg_arena,
		      struct task_struct *p __arg_trusted,
		      struct ctq_node __arena *n __arg_arena, u64 key)
{
	return ctq_link(q, p, n, key, true);
}

__weak
int ctq_remove(struct ctq_node __arena *n __arg_arena)
{
	struct ctq __arena *q;
	int ret = 0;

	/* Cancel a move from another queue before it can commit. */
	if (smp_load_acquire(&n->park) == CTQ_PARK_PARKED)
		cmpxchg(&n->park, CTQ_PARK_PARKED, CTQ_PARK_CANCELLED);

	q = smp_load_acquire(&n->ctq);

	if (!q)
		return 0;

	scx_spin_lock(&q->lock);

	if (n->ctq == q) {
		ret = rb_remove_node(&q->tree, &n->rb);
		if (!ret)
			WRITE_ONCE(n->ctq, NULL);
	}

	scx_spin_unlock(&q->lock);

	return ret;
}

__weak
u64 ctq_consume_internal(struct ctq __arena *q __arg_arena, s32 cpu)
{
	struct ctq_node __arena *n, *picked = NULL;
	struct ctq_consume_res __arena *res;
	u32 this_cpu, nr_reports = 0;
	rbnode_t *rbn;

	this_cpu = bpf_get_smp_processor_id();
	if (unlikely(this_cpu >= nr_cpu_ids)) {
		scx_bpf_error("ctq: invalid CPU %u", this_cpu);
		return (u64)NULL;
	}
	res = &ctq_cpus[this_cpu].res;

	scx_spin_lock(&q->lock);

	/*
	 * Take the first task @cpu may run. Report the ones walked past that
	 * nobody has been told about since they were inserted.
	 */
	for (rbn = q->tree.first; rbn && can_loop; rbn = rb_next(rbn)) {
		n = (struct ctq_node __arena *)rbn;

		if (ctq_task_allowed(n, cpu)) {
			picked = n;
			break;
		}

		if (!(n->flags & CTQ_NODE_REPORTED) &&
		    nr_reports < CTQ_MAX_REPORTS) {
			n->flags |= CTQ_NODE_REPORTED;
			res->reports[nr_reports++] = n;
		}
	}

	if (picked) {
		if (unlikely(rb_remove_node(&q->tree, &picked->rb)))
			scx_bpf_error("ctq: failed to remove a picked node");
		/*
		 * A dequeue that finds the node off the queue skips the lock,
		 * and the enqueue after it must see DISPATCHING and the round.
		 */
		picked->flags |= CTQ_NODE_DISPATCHING;
		picked->pop_cpu = this_cpu;
		picked->pop_round = READ_ONCE(ctq_cpus[this_cpu].round);
		smp_store_release(&picked->ctq, NULL);
	}

	scx_spin_unlock(&q->lock);

	WRITE_ONCE(res->picked, picked);
	if (nr_reports < CTQ_MAX_REPORTS)
		WRITE_ONCE(res->reports[nr_reports], NULL);

	return (u64)res;
}

static __always_inline
bool ctq_dispatch_node(struct ctq_node __arena *n, u64 enq_flags)
{
	struct task_struct *p;
	bool inserted = false;

	if (ctq_tid_to_task) {
		p = scx_bpf_tid_to_task(n->tid);
		if (!p)
			return false;
		return scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, 0, enq_flags);
	}

	/* A pid can be reused, so the task found must be the one queued. */
	p = bpf_core_cast((void *)n->task, struct task_struct);
	p = bpf_task_from_pid(p->pid);
	if (!p)
		return false;
	if ((u64)p == n->task)
		inserted = scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, 0, enq_flags);
	bpf_task_release(p);

	return inserted;
}

__weak
u64 ctq_move_to_local_internal(struct ctq __arena *q __arg_arena, u64 enq_flags)
{
	const struct ctq_consume_res __arena *res;
	struct ctq_node __arena *n;

	res = ctq_consume(q, bpf_get_smp_processor_id());
	if (!res)
		return (u64)NULL;

	n = res->picked;
	if (n && !ctq_dispatch_node(n, enq_flags))
		WRITE_ONCE(res->picked, NULL);

	return (u64)res;
}
