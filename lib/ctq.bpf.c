/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 * Author: Changwoo Min <changwoo@igalia.com>
 */
#include <scx/common.bpf.h>
#include <bpf/bpf_core_read.h>
#include <lib/arena_map.h>
#include <lib/sdt_task.h>
#include <lib/spinlock.h>
#include <lib/topology.h>
#include <lib/ctq.h>

extern const volatile u32 nr_cpu_ids;

/* set by userspace when the scheduler enables SCX_OPS_TID_TO_TASK (v7.2+) */
const volatile bool ctq_tid_to_task;

/*
 * The top bit of ctq_cpu.round: the CPU consumed a task since the round last
 * moved on, so the round must move on at its next flushed point. A round that
 * consumed nothing stays, which spares the store.
 */
#define CTQ_ROUND_CONSUMED	(1ULL << 63)

/* the state of each CPU, one cache line each */
struct ctq_cpu {
	/* the dispatch round and CTQ_ROUND_CONSUMED, see ctq_cpu_flushed() */
	u64			round;
	/* the result of the CPU's last consume */
	struct ctq_consume_res	res;
} __attribute__((aligned(SCX_CACHELINE_SIZE)));

_Static_assert(sizeof(struct ctq_cpu) == SCX_CACHELINE_SIZE,
	       "ctq_cpu must be one cache line");

/* each CPU's state by CPU id, see ctq_lib_init() */
static struct ctq_cpu __arena * __arena *ctq_cpus;

/* the report generation, advanced by ctq_cpu_offline() */
static volatile u32 ctq_report_gen;

/*
 * Place the states of the CPUs on NUMA node @numa in @cpus, one after
 * another, and return how many there are. With @cpus NULL, only count them.
 * Global, so that the verifier checks it once on its own: inlined, the count
 * sizes an allocation and the verifier walks its loop once per value.
 */
__weak
u32 ctq_place_numa(s32 numa, struct ctq_cpu __arena *cpus __arg_arena)
{
	u32 cpu, nr = 0;

	bpf_for(cpu, 0, nr_cpu_ids) {
		if (topo_cpu_to_numa_id(cpu) != numa)
			continue;
		if (cpus)
			ctq_cpus[cpu] = &cpus[nr];
		nr++;
	}

	return nr;
}

/*
 * A CPU's state is mostly its own to touch, so it lives on the CPU's NUMA
 * node: the states of each node share one allocation there, and a table maps
 * a CPU id to its state. Without a topology, every state goes on
 * NUMA_NO_NODE. Allocate whole pages, since a static allocation is capped at
 * a few pages.
 */
__weak
int ctq_lib_init(void)
{
	u32 pages = div_round_up(nr_cpu_ids * sizeof(*ctq_cpus), PAGE_SIZE);
	struct ctq_cpu __arena *cpus;
	s32 numa, nr_numas = 0;
	u32 cpu, nr;

	ctq_cpus = bpf_arena_alloc_pages(&arena, NULL, pages, NUMA_NO_NODE, 0);
	if (!ctq_cpus)
		return -ENOMEM;

	bpf_for(cpu, 0, nr_cpu_ids) {
		numa = topo_cpu_to_numa_id(cpu);
		if (numa >= nr_numas)
			nr_numas = numa + 1;
	}

	bpf_for(numa, NUMA_NO_NODE, nr_numas) {
		nr = ctq_place_numa(numa, NULL);
		if (!nr)
			continue;

		pages = div_round_up(nr * sizeof(*cpus), PAGE_SIZE);
		cpus = bpf_arena_alloc_pages(&arena, NULL, pages, numa, 0);
		if (!cpus)
			return -ENOMEM;

		ctq_place_numa(numa, cpus);
	}

	return 0;
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
 * where its flush is known to be done. The kernel flushes the inserts of an
 * ops.dispatch() call when the call returns, so any point on the CPU outside
 * its ops.dispatch() calls will do: the start of the next call, a re-enqueue
 * of its local DSQ, or ops.running(), since a CPU picks the next task only
 * after its calls have returned. A consume records the CPU and its round.
 * While that CPU's count is unchanged, its flush may still be pending. The
 * CPU is the one running the consume, whose dispatch buffer holds the insert,
 * also when it dispatches for an SMT sibling under core scheduling.
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
	u64 round;

	if (unlikely(cpu >= nr_cpu_ids)) {
		scx_bpf_error("ctq: invalid CPU %u", cpu);
		return -EINVAL;
	}
	c = ctq_cpus[cpu];

	/* Only this CPU writes its round, so a plain read will do. */
	round = c->round;
	if (likely(!(round & CTQ_ROUND_CONSUMED)))
		return 0;

	/* The flush happens before the bump that reports it. */
	smp_store_release(&c->round, (round & ~CTQ_ROUND_CONSUMED) + 1);

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
	    (smp_load_acquire(&ctq_cpus[cpu]->round) & ~CTQ_ROUND_CONSUMED) ==
	    n->pop_round)
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
 * Is @task executing on its CPU, switching out included? on_cpu is an int up
 * to v6.18 and a u8 later, so let CO-RE size the load. Ordered like
 * smp_load_acquire(), against the clear in finish_task().
 */
static __always_inline
bool ctq_task_on_cpu(const struct task_struct *task)
{
	bool on_cpu = BPF_CORE_READ_BITFIELD(task, on_cpu);

	if (!CONFIG_X86_64)
		smp_mb();
	barrier();
	return on_cpu;
}

/*
 * Must a walk leave the task of @n until it is off its CPU?
 *
 * put_prev_task_scx() queues a task while it is still current on its CPU.
 * Until the context switch is done, that CPU runs BPF programs in the task's
 * context, such as ops.running() of the next task, and with
 * CONFIG_PREEMPT_RCU each of them calls migrate_disable() on the task in its
 * prolog. Before v7.2, the flush tests a task it moves from another CPU for
 * migration-disabled without that CPU's rq lock, so it can see the prolog's
 * count and fail the scheduler. From v7.2 (5c94a3ab6ed9), the flush tests
 * under that lock, which the CPU holds until the switch is done.
 *
 * Before v7.2, a walk takes such a task only once finish_task() has
 * cleared on_cpu after the switch, when every prolog has ended. A queued task
 * does not run, so on_cpu stays clear until the task is dispatched. Only a
 * task that was on its CPU when it was linked can be on it later, so the walk
 * reads the task only for nodes flagged at link.
 */
static __always_inline
bool ctq_node_on_cpu(struct ctq_node __arena *n)
{
	const struct task_struct *p;

	if (likely(!(n->flags & CTQ_NODE_ON_CPU)))
		return false;

	p = bpf_core_cast((void *)n->task, struct task_struct);
	if (ctq_task_on_cpu(p))
		return true;

	n->flags &= ~CTQ_NODE_ON_CPU;
	return false;
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
	u32 flags, on_cpu_flag = 0;
	s32 forced_id = -1;
	u64 tid = 0;
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

	/* The caller should have checked ctq_task_dispatching(), see ctq.h. */
	if (unlikely(ctq_pop_pending(n))) {
		bpf_printk("ctq: %s[%d] inserted while dispatching", p->comm,
			   p->pid);
		return CTQ_ERR_INSERT_BYPASS;
	}

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

	/* See ctq_node_on_cpu(). */
	if (LINUX_KERNEL_VERSION < KERNEL_VERSION(7, 2, 0) && ctq_task_on_cpu(p))
		on_cpu_flag = CTQ_NODE_ON_CPU;

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

	flags = n->flags & ~(CTQ_NODE_REPORTED | CTQ_NODE_ALL_CPUS |
			     CTQ_NODE_ON_CPU);
	if (forced_id < 0 && p->nr_cpus_allowed == nr_cpu_ids)
		flags |= CTQ_NODE_ALL_CPUS;
	flags |= on_cpu_flag;

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

/*
 * Have every queue report its tasks once more, each when a walk next reaches
 * it. A walk reads the generation without ordering and may report a task one
 * walk late. A BPF atomic is fully ordered only if it returns its value, so
 * return it: a caller that orders its reads after a walk's then sees the
 * writes it made before this call once the walk sees the new generation.
 */
__weak
int ctq_cpu_offline(s32 cpu)
{
	return __sync_fetch_and_add(&ctq_report_gen, 1);
}

__weak
u64 ctq_cpu_round(s32 cpu)
{
	/* Callers such as ops.dump_cpu() may touch no arena memory themselves. */
	scx_arena_subprog_init();

	if (!ctq_cpus || cpu < 0 || cpu >= nr_cpu_ids)
		return 0;
	return READ_ONCE(ctq_cpus[cpu]->round);
}

__weak
u64 ctq_consume_internal(struct ctq __arena *q __arg_arena, s32 cpu)
{
	struct ctq_node __arena *n, *picked = NULL;
	struct ctq_consume_res __arena *res;
	u32 gen = READ_ONCE(ctq_report_gen);
	struct ctq_cpu __arena *c;
	u32 this_cpu, nr_reports = 0;
	u64 round;
	bool skipped = false;
	rbnode_t *rbn;

	this_cpu = bpf_get_smp_processor_id();
	if (unlikely(this_cpu >= nr_cpu_ids)) {
		scx_bpf_error("ctq: invalid CPU %u", this_cpu);
		return (u64)NULL;
	}
	c = ctq_cpus[this_cpu];
	res = &c->res;

	/*
	 * Skip an empty queue without the lock, as the kernel does for a DSQ.
	 * A consume cannot count on an insert it races with: the inserting
	 * side kicks a CPU for its task, so no task waits on this consume.
	 */
	if (!ctq_peek(q)) {
		WRITE_ONCE(res->picked, NULL);
		WRITE_ONCE(res->reports[0], NULL);
		return (u64)res;
	}

	scx_spin_lock(&q->lock);

	/*
	 * Take the first task @cpu may run, leaving any still on its CPU.
	 * Report the ones @cpu may not run that nobody has been told about
	 * since they were inserted, or since a CPU went offline.
	 */
	for (rbn = q->tree.first; rbn && can_loop; rbn = rb_next(rbn)) {
		n = (struct ctq_node __arena *)rbn;

		if (ctq_task_allowed(n, cpu)) {
			if (likely(!ctq_node_on_cpu(n))) {
				picked = n;
				break;
			}
			skipped = true;
			continue;
		}

		if ((!(n->flags & CTQ_NODE_REPORTED) || n->report_gen != gen) &&
		    nr_reports < CTQ_MAX_REPORTS) {
			n->flags |= CTQ_NODE_REPORTED;
			n->report_gen = gen;
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
		round = c->round;
		picked->pop_round = round & ~CTQ_ROUND_CONSUMED;
		if (!(round & CTQ_ROUND_CONSUMED))
			WRITE_ONCE(c->round, round | CTQ_ROUND_CONSUMED);
		smp_store_release(&picked->ctq, NULL);
	}

	scx_spin_unlock(&q->lock);

	/* Have @cpu look again once the task left behind is off its CPU. */
	if (unlikely(skipped && !picked))
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);

	WRITE_ONCE(res->picked, picked);
	if (nr_reports < CTQ_MAX_REPORTS)
		WRITE_ONCE(res->reports[nr_reports], NULL);

	return (u64)res;
}

/*
 * Insert @p into @cpu's local DSQ. Returns false if it went elsewhere.
 *
 * A walk takes a task only once it is off its CPU, see ctq_node_on_cpu(), so
 * its migration-disabled state is final here. forced_id keeps such a task
 * from other CPUs' walks. Should one get through, send it to its own CPU,
 * since the flush fails the scheduler on a move elsewhere.
 */
static __always_inline
bool ctq_insert_local(struct task_struct *p, u64 enq_flags, s32 cpu)
{
	s32 task_cpu = scx_bpf_task_cpu(p);

	if (unlikely(task_cpu != cpu && is_migration_disabled(p))) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | task_cpu, 0, enq_flags);
		return false;
	}

	return scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, 0, enq_flags);
}

static __always_inline
bool ctq_dispatch_node(struct ctq_node __arena *n, u64 enq_flags, s32 cpu)
{
	struct task_struct *p;
	bool inserted = false;

	if (ctq_tid_to_task) {
		p = scx_bpf_tid_to_task(n->tid);
		if (!p)
			return false;
		return ctq_insert_local(p, enq_flags, cpu);
	}

	/* A pid can be reused, so the task found must be the one queued. */
	p = bpf_core_cast((void *)n->task, struct task_struct);
	p = bpf_task_from_pid(p->pid);
	if (!p)
		return false;
	if ((u64)p == n->task)
		inserted = ctq_insert_local(p, enq_flags, cpu);
	bpf_task_release(p);

	return inserted;
}

/*
 * Insert into SCX_DSQ_LOCAL_ON | @cpu rather than SCX_DSQ_LOCAL. Under core
 * scheduling, @cpu can be an SMT sibling of the CPU running the dispatch.
 * Kernels without 3dd52416e44a ("sched_ext: Fix this_rq() assumptions in
 * dispatch kfuncs") take SCX_DSQ_LOCAL as the running CPU's local DSQ.
 */
__weak
u64 ctq_move_to_local_internal(struct ctq __arena *q __arg_arena, s32 cpu,
			       u64 enq_flags)
{
	const struct ctq_consume_res __arena *res;
	struct ctq_node __arena *n;

	res = ctq_consume(q, cpu);
	if (!res)
		return (u64)NULL;

	n = res->picked;
	if (n && !ctq_dispatch_node(n, enq_flags, cpu))
		WRITE_ONCE(res->picked, NULL);

	return (u64)res;
}
