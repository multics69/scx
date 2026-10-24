/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 * Author: Changwoo Min <changwoo@igalia.com>
 */

/*
 * CTQ: an arena task queue ordered by a vtime key.
 *
 * A CTQ is one rbtree of queued tasks, ordered by key with equal keys in
 * insertion order, written by one writer at a time under the queue's lock.
 * Other CPUs read its head and length without the lock, as they do with a
 * kernel DSQ through scx_bpf_dsq_peek() and scx_bpf_dsq_nr_queued().
 *
 * A consume walks the tree from the head and takes the first task the
 * consuming CPU may run. The tasks it walks past are reported to the caller,
 * each at most once per enqueue, so that the caller can find a CPU for them.
 * The walk tests affinity without the task_struct: forced_id and ALL_CPUS
 * are recorded at insert, and otherwise the bit is read from p->cpus_ptr
 * through a read-only cast. A queued task's cpus_ptr and migration-disabled
 * state cannot change while it is queued, since the kernel dequeues a task
 * before changing either.
 *
 * ctq_move_to_local() consumes a task and inserts it into the local DSQ. The
 * node holds no reference to its task, so the task is looked up by its tid,
 * or by its pid with a check that the result is the queued task.
 *
 * A consumed task is DISPATCHING until the consuming CPU's dispatch round
 * has ended. If it is enqueued again before then, ctq_insert() refuses it
 * with CTQ_ERR_INSERT_BYPASS, and the caller dispatches it directly instead.
 * The kernel then discards the consuming CPU's insert. ctq.bpf.c explains why
 * the window lasts until the round ends rather than until the insert.
 *
 * A task parked in another queue can be moved into a CTQ by another CPU with
 * ctq_insert_parked(). The task's dequeue can cancel such a move, and the
 * move commits only if it was not cancelled. ctq.bpf.c explains why.
 *
 * What a user must provide:
 *
 * - Embed struct ctq_node in a task context that is freed only after an RCU
 *   grace period, such as one from scx_task_alloc() freed with
 *   scx_task_free_rcu(). A node is read through its pointer by CPUs that do
 *   not hold the queue's lock.
 * - Call ctq_remove() from ops.dequeue() and ctq_task_fini() before freeing
 *   the task context.
 * - At the top of ops.enqueue(), before any path that keeps the task in BPF
 *   custody, check ctq_task_dispatching(). When it is true, or when
 *   ctq_insert() returns CTQ_ERR_INSERT_BYPASS, insert the task into the
 *   local DSQ of a CPU it may run on (SCX_DSQ_LOCAL_ON | cpu) instead.
 * - Call ctq_task_running() from ops.running(), and ctq_move_to_local() only
 *   from ops.dispatch().
 * - Call ctq_task_park() before parking a task in another queue that may hand
 *   it to ctq_insert_parked(). While such a hand-off is in flight, the task's
 *   ops.enqueue() must neither park nor insert it, and dispatches it directly
 *   instead, as for ctq_task_dispatching().
 * - Set ctq_tid_to_task when SCX_OPS_TID_TO_TASK is enabled, which needs
 *   v7.2 or later. Without it, leave SCX_OPS_ENQ_EXITING clear, since the
 *   pid of an exiting task can be unhashed while the task is still enqueued.
 * - Allocate a struct ctq with SCX_CACHELINE_SIZE alignment, and call
 *   ctq_lib_init() once before using any queue.
 */
#pragma once

#ifdef __BPF__
#include <scx/common.bpf.h>
#include <bpf_arena_common.bpf.h>
#include <bpf_arena_spin_lock.h>
#include <lib/rbtree.h>

enum ctq_node_flags {
	/* reported by a consume walk since the node was inserted */
	CTQ_NODE_REPORTED	= 1U << 0,
	/* the task may run on every CPU; never set with forced_id */
	CTQ_NODE_ALL_CPUS	= 1U << 1,
	/* consumed, and the consuming CPU's dispatch round may not have ended */
	CTQ_NODE_DISPATCHING	= 1U << 2,
};

/* positive return values, apart from -errno */
enum ctq_err {
	/* ctq_insert() of a DISPATCHING node; dispatch the task directly instead */
	CTQ_ERR_INSERT_BYPASS	= 1,
	/* ctq_insert_parked() of a node whose dequeue cancelled the move */
	CTQ_ERR_PARK_CANCELLED	= 2,
};

/* the state of a node's move from another queue, see ctq_insert_parked() */
enum ctq_park {
	CTQ_PARK_NONE		= 0,
	/* parked in another queue, to be moved here */
	CTQ_PARK_PARKED		= 1,
	/* the task was dequeued while parked; the move must not commit */
	CTQ_PARK_CANCELLED	= 2,
};

struct ctq;

struct ctq_node {
	/* first, so that a tree node converts to its ctq_node by a cast */
	struct rbnode		rb;
	/* the queue the node is in, NULL if none; written under its lock */
	struct ctq __arena	*ctq;
	u32			flags;
	/* enum ctq_park, changed by cmpxchg once the task is parked */
	u32			park;
	/* the CPU the task must run on (pinned or migration-disabled), or -1 */
	s32			forced_id;
	/* the CPU that consumed the node last */
	s32			pop_cpu;
	/* task_struct address, read through a read-only cast */
	u64			task;
	/* p->scx.tid, 0 if the kernel lacks it */
	u64			tid;
	/* the round of pop_cpu when it consumed the node */
	u64			pop_round;
};

struct ctq {
	arena_spinlock_t	lock;
	struct rbtree		tree;
} __attribute__((aligned(SCX_CACHELINE_SIZE)));

/* the picked task and the reports fill one cache line with the CPU's round */
#define CTQ_MAX_REPORTS							\
	(SCX_CACHELINE_SIZE / sizeof(struct ctq_node __arena *) - 2)

struct ctq_consume_res {
	/* the task taken off the queue, or NULL if none may run */
	struct ctq_node __arena *picked;
	/* tasks walked past, NULL-terminated when fewer than CTQ_MAX_REPORTS */
	struct ctq_node __arena *reports[CTQ_MAX_REPORTS];
};

int ctq_lib_init(void);
int ctq_init(struct ctq __arena *q);
int ctq_task_init(struct ctq_node __arena *n);
int ctq_task_fini(struct ctq_node __arena *n);

int ctq_insert(struct ctq __arena *q, struct task_struct *p,
	       struct ctq_node __arena *n, u64 key);
int ctq_insert_parked(struct ctq __arena *q, struct task_struct *p,
		      struct ctq_node __arena *n, u64 key);
int ctq_remove(struct ctq_node __arena *n);

static __always_inline void ctq_task_park(struct ctq_node __arena *n)
{
	WRITE_ONCE(n->park, CTQ_PARK_PARKED);
}

int ctq_cpu_flushed(void);
int ctq_task_dispatching(struct ctq_node __arena *n);
int ctq_task_running(struct ctq_node __arena *n);

/*
 * Take the first task @cpu may run off @q and report the tasks walked past.
 * The result lives in a per-CPU slot and stays valid until this CPU's next
 * consume.
 */
u64 ctq_consume_internal(struct ctq __arena *q, s32 cpu);
#define ctq_consume(q, cpu)						\
	((const struct ctq_consume_res __arena *)ctq_consume_internal((q), (cpu)))

/*
 * ctq_consume() for this CPU and insert the picked task into its local DSQ,
 * keeping its slice. picked is NULL when nothing was inserted: no task may
 * run on this CPU, or the picked task is already gone. In the latter case the
 * kernel ends the dispatch round, so the caller decides whether this CPU must
 * dispatch again while the queue still holds tasks.
 */
u64 ctq_move_to_local_internal(struct ctq __arena *q, u64 enq_flags);
#define ctq_move_to_local(q, enq_flags)					\
	((const struct ctq_consume_res __arena *)			\
	 ctq_move_to_local_internal((q), (enq_flags)))

/*
 * Lockless reads of the head and the length, with the guarantees of
 * rb_first() and friends: advisory, the head pointer alone decides emptiness,
 * and the length is a separate read.
 */
static __always_inline struct ctq_node __arena *ctq_peek(struct ctq __arena *q)
{
	return (struct ctq_node __arena *)rb_first(&q->tree);
}

static __always_inline int ctq_peek_key(struct ctq __arena *q, u64 *key)
{
	return rb_first_key(&q->tree, key);
}

static __always_inline u64 ctq_nr_queued(struct ctq __arena *q)
{
	return rb_nr_nodes(&q->tree);
}

#endif /* __BPF__ */
