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
 * What a user must provide:
 *
 * - Embed struct ctq_node in a task context that is freed only after an RCU
 *   grace period, such as one from scx_task_alloc() freed with
 *   scx_task_free_rcu(). A node is read through its pointer by CPUs that do
 *   not hold the queue's lock.
 * - Call ctq_remove() from ops.dequeue() and ctq_task_fini() before freeing
 *   the task context.
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
};

struct ctq;

struct ctq_node {
	/* first, so that a tree node converts to its ctq_node by a cast */
	struct rbnode		rb;
	/* the queue the node is in, NULL if none; written under its lock */
	struct ctq __arena	*ctq;
	u32			flags;
	/* the CPU the task must run on (pinned or migration-disabled), or -1 */
	s32			forced_id;
	/* task_struct address, read through a read-only cast */
	u64			task;
};

struct ctq {
	arena_spinlock_t	lock;
	struct rbtree		tree;
} __attribute__((aligned(SCX_CACHELINE_SIZE)));

/* the picked task and the reports fill exactly one cache line */
#define CTQ_MAX_REPORTS							\
	(SCX_CACHELINE_SIZE / sizeof(struct ctq_node __arena *) - 1)

struct ctq_consume_res {
	/* the task taken off the queue, or NULL if none may run */
	struct ctq_node __arena *picked;
	/* tasks walked past, NULL-terminated when fewer than CTQ_MAX_REPORTS */
	struct ctq_node __arena *reports[CTQ_MAX_REPORTS];
};

_Static_assert(sizeof(struct ctq_consume_res) == SCX_CACHELINE_SIZE,
	       "ctq_consume_res must be one cache line");

int ctq_lib_init(void);
int ctq_init(struct ctq __arena *q);
int ctq_task_init(struct ctq_node __arena *n);
int ctq_task_fini(struct ctq_node __arena *n);

int ctq_insert(struct ctq __arena *q, struct task_struct *p,
	       struct ctq_node __arena *n, u64 key);
int ctq_remove(struct ctq_node __arena *n);

/*
 * Take the first task @cpu may run off @q and report the tasks walked past.
 * The result lives in a per-CPU slot and stays valid until this CPU's next
 * consume.
 */
u64 ctq_consume_internal(struct ctq __arena *q, s32 cpu);
#define ctq_consume(q, cpu)						\
	((const struct ctq_consume_res __arena *)ctq_consume_internal((q), (cpu)))

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
