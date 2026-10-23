/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 * Author: Changwoo Min <changwoo@igalia.com>
 */
#include <scx/common.bpf.h>
#include <lib/sdt_task.h>
#include <lib/ctq.h>

#include "selftest.h"

extern const volatile u32 nr_cpu_ids;

#define CTQ_ST_NR_NODES	32

static struct ctq_node __arena *ctq_st_nodes[CTQ_ST_NR_NODES];

static struct ctq __arena *ctq_st_alloc(void)
{
	struct ctq __arena *q;

	q = scx_static_alloc(sizeof(*q), SCX_CACHELINE_SIZE);
	if (q && ctq_init(q))
		return NULL;
	return q;
}

static int ctq_st_alloc_nodes(void)
{
	struct ctq_node __arena *n;
	int i;

	bpf_for(i, 0, CTQ_ST_NR_NODES) {
		n = scx_static_alloc(sizeof(*n), 8);
		if (!n)
			return -ENOMEM;
		ctq_task_init(n);
		ctq_st_nodes[i] = n;
	}

	return 0;
}

/* Restrict @n to @cpu after insert, as a pinned task would be. */
static void ctq_st_pin(struct ctq_node __arena *n, s32 cpu)
{
	n->forced_id = cpu;
	n->flags &= ~CTQ_NODE_ALL_CPUS;
}

/* Let @n run anywhere after insert, whatever its task's affinity. */
static void ctq_st_any(struct ctq_node __arena *n)
{
	n->forced_id = -1;
	n->flags |= CTQ_NODE_ALL_CPUS;
}

/*
 * Consumes return tasks in key order, equal keys in insertion order, and the
 * lockless head and length follow along.
 */
static int ctq_st_order(struct task_struct *p)
{
	const struct ctq_consume_res __arena *res;
	const int nr_keys = 4, per_key = CTQ_ST_NR_NODES / 4;
	struct ctq __arena *q;
	u64 key;
	int i;

	q = ctq_st_alloc();
	if (!q)
		return 1;

	if (ctq_peek(q) || ctq_peek_key(q, &key) != -ENOENT || ctq_nr_queued(q))
		return 2;

	bpf_for(i, 0, CTQ_ST_NR_NODES) {
		if (ctq_insert(q, p, ctq_st_nodes[i], i % nr_keys))
			return 3;
		ctq_st_any(ctq_st_nodes[i]);
	}

	if (ctq_nr_queued(q) != CTQ_ST_NR_NODES)
		return 4;

	bpf_for(i, 0, CTQ_ST_NR_NODES) {
		struct ctq_node __arena *want;

		/* All of key 0 in insertion order, then all of key 1, ... */
		want = ctq_st_nodes[(i / per_key) + nr_keys * (i % per_key)];

		if (ctq_peek(q) != want || ctq_peek_key(q, &key) ||
		    key != want->rb.key)
			return 5;

		res = ctq_consume(q, 0);
		if (!res || res->picked != want || res->reports[0])
			return 6;

		if (want->ctq || ctq_nr_queued(q) != CTQ_ST_NR_NODES - 1 - i)
			return 7;
	}

	res = ctq_consume(q, 0);
	if (!res || res->picked)
		return 8;

	return 0;
}

/*
 * A consume walks past tasks the CPU may not run, reports each once per
 * enqueue and once more after a CPU goes offline, caps the reports per
 * consume, and leaves them queued.
 */
static int ctq_st_reports(struct task_struct *p)
{
	const struct ctq_consume_res __arena *res;
	struct ctq_node __arena *a, *b, *c;
	struct ctq __arena *q;
	int i;

	q = ctq_st_alloc();
	if (!q)
		return 1;

	a = ctq_st_nodes[0];
	b = ctq_st_nodes[1];
	c = ctq_st_nodes[2];

	/* a and b only on CPU 1, ahead of c, which may run anywhere. */
	if (ctq_insert(q, p, a, 1) || ctq_insert(q, p, b, 2) ||
	    ctq_insert(q, p, c, 3))
		return 2;
	ctq_st_pin(a, 1);
	ctq_st_pin(b, 1);
	ctq_st_any(c);

	res = ctq_consume(q, 0);
	if (!res || res->picked != c || res->reports[0] != a ||
	    res->reports[1] != b || res->reports[2])
		return 3;

	/* Already reported: nothing to take and nothing new to report. */
	res = ctq_consume(q, 0);
	if (!res || res->picked || res->reports[0])
		return 4;

	/* After a CPU goes offline, they are reported once more. */
	ctq_cpu_offline(1);
	res = ctq_consume(q, 0);
	if (!res || res->picked || res->reports[0] != a ||
	    res->reports[1] != b || res->reports[2])
		return 20;
	res = ctq_consume(q, 0);
	if (!res || res->picked || res->reports[0])
		return 21;

	if (ctq_nr_queued(q) != 2)
		return 5;

	/* A reinsert clears the report. */
	if (ctq_remove(b) || b->ctq)
		return 6;
	if (ctq_remove(b))
		return 7;
	if (ctq_insert(q, p, b, 2))
		return 8;
	ctq_st_pin(b, 1);

	res = ctq_consume(q, 0);
	if (!res || res->picked || res->reports[0] != b || res->reports[1])
		return 9;

	/* CPU 1 takes them in order without reporting anything. */
	res = ctq_consume(q, 1);
	if (!res || res->picked != a || res->reports[0])
		return 10;
	res = ctq_consume(q, 1);
	if (!res || res->picked != b || res->reports[0])
		return 11;

	/* More restricted tasks than a consume reports: the rest come next. */
	bpf_for(i, 0, CTQ_MAX_REPORTS + 2) {
		if (i >= CTQ_ST_NR_NODES)
			return 12;
		if (ctq_insert(q, p, ctq_st_nodes[i], i))
			return 13;
		ctq_st_pin(ctq_st_nodes[i], 1);
	}

	res = ctq_consume(q, 0);
	if (!res || res->picked)
		return 14;
	bpf_for(i, 0, CTQ_MAX_REPORTS) {
		if (res->reports[i] != ctq_st_nodes[i])
			return 15;
	}

	res = ctq_consume(q, 0);
	if (!res || res->picked || res->reports[2] ||
	    res->reports[0] != ctq_st_nodes[CTQ_MAX_REPORTS] ||
	    res->reports[1] != ctq_st_nodes[CTQ_MAX_REPORTS + 1])
		return 16;

	bpf_for(i, 0, CTQ_MAX_REPORTS + 2) {
		if (i >= CTQ_ST_NR_NODES)
			return 17;
		if (ctq_remove(ctq_st_nodes[i]))
			return 18;
	}

	return ctq_nr_queued(q) ? 19 : 0;
}

/*
 * Without forced_id and ALL_CPUS, the walk reads the bit from the task's
 * cpus_ptr. It must agree with the kernel's own test on every CPU.
 */
static int ctq_st_affinity(struct task_struct *p)
{
	const struct ctq_consume_res __arena *res;
	struct ctq_node __arena *n = ctq_st_nodes[0];
	struct ctq __arena *q;
	bool allowed;
	u32 cpu;

	q = ctq_st_alloc();
	if (!q)
		return 1;

	bpf_for(cpu, 0, nr_cpu_ids) {
		if (ctq_insert(q, p, n, 0))
			return 2;
		n->forced_id = -1;
		n->flags &= ~CTQ_NODE_ALL_CPUS;

		/* @p is not migration-disabled, so cpus_ptr is &cpus_mask. */
		allowed = bpf_cpumask_test_cpu(cpu, &p->cpus_mask);

		res = ctq_consume(q, cpu);
		if (!res || (res->picked == n) != allowed)
			return 3;

		if (!allowed && ctq_remove(n))
			return 4;
	}

	/* A pinned task runs only on its CPU. */
	if (ctq_insert(q, p, n, 0))
		return 5;
	ctq_st_pin(n, 0);

	if (nr_cpu_ids > 1) {
		res = ctq_consume(q, 1);
		if (!res || res->picked)
			return 6;
	}

	res = ctq_consume(q, 0);
	if (!res || res->picked != n)
		return 7;

	return 0;
}

__weak
int scx_selftest_ctq(void)
{
	struct task_struct *p;
	int ret;

	ret = ctq_lib_init();
	if (ret)
		return ret;

	ret = ctq_st_alloc_nodes();
	if (ret)
		return ret;

	/* Any live task will do. Its own affinity is checked as it is. */
	p = bpf_task_from_pid(1);
	if (!p)
		return -ESRCH;

	ret = ctq_st_order(p);
	if (ret) {
		bpf_printk("SELFTEST ctq_st_order FAIL: %d", ret);
		goto out;
	}

	ret = ctq_st_reports(p);
	if (ret) {
		bpf_printk("SELFTEST ctq_st_reports FAIL: %d", ret);
		goto out;
	}

	ret = ctq_st_affinity(p);
	if (ret)
		bpf_printk("SELFTEST ctq_st_affinity FAIL: %d", ret);
out:
	bpf_task_release(p);
	return ret;
}
