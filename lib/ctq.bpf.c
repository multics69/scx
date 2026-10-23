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

/* each CPU's consume result by CPU id, see ctq_lib_init() */
static struct ctq_consume_res __arena * __arena *ctq_results;

/* the report generation, advanced by ctq_cpu_offline() */
static volatile u32 ctq_report_gen;

/*
 * Place the results of the CPUs on NUMA node @numa in @res, one after
 * another, and return how many there are. With @res NULL, only count them.
 * Global, so that the verifier checks it once on its own: inlined, the count
 * sizes an allocation and the verifier walks its loop once per value.
 */
__weak
u32 ctq_place_numa(s32 numa, struct ctq_consume_res __arena *res __arg_arena)
{
	u32 cpu, nr = 0;

	bpf_for(cpu, 0, nr_cpu_ids) {
		if (topo_cpu_to_numa_id(cpu) != numa)
			continue;
		if (res)
			ctq_results[cpu] = &res[nr];
		nr++;
	}

	return nr;
}

/*
 * A CPU's result is its own to touch, so it lives on the CPU's NUMA node: the
 * results of each node share one allocation there, and a table maps a CPU id
 * to its result. Without a topology, every result goes on NUMA_NO_NODE.
 * Allocate whole pages, since a static allocation is capped at a few pages.
 */
__weak
int ctq_lib_init(void)
{
	u32 pages = div_round_up(nr_cpu_ids * sizeof(*ctq_results), PAGE_SIZE);
	struct ctq_consume_res __arena *res;
	s32 numa, nr_numas = 0;
	u32 cpu, nr;

	ctq_results = bpf_arena_alloc_pages(&arena, NULL, pages, NUMA_NO_NODE,
					    0);
	if (!ctq_results)
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

		pages = div_round_up(nr * sizeof(*res), PAGE_SIZE);
		res = bpf_arena_alloc_pages(&arena, NULL, pages, numa, 0);
		if (!res)
			return -ENOMEM;

		ctq_place_numa(numa, res);
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
	WRITE_ONCE(n->forced_id, -1);
	WRITE_ONCE(n->task, 0);

	return 0;
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

__weak
int ctq_insert(struct ctq __arena *q __arg_arena, struct task_struct *p __arg_trusted,
	       struct ctq_node __arena *n __arg_arena, u64 key)
{
	s32 forced_id = -1;
	u32 flags;
	int ret;

	/*
	 * The task's enqueue is serialized against its dequeue and other
	 * enqueues, so a node being inserted is in no queue.
	 */
	if (unlikely(READ_ONCE(n->ctq))) {
		scx_bpf_error("ctq: pid %d inserted twice", p->pid);
		return -EALREADY;
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

	scx_spin_lock(&q->lock);

	flags = n->flags & ~(CTQ_NODE_REPORTED | CTQ_NODE_ALL_CPUS);
	if (forced_id < 0 && p->nr_cpus_allowed == nr_cpu_ids)
		flags |= CTQ_NODE_ALL_CPUS;

	n->forced_id = forced_id;
	n->task = (u64)p;
	n->flags = flags;
	n->rb.key = key;

	ret = rb_insert_node(&q->tree, &n->rb);
	if (!ret)
		WRITE_ONCE(n->ctq, q);

	scx_spin_unlock(&q->lock);

	return ret;
}

__weak
int ctq_remove(struct ctq_node __arena *n __arg_arena)
{
	struct ctq __arena *q = READ_ONCE(n->ctq);
	int ret = 0;

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
u64 ctq_consume_internal(struct ctq __arena *q __arg_arena, s32 cpu)
{
	struct ctq_node __arena *n, *picked = NULL;
	struct ctq_consume_res __arena *res;
	u32 gen = READ_ONCE(ctq_report_gen);
	u32 this_cpu, nr_reports = 0;
	rbnode_t *rbn;

	this_cpu = bpf_get_smp_processor_id();
	if (unlikely(this_cpu >= nr_cpu_ids)) {
		scx_bpf_error("ctq: invalid CPU %u", this_cpu);
		return (u64)NULL;
	}
	res = ctq_results[this_cpu];

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
	 * Take the first task @cpu may run. Report the ones walked past that
	 * nobody has been told about since they were inserted, or since a CPU
	 * went offline.
	 */
	for (rbn = q->tree.first; rbn && can_loop; rbn = rb_next(rbn)) {
		n = (struct ctq_node __arena *)rbn;

		if (ctq_task_allowed(n, cpu)) {
			picked = n;
			break;
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
		WRITE_ONCE(picked->ctq, NULL);
	}

	scx_spin_unlock(&q->lock);

	WRITE_ONCE(res->picked, picked);
	if (nr_reports < CTQ_MAX_REPORTS)
		WRITE_ONCE(res->reports[nr_reports], NULL);

	return (u64)res;
}
