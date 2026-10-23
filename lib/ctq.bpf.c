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

/* the consume result of each CPU, one cache line each */
static struct ctq_consume_res __arena *ctq_results;

__weak
int ctq_lib_init(void)
{
	ctq_results = scx_static_alloc(nr_cpu_ids * sizeof(*ctq_results),
				       SCX_CACHELINE_SIZE);
	return ctq_results ? 0 : -ENOMEM;
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
	res = &ctq_results[this_cpu];

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
		WRITE_ONCE(picked->ctq, NULL);
	}

	scx_spin_unlock(&q->lock);

	WRITE_ONCE(res->picked, picked);
	if (nr_reports < CTQ_MAX_REPORTS)
		WRITE_ONCE(res->reports[nr_reports], NULL);

	return (u64)res;
}
