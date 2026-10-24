/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 * Author: Changwoo Min <changwoo@igalia.com>
 */

/*
 * The queues lavd holds tasks in: one steady and one turbulent queue per
 * compute domain, and one queue per core when per-CPU queues are in use. Each
 * is named by its DSQ id, and every operation on them goes through here.
 */
#include <scx/common.bpf.h>
#include <bpf_arena_common.bpf.h>
#include "intf.h"
#include "lavd.bpf.h"
#include "util.bpf.h"
#include "queue.bpf.h"
#include <errno.h>
#include <stdbool.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

__hidden
int queue_init(u64 dsq_id, s32 node)
{
	return scx_bpf_create_dsq(dsq_id, node);
}

__hidden
void queue_insert_vtime(struct task_struct *p, u64 dsq_id, u64 slice,
			u64 vtime, u64 enq_flags)
{
	scx_bpf_dsq_insert_vtime(p, dsq_id, slice, vtime, enq_flags);
}

/* Insert a task moved in from a queue it was parked in, such as a BTQ. */
__hidden
void queue_insert_vtime_parked(struct task_struct *p, u64 dsq_id, u64 slice,
			       u64 vtime, u64 enq_flags)
{
	scx_bpf_dsq_insert_vtime(p, dsq_id, slice, vtime, enq_flags);
}

__hidden
bool queue_move_to_local(u64 dsq_id, u64 enq_flags)
{
	return scx_bpf_dsq_move_to_local(dsq_id, enq_flags);
}

__hidden
s32 queue_nr_queued(u64 dsq_id)
{
	return scx_bpf_dsq_nr_queued(dsq_id);
}

/* The head task's vtime, or U64_MAX if the queue is empty. */
__hidden
u64 queue_peek_vtime(u64 dsq_id)
{
	struct task_struct *p;

	p = __COMPAT_scx_bpf_dsq_peek(dsq_id);
	return p ? p->scx.dsq_vtime : U64_MAX;
}

/* The head task's load, or 0 if the queue is empty. */
u64 __attribute__((noinline)) queue_peek_load(u64 dsq_id)
{
	struct task_struct *peek_p = __COMPAT_scx_bpf_dsq_peek(dsq_id);

	if (peek_p) {
		task_ctx *peek_taskc = find_task_ctx(peek_p);
		if (peek_taskc)
			return task_load_metric(peek_taskc);
	}
	return 0;
}
