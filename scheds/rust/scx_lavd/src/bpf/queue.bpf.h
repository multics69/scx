/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 * Author: Changwoo Min <changwoo@igalia.com>
 */
#pragma once

#include <scx/common.bpf.h>
#include <bpf_arena_common.bpf.h>

/* lavd's own queues, named by their DSQ ids (queue.bpf.c). */
int queue_init(u64 dsq_id, s32 node);
void queue_insert_vtime(struct task_struct *p, u64 dsq_id, u64 slice,
			u64 vtime, u64 enq_flags);
void queue_insert_vtime_parked(struct task_struct *p, u64 dsq_id, u64 slice,
			       u64 vtime, u64 enq_flags);
bool queue_move_to_local(u64 dsq_id, u64 enq_flags);
s32 queue_nr_queued(u64 dsq_id);
u64 queue_peek_vtime(u64 dsq_id);
u64 queue_peek_load(u64 dsq_id);
