/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 * Author: Changwoo Min <changwoo@igalia.com>
 */
#pragma once

#include <scx/common.bpf.h>
#include <bpf_arena_common.bpf.h>
#include <lib/ctq.h>

struct task_ctx;

/* lavd's own queues, identified by lavd's DSQ ids (queue.bpf.c). */
int queue_lib_init(void);
int queue_insert_vtime(struct task_struct *p, struct task_ctx __arena *taskc,
		       u64 dsq_id, u64 vtime);
int queue_insert_vtime_parked(struct task_struct *p,
			      struct task_ctx __arena *taskc, u64 dsq_id,
			      u64 vtime);
bool queue_move_to_local(u64 dsq_id, s32 cpu, u64 enq_flags);
s32 queue_nr_queued(u64 dsq_id);
u64 queue_peek_vtime(u64 dsq_id);
u64 queue_peek_load(u64 dsq_id);
void queue_cpu_offline(s32 cpu);
void queue_cpu_flushed(void);

/* A task's side of the queues (queue.bpf.c). */
void queue_task_init(struct task_ctx __arena *taskc);
void queue_task_fini(struct task_ctx __arena *taskc);
bool queue_task_in_flight(struct task_ctx __arena *taskc);
void queue_task_park(struct task_ctx __arena *taskc);
void queue_task_running(struct task_ctx __arena *taskc);
void queue_task_dequeue(struct task_ctx __arena *taskc);

/* Exit dumps (queue.bpf.c). */
void queue_dump_task(struct task_ctx __arena *taskc);
void queue_dump_cpdom(u64 cpdom_id);
