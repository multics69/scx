/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 * Copyright (c) 2026 Changwoo Min <changwoo@igalia.com>
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

const volatile bool fifo_sched;

static u64 vtime_now;
UEI_DEFINE(uei);

#define SHARED_DSQ 0

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 2);
} stats SEC(".maps");

static void stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}

s32 BPF_STRUCT_OPS(min_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		stat_inc(0);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	}

	return cpu;
}

void BPF_STRUCT_OPS(min_enqueue, struct task_struct *p, u64 enq_flags)
{
	stat_inc(1);

	if (fifo_sched) {
		scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
	} else {
		u64 vtime = p->scx.dsq_vtime;

		if (time_before(vtime, vtime_now - SCX_SLICE_DFL))
			vtime = vtime_now - SCX_SLICE_DFL;

		scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime,
					 enq_flags);
	}
}

void BPF_STRUCT_OPS(min_dispatch, s32 cpu, struct task_struct *prev)
{
	scx_bpf_dsq_move_to_local(SHARED_DSQ, 0);
}

void BPF_STRUCT_OPS(min_running, struct task_struct *p)
{
	if (fifo_sched)
		return;

	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(min_stopping, struct task_struct *p, bool runnable)
{
	if (fifo_sched)
		return;

	u64 delta = scale_by_task_weight_inverse(p, SCX_SLICE_DFL - p->scx.slice);

	scx_bpf_task_set_dsq_vtime(p, p->scx.dsq_vtime + delta);
}

void BPF_STRUCT_OPS(min_enable, struct task_struct *p)
{
	scx_bpf_task_set_dsq_vtime(p, vtime_now);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(min_init)
{
	int ret;

	ret = scx_bpf_create_dsq(SHARED_DSQ, -1);
	if (ret) {
		scx_bpf_error("failed to create DSQ %d (%d)", SHARED_DSQ, ret);
		return ret;
	}

	return 0;
}

void BPF_STRUCT_OPS(min_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(min_ops,
	       .select_cpu		= (void *)min_select_cpu,
	       .enqueue			= (void *)min_enqueue,
	       .dispatch		= (void *)min_dispatch,
	       .running			= (void *)min_running,
	       .stopping		= (void *)min_stopping,
	       .enable			= (void *)min_enable,
	       .init			= (void *)min_init,
	       .exit			= (void *)min_exit,
	       .name			= "min");
