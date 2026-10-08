/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Changwoo Min <changwoo@igalia.com>
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

#define SHARED_DSQ 0

struct task_ctx {
	u64 avg_runtime;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

void BPF_STRUCT_OPS(min_enqueue, struct task_struct *p, u64 enq_flags)
{
	u64 vtime = bpf_ktime_get_ns();

	bpf_printk("%s:%d: %s[%d]", __func__, __LINE__, p->comm, p->pid);
	scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime, enq_flags);
}

void BPF_STRUCT_OPS(min_dispatch, s32 cpu, struct task_struct *prev)
{
	bpf_printk("%s:%d", __func__, __LINE__);
	scx_bpf_dsq_move_to_local(SHARED_DSQ, 0);
}

s32 BPF_STRUCT_OPS(min_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	bpf_printk("%s:%d: %s[%d]", __func__, __LINE__, p->comm, p->pid);

	if (!bpf_task_storage_get(&task_ctx_stor, p, 0,
				  BPF_LOCAL_STORAGE_GET_F_CREATE))
		return -ENOMEM;

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(min_init)
{
	bpf_printk("%s:%d", __func__, __LINE__);
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(min_exit, struct scx_exit_info *ei)
{
	bpf_printk("%s:%d", __func__, __LINE__);
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(min_ops,
	       .enqueue			= (void *)min_enqueue,
	       .dispatch		= (void *)min_dispatch,
	       .init_task		= (void *)min_init_task,
	       .init			= (void *)min_init,
	       .exit			= (void *)min_exit,
	       .timeout_ms		= 5000,
	       .name			= "min");
