/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Changwoo Min <changwoo@igalia.com>
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

#define SHARED_DSQ 0

void BPF_STRUCT_OPS(min_enqueue, struct task_struct *p, u64 enq_flags)
{
	bpf_printk("%s:%d: %s[%d]", __func__, __LINE__, p->comm, p->pid);
	scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
}

void BPF_STRUCT_OPS(min_dispatch, s32 cpu, struct task_struct *prev)
{
	bpf_printk("%s:%d", __func__, __LINE__);
	scx_bpf_dsq_move_to_local(SHARED_DSQ, 0);
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
	       .init			= (void *)min_init,
	       .exit			= (void *)min_exit,
	       .timeout_ms		= 5000,
	       .name			= "min");
