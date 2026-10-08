/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Changwoo Min <changwoo@igalia.com>
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

#define SHARED_DSQ 0

s64 nr_queued;

struct task_ctx {
	u64 running_at;
	u64 avg_runtime;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

#define min(x, y) (((x) < (y)) ? (x) : (y))
#define max(x, y) (((x) > (y)) ? (x) : (y))

s32 BPF_STRUCT_OPS(min_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;

	bpf_printk("%s:%d: %s[%d]", __func__, __LINE__, p->comm, p->pid);
	return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
}

void BPF_STRUCT_OPS(min_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *taskc;
	u64 vtime = bpf_ktime_get_ns();
	s64 nr;
	u64 slice;

	taskc = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (taskc) {
		u64 runtime = taskc->avg_runtime;

		if (enq_flags & SCX_ENQ_WAKEUP)
			runtime /= 2;
		vtime = (vtime & ~0xFFF) + min(runtime / 4000, 0xFFF);
	}

	nr = __sync_fetch_and_add(&nr_queued, 1) + 1;
	if (nr < 1)
		nr = 1;
	slice = max(SCX_SLICE_DFL / nr, 1);

	bpf_printk("%s:%d: %s[%d] -- %llu nr_queued=%lld slice=%llu", __func__, __LINE__,
		   p->comm, p->pid, vtime, nr, slice);
	scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, slice, vtime, enq_flags);
}

void BPF_STRUCT_OPS(min_dispatch, s32 cpu, struct task_struct *prev)
{
	bpf_printk("%s:%d", __func__, __LINE__);
	scx_bpf_dsq_move_to_local(SHARED_DSQ, 0);
}

void BPF_STRUCT_OPS(min_running, struct task_struct *p)
{
	struct task_ctx *taskc;

	bpf_printk("%s:%d: %s[%d]", __func__, __LINE__, p->comm, p->pid);

	__sync_fetch_and_sub(&nr_queued, 1);

	taskc = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!taskc)
		return;

	taskc->running_at = bpf_ktime_get_ns();
}

void BPF_STRUCT_OPS(min_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *taskc;
	u64 runtime;

	taskc = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!taskc)
		return;

	runtime = bpf_ktime_get_ns() - taskc->running_at;
	/*
	 * p->prio is 100 to 139 for normal tasks, 120 + nice, where a lower
	 * value means a higher priority. 120 is nice 0, whose runtime stays
	 * as is. A higher-priority task's runtime counts for less and a
	 * lower-priority task's for more.
	 */
	runtime = runtime * p->prio / 120;
	taskc->avg_runtime = (taskc->avg_runtime / 2) + (runtime / 2);

	bpf_printk("%s:%d: %s[%d] prio=%d runtime=%llu avg_runtime=%llu", __func__, __LINE__,
		   p->comm, p->pid, p->prio, runtime, taskc->avg_runtime);
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
	       .select_cpu		= (void *)min_select_cpu,
	       .enqueue			= (void *)min_enqueue,
	       .dispatch		= (void *)min_dispatch,
	       .running			= (void *)min_running,
	       .stopping		= (void *)min_stopping,
	       .init_task		= (void *)min_init_task,
	       .init			= (void *)min_init,
	       .exit			= (void *)min_exit,
	       .timeout_ms		= 5000,
	       .name			= "min");
