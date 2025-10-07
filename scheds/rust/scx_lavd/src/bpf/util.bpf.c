/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023, 2024 Valve Corporation.
 * Author: Changwoo Min <changwoo@igalia.com>
 */

/*
 * To be included to the main.bpf.c
 */

/*
 * Sched related globals
 */
private(LAVD) struct bpf_cpumask __kptr *turbo_cpumask; /* CPU mask for turbo CPUs */
private(LAVD) struct bpf_cpumask __kptr *big_cpumask; /* CPU mask for big CPUs */
private(LAVD) struct bpf_cpumask __kptr *little_cpumask; /* CPU mask for little CPUs */
private(LAVD) struct bpf_cpumask __kptr *active_cpumask; /* CPU mask for active CPUs */
private(LAVD) struct bpf_cpumask __kptr *ovrflw_cpumask; /* CPU mask for overflow CPUs */

const volatile u64	nr_llcs;	/* number of LLC domains */
const volatile u64	__nr_cpu_ids;	/* maximum CPU IDs */
volatile u64		nr_cpus_onln;	/* current number of online CPUs */

const volatile u32	cpu_sibling[LAVD_CPU_ID_MAX]; /* siblings for CPUs when SMT is active */

/*
 * Options
 */
volatile bool		reinit_cpumask_for_performance;
volatile bool		no_preemption;
volatile bool		no_core_compaction;
volatile bool		no_freq_scaling;

const volatile bool	no_wake_sync;
const volatile bool	no_slice_boost;
const volatile bool	per_cpu_dsq;
const volatile bool	enable_cpu_bw;
const volatile bool	is_autopilot_on;
const volatile u8	verbose;

/*
 * Exit information
 */
UEI_DEFINE(uei);

/*
 * per-CPU globals
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct cpu_ctx);
	__uint(max_entries, 1);
} cpu_ctx_stor SEC(".maps");

/*
 * Per-task scheduling context
 */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, task_ctx);
} task_ctx_stor SEC(".maps");


__hidden
task_ctx *get_task_ctx(struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
}

__hidden
struct cpu_ctx *get_cpu_ctx(void)
{
	const u32 idx = 0;
	return bpf_map_lookup_elem(&cpu_ctx_stor, &idx);
}

__hidden
struct cpu_ctx *get_cpu_ctx_id(s32 cpu_id)
{
	const u32 idx = 0;
	return bpf_map_lookup_percpu_elem(&cpu_ctx_stor, &idx, cpu_id);
}

__hidden
struct cpu_ctx *get_cpu_ctx_task(const struct task_struct *p)
{
	return get_cpu_ctx_id(scx_bpf_task_cpu(p));
}

u32 __attribute__ ((noinline)) calc_avg32(u32 old_val, u32 new_val)
{
	/*
	 * Calculate the exponential weighted moving average (EWMA).
	 *  - EWMA = (0.875 * old) + (0.125 * new)
	 */
	return __calc_avg(old_val, new_val, 3);
}

u64 __attribute__ ((noinline)) calc_avg(u64 old_val, u64 new_val)
{
	/*
	 * Calculate the exponential weighted moving average (EWMA).
	 *  - EWMA = (0.875 * old) + (0.125 * new)
	 */
	return __calc_avg(old_val, new_val, 3);
}

u64 __attribute__ ((noinline)) calc_asym_avg(u64 old_val, u64 new_val)
{
	/*
	 * Increase fast but descrease slowly.
	 */
	if (old_val < new_val)
		return __calc_avg(new_val, old_val, 2);
	else
		return __calc_avg(old_val, new_val, 3);
}

u64 __attribute__ ((noinline)) calc_avg_freq(u64 old_freq, u64 interval)
{
	u64 new_freq, ewma_freq;

	/*
	 * Calculate the exponential weighted moving average (EWMA) of a
	 * frequency with a new interval measured.
	 */
	new_freq = LAVD_TIME_ONE_SEC / interval;
	ewma_freq = __calc_avg(old_freq, new_freq, 3);
	return ewma_freq;
}

static bool is_kernel_task(struct task_struct *p)
{
	return !!(p->flags & PF_KTHREAD);
}

static bool is_kernel_worker(struct task_struct *p)
{
	return !!(p->flags & (PF_WQ_WORKER | PF_IO_WORKER));
}

static bool is_pinned(const struct task_struct *p)
{
	return p->nr_cpus_allowed == 1;
}

__hidden
bool test_task_flag(task_ctx *taskc, u64 flag)
{
	return (taskc->flags & flag) == flag;
}

__hidden
void set_task_flag(task_ctx *taskc, u64 flag)
{
	taskc->flags |= flag;
}

__hidden
void reset_task_flag(task_ctx *taskc, u64 flag)
{
	taskc->flags &= ~flag;
}

__hidden
inline bool test_cpu_flag(struct cpu_ctx *cpuc, u64 flag)
{
	return (cpuc->flags & flag) == flag;
}

__hidden
inline void set_cpu_flag(struct cpu_ctx *cpuc, u64 flag)
{
	cpuc->flags |= flag;
}

__hidden
inline void reset_cpu_flag(struct cpu_ctx *cpuc, u64 flag)
{
	cpuc->flags &= ~flag;
}

__hidden
bool is_lat_cri(task_ctx *taskc)
{
	return taskc->lat_cri >= sys_stat.avg_lat_cri;
}

__hidden
bool is_lock_holder(task_ctx *taskc)
{
	return test_task_flag(taskc, LAVD_FLAG_FUTEX_BOOST);
}

__hidden
bool is_lock_holder_running(struct cpu_ctx *cpuc)
{
	return test_cpu_flag(cpuc, LAVD_FLAG_FUTEX_BOOST);
}

bool have_scheduled(task_ctx *taskc)
{
	/*
	 * If task's time slice hasn't been updated, that means the task has
	 * been scheduled by this scheduler.
	 */
	return taskc->slice != 0;
}

bool can_boost_slice(void)
{
	return sys_stat.nr_queued_task <= sys_stat.nr_active;
}

u16 get_nice_prio(struct task_struct __arg_trusted *p)
{
	u16 prio = p->static_prio - MAX_RT_PRIO; /* [0, 40) */
	return prio;
}

static bool use_full_cpus(void)
{
	return sys_stat.nr_active >= nr_cpus_onln;
}

s64 __attribute__ ((noinline)) pick_any_bit(u64 bitmap, u64 nuance)
{
	u64 i, pos;

	#pragma clang loop unroll(disable)
	bpf_for(i, 0, 64) {
		pos = (i + nuance) % 64;
		if (bitmap & (1LLU << pos))
			return pos;
	}

	return -ENOENT;
}

static void set_on_core_type(task_ctx *taskc,
			     const struct cpumask *cpumask)
{
	bool on_big = false, on_little = false;
	struct cpu_ctx *cpuc;
	int cpu;

	bpf_for(cpu, 0, __nr_cpu_ids) {
		if (!bpf_cpumask_test_cpu(cpu, cpumask))
			continue;

		cpuc = get_cpu_ctx_id(cpu);
		if (!cpuc) {
			scx_bpf_error("Failed to look up cpu_ctx: %d", cpu);
			return;
		}

		if (cpuc->big_core)
			on_big = true;
		else
			on_little = true;

		if (on_big && on_little)
			break;
	}

	if (on_big)
		set_task_flag(taskc, LAVD_FLAG_ON_BIG);
	else
		reset_task_flag(taskc, LAVD_FLAG_ON_BIG);

	if (on_little)
		set_task_flag(taskc, LAVD_FLAG_ON_LITTLE);
	else
		reset_task_flag(taskc, LAVD_FLAG_ON_LITTLE);
}

bool __attribute__ ((noinline)) prob_x_out_of_y(u32 x, u32 y)
{
	u32 r;

	if (x >= y)
		return true;

	/*
	 * [0, r, y)
	 *  ---- x?
	 */
	r = bpf_get_prandom_u32() % y;
	return r < x;
}
/*
 * We define the primary cpu in the physical core as the lowest logical cpu id.
 */
u32 __attribute__ ((noinline)) get_primary_cpu(u32 cpu) {
	const volatile u32 *sibling;

	if (!is_smt_active)
		return cpu;

	sibling = MEMBER_VPTR(cpu_sibling, [cpu]);
	if (!sibling) {
		debugln("Infeasible CPU id: %d", cpu);
		return cpu;
	}

	return ((cpu < *sibling) ? cpu : *sibling);
}

u32 cpu_to_dsq(u32 cpu)
{
	return (get_primary_cpu(cpu)) | LAVD_DSQ_TYPE_CPU << LAVD_DSQ_TYPE_SHFT;
}
