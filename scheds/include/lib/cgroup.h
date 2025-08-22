/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Author: Changwoo Min <changwoo@igalia.com>
 */
#pragma once

#include <errno.h>
#include <lib/atq.h>

enum scx_cgroup_consts {
	/* cache line size of an architecture */
	SCX_CACHELINE_SIZE		= 64,
};

/**
 * Per-cgroup data structure containing cpu.max-related information.
 * In the future, it can be extended to support other features of cgroup
 * beyond cpu.max.
 */
struct scx_cgroup_ctx {
	/*
	 * Normalized quota by period of 100 msec. By using the same period,
	 * we can use a single BPF timer to handle all the cgroups.
	 */
	u64		nquota;

	/*
	 * The upper bound of a cgroup’s quota, which is the minimum
	 * normalized quota of all its ancestors and itself.
	 */
	u64		nquota_ub;

	/*
	 * We do not use normalized time for burst to accumulate unused time
	 * for more than 100 msec period. @burst and @period are given values
	 * in nanoseconds, and @period_start_clk represents when a new period
	 * starts. @burst_remaining is the maximum burst that can be
	 * accumulated until the end of the period from @period_start_clk.
	 */
	u64		period;
	u64		period_start_clk;
	u64		burst;
	s64		burst_remaining;

	/*
	 * The amount of remaining time out of @quota after LLC contexts
	 * deduct the budget for execution. It can be negative when the quota
	 * is over-allocated.
	 */
	s64		budget_remaining;

	/*
	 * Total amount of time executed once replenished. It includes
	 * @runtime_total of all LLC contexts of this cgroup. It is sloppy
	 * since it is updated only before asking more budget to its parent.
	 * In other words, it is not updated as @runtime_total of its LLC
	 * contexts are updated, so it could be outdated. When it is greater
	 * than @quota_ub, we cannot ask for more budget from the parent,
	 * so there will be no more updates on @runtime_total_sloppy before
	 * the next period starts.
	 */
	s64		runtime_total_sloppy;

	/*
	 * A boolean flag indicating whether the cgroup has LLC contexts.
	 */
	bool		has_llcx;

	/*
	 * A boolean flag indicating whether the cgroup is throttled or not.
	 * Note that the cgroup can be throttled before reaching the upper
	 * bound (nquota_nb) if the subrooot cgroup runs out of the time.
	 */
	bool		is_throttled;
};


/**
 * If a cgroup is either at a leaf level or threaded, we manage per-LLC-cgroup
 * contexts to reduce cross-LLC cache coherence traffic. Otherwise, the cgroup
 * stats are used only for distributing remaining budgets. In this case, we do
 * not manage per-LLC context since they will be accessed much less frequently.
 */
struct scx_cgroup_llc_ctx {
	/*
	 * The amount of remaining time reserved before task execution.
	 * When @budget_remaining becomes zero (or negative), we ask
	 * more time budget to the scx_cgroup_ctx. When no budget remains
	 * the scx_cgroup_ctx, we walk up the cgroup hierarchy. It can be
	 * negative when the quota is over-booked.
	 *
	 * The budget that was chunk-allocated from the upper level may not
	 * be fully used. Such remaining time at the LLC level will be carried
	 * over to the next period for eventual quota enforcement.
	 */
	s64		budget_remaining;

	/*
	 * Total amount of time executed once replenished. It should not
	 * exceed @quota_ub.
	 */
	s64		runtime_total;

	/*
	 * Tasks that can not be enqueued when the cgroup is running out
	 * of time (i.e., throttled). In this case, tasks will be enqueued
	 * to the backlog task queue (BTQ) for later execution. Tasks in the
	 * BTQ are ordered by vtime and will be enqueued to a proper DSQ
	 * for execution when the cgroup becomes unthrottled again.
	 *
 	 * When moving a task from BTQ to a proper DSQ, we need to choose a
 	 * target CPU by considering CPU idle status, task’s previous CPU, etc.
 	 * Since DSQ does not support a pop-like operation that dispatches a
	 * task from the DSQ without moving to another DSQ, we use ATQ as a
	 * backend of BTQ.
	 */
	scx_atq_t	*btq;
} __attribute__((aligned(SCX_CACHELINE_SIZE)));

/**
 * Configs for cpu.max
 */
struct scx_cgroup_bw_config {
	/* The budget allocation from a parent cgroup to a child cgroup in nsec. */
	u64		budget_p2c;
	/* The budget allocation from a cgroup to its LLC context in nsec. */
	u64		budget_c2l;
	/* The number of LLC domains. LLC ID should be in [0, nr_llcs). */
	int		nr_llcs;
	/* verbose level */
	int		verbose;
};

/**
 * scx_cgroup_bw_lib_init - Initialize the library with a configuration.
 * @config: tunnables, see the struct definition.
 *
 * It should be called for the library initialization before calling any
 * other API.
 *
 * Return 0 for success, -errno for failure.
 */
int scx_cgroup_bw_lib_init(struct scx_cgroup_bw_config *config);

/**
 * scx_cgroup_bw_init - 
 * @cgrp:
 * @args:
 *
 * Returns
 */
int scx_cgroup_bw_init(struct cgroup *cgrp __arg_trusted, struct scx_cgroup_init_args *args __arg_trusted);

/**
 * scx_cgroup_bw_exit - 
 * @cgrp:
 *
 * Returns
 */
int scx_cgroup_bw_exit(struct cgroup *cgrp __arg_trusted);

/**
 * scx_cgroup_bw_set - 
 * @cgrp:
 *
 * Returns
 */
int scx_cgroup_bw_set(struct cgroup *cgrp __arg_trusted, u64 period_us, u64 quota_us, u64 burst_us);

/**
 * scx_cgroup_bw_reserve - 
 * @cgrp:
 * @llc_id:
 * @slice_ns:
 *
 * Returns
 */
int scx_cgroup_bw_reserve(struct cgroup *cgrp __arg_trusted, int llc_id, u64 slice_ns);

/**
 * scx_cgroup_bw_consume - 
 * @cgrp:
 * @llc_id:
 * @reserved_ns:
 * @consumed_ns:
 *
 * Returns
 */
int scx_cgroup_bw_consume(struct cgroup *cgrp __arg_trusted, int llc_id, u64 reserved_ns, u64 consumed_ns);

/**
 * scx_cgroup_bw_put_aside - 
 * @p:
 * @vtime:
 * @cgrp:
 * @llc_id:
 *
 * Returns
 */
int scx_cgroup_bw_put_aside(struct task_struct *p __arg_trusted, u64 vtime, struct cgroup *cgrp __arg_trusted, int llc_id);

/**
 * REGISTER_SCX_CGROUP_BW_ENQUEUE_CB - Register an enqueue callback.
 * @enqueue_cb: A function name with a prototype of 'void fn(pid_t pid)'.
 *
 * @enqueue_cb enqueues a task with @pid following the BPF scheduler's
 * regular enqueue path. @enqueue_cb will be called when a throttled cgroup
 * becomes available again or when the cgroup is exiting for some reason.
 * @enqueue_cb MUST enqueue the task; otherwise, the task will be lost and
 * never be scheduled.
 */
#define REGISTER_SCX_CGROUP_BW_ENQUEUE_CB(enqueue_cb)				\
	__hidden int scx_group_bw_enqueue_cb(pid_t pid)				\
	{									\
		extern int enqueue_cb(pid_t pid);				\
		enqueue_cb(pid);						\
		return 0;							\
	}

extern int scx_group_bw_enqueue_cb(pid_t pid);
