/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Author: Changwoo Min <changwoo@igalia.com>
 */

#include <scx/common.bpf.h>

#include <lib/cgroup.h>

enum scx_cgroup_internal_consts {
	CBW_CLOCK_BOOTTIME		= 7,
	/* normalized period in nsec: 100 msec */
	CBW_NPERIOD			= (100ULL * 1000ULL * 1000ULL),
	/* maximum number of scx_cgroup_llc_ctx: 2048 cgroups * 32 LLCs */
	CBW_NR_CGRP_LLC_MAX		= (2048 * 32),
	/* unlimited quota ("max") */
	CBW_RUNTUME_INF			= ((u64)~0ULL),
};

/*
 * Library-wide configuration for CPU bandwidth control.
 */
static struct scx_cgroup_bw_config cbw_config;

/*
 * A map to store scx_cgroup_ctx. It is accessed through a cgroup pointer. 
 */
struct {
	__uint(type, BPF_MAP_TYPE_CGRP_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct scx_cgroup_ctx);
} cbw_cgrp_map SEC(".maps");

/*
 * A map to store scx_cgroup_llc_ctx. It is accessed through a pair of
 * cgroup id and LLC id (struct cgroup_llc_id), where LLC id should be
 * in a range of [0, cbw_config.nr_llcs).
 */
struct cgroup_llc_id {
	u64		cgrp_id;
	int		llc_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct cgroup_llc_id);
	__type(value, struct scx_cgroup_llc_ctx);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, CBW_NR_CGRP_LLC_MAX);
} cbw_cgrp_llc_map SEC(".maps");


/*
 * Timer to replenish time budget for all cgroups periodically.
 */
struct replenish_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct replenish_timer);
} replenish_timer SEC(".maps") __weak;

/*
 * Debug macros.
 */
#define cbw_err(...) do { 							\
	bpf_printk(__VA_ARGS__);						\
} while(0)

#define cbw_dbg(fmt, ...) do { 							\
	if (cbw_config.verbose > 0)						\
		bpf_printk("[%s:%d] " fmt, __func__, __LINE__, ##__VA_ARGS__);	\
} while(0)

/*
 * Arithmetic helpers.
 */
#ifndef min
#define min(X, Y) (((X) < (Y)) ? (X) : (Y))
#endif

#ifndef max
#define max(X, Y) (((X) < (Y)) ? (Y) : (X))
#endif

#ifndef clamp
#define clamp(val, lo, hi) min(max(val, lo), hi)
#endif

static
u64 div_round_up(u64 dividend, u64 divisor)
{
	return (dividend + divisor - 1) / divisor;
}

/*
 * A handler function for the replenish timer.
 */
static
int replenish_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	/* TODO: to be implemented */
	return 0;
}

/*
 * Check if the kernel support cpu.max for scx schedulers.
 */
static
bool is_kernel_compatible(void)
{
	struct scx_cgroup_init_args args;
	return bpf_core_field_exists(args.bw_period_us);
}

/**
 * scx_cgroup_bw_lib_init - Initialize the library with a configuration.
 * @config: tunnables, see the struct definition.
 *
 * It should be called for the library initialization before calling any
 * other API.
 *
 * Return 0 for success, -errno for failure.
 */
int scx_cgroup_bw_lib_init(struct scx_cgroup_bw_config *config)
{
	struct bpf_timer *timer;
	int err;
	u32 key = 0;

	/* If the kernel does not support cpu.max, let's stop here. */
	if (!is_kernel_compatible())
		return -ENOTSUP;

	/* Initialize the library-wide configuration. */
	if (!config)
		return -EINVAL;
	cbw_config = *config;

	/* Initialize the replenish timer. */
	timer = bpf_map_lookup_elem(&replenish_timer, &key);
	if (!timer) {
		cbw_err("Failed to lookup replenish timer");
		return -ESRCH;
	}

	bpf_timer_init(timer, &replenish_timer, CBW_CLOCK_BOOTTIME);
	bpf_timer_set_callback(timer, replenish_timerfn);
	err = bpf_timer_start(timer, CBW_NPERIOD, 0);
	if (err) {
		cbw_err("Failed to start replenish timer");
		return err;
	}

	return 0;
}

static
bool cgroup_is_threaded(struct cgroup *cgrp)
{
	return cgrp->dom_cgrp != cgrp;
}

static
u64 cgroup_get_id(struct cgroup *cgrp)
{
	return cgrp->kn->id;
}

static
struct scx_cgroup_ctx *cbw_get_cgroup_ctx(struct cgroup *cgrp)
{
	return bpf_cgrp_storage_get(&cbw_cgrp_map, cgrp, 0, 0);
}

static
struct scx_cgroup_llc_ctx *cbw_alloc_llc_ctx(struct cgroup *cgrp, int llc_id)
{
	static const struct scx_cgroup_llc_ctx llcx0;
	struct scx_cgroup_llc_ctx *llcx;
	struct cgroup_llc_id key = {
		.cgrp_id = cgroup_get_id(cgrp),
		.llc_id = llc_id,
	};

	if (bpf_map_update_elem(&cbw_cgrp_llc_map, &key, &llcx0, BPF_NOEXIST))
		return NULL;

	llcx = bpf_map_lookup_elem(&cbw_cgrp_llc_map, &key);
	if (!llcx)
		return NULL;

	llcx->btq = (scx_atq_t *)scx_atq_create(false);
	if (!llcx->btq) {
		cbw_err("Fail to allocate a BTQ");
		bpf_map_delete_elem(&cbw_cgrp_llc_map, &key);
		return NULL;
	}

	return llcx;
}

static
struct scx_cgroup_llc_ctx *cbw_get_llc_ctx(struct cgroup *cgrp, int llc_id)
{
	struct cgroup_llc_id key = {
		.cgrp_id = cgroup_get_id(cgrp),
		.llc_id = llc_id,
	};

	return bpf_map_lookup_elem(&cbw_cgrp_llc_map, &key);
}

static
long cbw_del_llc_ctx(struct cgroup *cgrp, int llc_id)
{
	struct cgroup_llc_id key = {
		.cgrp_id = cgroup_get_id(cgrp),
		.llc_id = llc_id,
	};

	return bpf_map_delete_elem(&cbw_cgrp_llc_map, &key);
}

static
void cbw_drain_n_free_btq(scx_atq_t *btq)
{
	u64 pid64;

	/*
	 * Pop all the tasks in the BTQ and ask the BPF scheduler to enqueue
	 * them to a DSQ for execution.
	 */
	while ((pid64 = scx_atq_pop(btq)) && can_loop) {
		pid_t pid = (pid_t)pid64;
		scx_group_bw_enqueue_cb(pid);
	}

	/* Note that ATQ does not provide an API to delete itself. */
}

static
int cbw_init_llc_ctx(struct cgroup *cgrp, struct scx_cgroup_ctx *cgx)
{
	int i;

	if (!cgx || !cgrp)
		return -EINVAL;

	bpf_for(i, 0, cbw_config.nr_llcs) {
		struct scx_cgroup_llc_ctx *llcx;

		llcx = cbw_alloc_llc_ctx(cgrp, i);
		if (!llcx)
			return -ENOMEM;
	}
	cgx->has_llcx = true;

	return 0;
}

static
void cbw_free_llc_ctx(struct cgroup *cgrp, struct scx_cgroup_ctx *cgx)
{
	int i;

	if (!cgrp)
		return;

	if (cgx)
		cgx->has_llcx = false;

	bpf_for(i, 0, cbw_config.nr_llcs) {
		struct scx_cgroup_llc_ctx *llcx;
		scx_atq_t *btq;

		llcx = cbw_get_llc_ctx(cgrp, i);
		if (!llcx)
			break;

		btq = llcx->btq;
		if (!cbw_del_llc_ctx(cgrp, i))
			cbw_drain_n_free_btq(btq);
	}
}

static
int cbw_update_nquota_ub(struct cgroup *cgrp, struct scx_cgroup_ctx *cgx)
{
	struct cgroup *parent;
	struct scx_cgroup_ctx *parentx;

	/*
	 * We assume that all its ancestors' nquota_ub are already updated
	 * (e.g., pre-order traversal of the cgroup tree). Hence, we don't
	 * need to walk up all its ancestors to get the minimum, so we compare
	 * against its parent's nquota_ub.
	 */
	cgx->nquota_ub = cgx->nquota;
	if ((parent = bpf_cgroup_ancestor(cgrp, 1))) {
		parentx = cbw_get_cgroup_ctx(parent);
		if (!parentx) {
			bpf_cgroup_release(parent);
			cbw_err("Fail to lookup a cgroup context");
			return -ESRCH;
		}

		cgx->nquota_ub = min(cgx->nquota_ub, parentx->nquota);
		bpf_cgroup_release(parent);
	}

	return 0;
}

static
void cbw_set_bandwidth(struct cgroup *cgrp, struct scx_cgroup_ctx *cgx,
		       u64 period_us, u64 quota_us, u64 burst_us)
{
	cgx->period = period_us * 1000;
	cgx->period_start_clk = scx_bpf_now();

	if (quota_us == CBW_RUNTUME_INF) {
		cgx->nquota = CBW_RUNTUME_INF;
		cgx->burst = 0;
	} else {
		cgx->nquota = div_round_up(quota_us * CBW_NPERIOD, period_us);
		cgx->burst = burst_us * 1000;
	}
}

/**
 * scx_cgroup_bw_init - Initialize a cgroup for CPU bandwidth control.
 * @cgrp: cgroup being initialized.
 * @args: init arguments, see the struct definition.
 *
 * Either the BPF scheduler is being loaded or @cgrp created, initialize
 * @cgrp for CPU bandwidth control. When being loaded, cgroups are initialized
 * in a pre-order from the root. This operation may block.
 *
 * Return 0 for success, -errno for failure.
 */
int scx_cgroup_bw_init(struct cgroup *cgrp __arg_trusted, struct scx_cgroup_init_args *args __arg_trusted)
{
	struct scx_cgroup_ctx *cgx, *parentx;
	struct cgroup *parent;

	/*
	 * Allocate and initialize scx_cgroup_ctx for @cgrp.
	 *
	 * For the cgroup directly under the root cgroup
	 * (i.e., its level == 1), budget the full quota to itself,
	 * so the cgroup can distribute the budget to its descendants
	 * when requested.
	 */
	cgx = bpf_cgrp_storage_get(&cbw_cgrp_map, cgrp, 0,
				   BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!cgx) {
		cbw_err("Failed to allocate cgroup ctx");
		return -ENOMEM;
	}

	cbw_set_bandwidth(cgrp, cgx, args->bw_period_us, args->bw_quota_us,
			  args->bw_burst_us);
	cbw_update_nquota_ub(cgrp, cgx);
	cgx->runtime_total_sloppy = 0;
	cgx->budget_remaining = (cgrp->level == 1)? cgx->nquota : 0;
	cgx->is_throttled = false;

	/*
	 * The parent of @cgrp becomes non-leaf. If the parent is not
	 * threaded, it cannot have tasks. So, we should free its
	 * per-LLC-cgroup contexts.
	 */
	if ((parent = bpf_cgroup_ancestor(cgrp, 1))) {
		if (!cgroup_is_threaded(parent)) {
			parentx = cbw_get_cgroup_ctx(parent);
			cbw_free_llc_ctx(parent, parentx);
		}
		bpf_cgroup_release(parent);
	}

	/*
	 * Create per-LLC-cgroup contexts if @cgrp can have tasks (i.e.,
	 * a cgroup is either at the leaf level or threaded). Here, @cgrp
	 * is at the leaf (a cgroup is a leaf until its child is created),
	 * so we will create per-LLC-cgroup contexts anyway.
	 */
	return cbw_init_llc_ctx(cgrp, cgx);
}

int scx_cgroup_bw_exit(struct cgroup *cgrp __arg_trusted)
{
	return -ENOTSUP;
}

/**
 * scx_cgroup_bw_set - A cgroup's bandwidth is being changed.
 * @cgrp: cgroup whose bandwidth is being updated
 * @period_us: bandwidth control period
 * @quota_us: bandwidth control quota
 * @burst_us: bandwidth control burst
 *
 * Update @cgrp's bandwidth control parameters. This is from the cpu.max
 * cgroup interface.
 *
 * @quota_us / @period_us determines the CPU bandwidth @cgrp is entitled
 * to. For example, if @period_us is 1_000_000 and @quota_us is
 * 2_500_000. @cgrp is entitled to 2.5 CPUs. @burst_us can be
 * interpreted in the same fashion and specifies how much @cgrp can
 * burst temporarily. The specific control mechanism and thus the
 * interpretation of @period_us and burstiness is upto to the BPF
 * scheduler.
 *
 * Return 0 for success, -errno for failure.
 */
int scx_cgroup_bw_set(struct cgroup *cgrp __arg_trusted, u64 period_us, u64 quota_us, u64 burst_us)
{
	struct cgroup *cur_cgrp;
	struct scx_cgroup_ctx *cgx, *cur_cgx;
	struct cgroup_subsys_state *subroot_css, *pos;
	int ret = 0;

	/* Update the cgroup's bandwidth. */
	cgx = cbw_get_cgroup_ctx(cgrp);
	if (!cgx) {
		cbw_err("Failed to lookup a cgroup ctx");
		return -ESRCH;
	}

	cbw_set_bandwidth(cgrp, cgx, period_us, quota_us, burst_us);

	/*
	 * Update nquota_ub of the cgroup and all its descendents in a
	 * top-down-like manner (pre-order traversal: self -> left -> right).
	 */
	bpf_rcu_read_lock();
	subroot_css = &cgrp->self;
	bpf_for_each(css, pos, subroot_css, BPF_CGROUP_ITER_DESCENDANTS_PRE) {
		cur_cgrp = pos->cgroup;
		cur_cgx = cbw_get_cgroup_ctx(cur_cgrp);
		if (!cur_cgx) {
			cbw_err("Failed to lookup a cgroup ctx");
			goto unlock_out;
		}

		ret = cbw_update_nquota_ub(cur_cgrp, cur_cgx);
		if (ret)
			goto unlock_out;
	}
unlock_out:
	bpf_rcu_read_unlock();
	return ret;
}

int scx_cgroup_bw_reserve(struct cgroup *cgrp __arg_trusted, int llc_id, u64 slice_ns)
{
	return -ENOTSUP;
}

int scx_cgroup_bw_consume(struct cgroup *cgrp __arg_trusted, int llc_id, u64 reserved_ns, u64 consumed_ns)
{
	return -ENOTSUP;
}
