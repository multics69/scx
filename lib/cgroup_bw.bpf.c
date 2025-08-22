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

static
int replenish_timerfn(void *map, int *key, struct bpf_timer *timer);

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
 * Check if the kernel support cpu.max for scx schedulers.
 */
static
bool is_kernel_compatible(void)
{
	return bpf_core_field_exists(struct scx_cgroup_init_args, bw_period_us);
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
__hidden
int scx_cgroup_bw_lib_init(struct scx_cgroup_bw_config *config)
{
	struct bpf_timer *timer;
	int ret;
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
	if ((ret = bpf_timer_start(timer, CBW_NPERIOD, 0))) {
		cbw_err("Failed to start replenish timer");
		return ret;
	}

	return 0;
}

__hidden
int scx_cgroup_bw_init(struct cgroup *cgrp __arg_trusted, struct scx_cgroup_init_args *args __arg_trusted)
{
	return -ENOTSUP;
}

__hidden
int scx_cgroup_bw_exit(struct cgroup *cgrp __arg_trusted)
{
	return -ENOTSUP;
}

__hidden
int scx_cgroup_bw_set(struct cgroup *cgrp __arg_trusted, u64 period_us, u64 quota_us, u64 burst_us)
{
	return -ENOTSUP;
}

__hidden
int scx_cgroup_bw_reserve(struct cgroup *cgrp __arg_trusted, int llc_id, u64 slice_ns)
{
	return -ENOTSUP;
}

__hidden
int scx_cgroup_bw_consume(struct cgroup *cgrp __arg_trusted, int llc_id, u64 reserved_ns, u64 consumed_ns)
{
	return -ENOTSUP;
}

__hidden
int scx_cgroup_bw_put_aside(struct task_struct *p __arg_trusted, u64 vtime, struct cgroup *cgrp __arg_trusted, int llc_id)
{
	return -ENOTSUP;
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
