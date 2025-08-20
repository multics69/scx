/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Author: Changwoo Min <changwoo@igalia.com>
 */

#include <scx/common.bpf.h>

#include <lib/cgroup.h>

__hidden
int scx_cgroup_bw_lib_init(struct scx_cgroup_bw_config *config)
{
	return -ENOTSUP;
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
