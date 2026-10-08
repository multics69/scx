/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Changwoo Min <changwoo@igalia.com>
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

void BPF_STRUCT_OPS(min_exit, struct scx_exit_info *ei)
{
	bpf_printk("%s:%d", __func__, __LINE__);
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(min_ops,
	       .exit			= (void *)min_exit,
	       .timeout_ms		= 5000,
	       .name			= "min");
