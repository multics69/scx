/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025 Valve Corporation.
 * Author: Changwoo Min <changwoo@igalia.com>
 */

/*
 * To be included to the main.bpf.c
 */

static void plan_x_cpdom_migration(void)
{
	struct cpdom_ctx *cpdomc;
	u64 dsq_id;
	u32 stealer_threshold, stealee_threshold, nr_stealee = 0;
	u64 avg_sc_load = 0, x_mig_delta, util, q_len, nr_nz_cpdoms = 0;

	/*
	 * The load balancing aims for two goals:
	 *
	 * 1) The *non-scaled* CPU utilizations of all active CPUs should be
	 * the same or similar. This helps to maintain low latency
	 * when the system is underloaded.
	 *
	 * 2) The *scaled* queue lengths of active compute domains should be
	 * the same or similar. Using scaled queue length allows putting more
	 * tasks to the powerful compute domains. This helps to maintain high
	 * throughput when the system is overloaded.
	 */

	/*
	 * Calcualte scaled load for each compute domain.
	 */
	bpf_for(dsq_id, 0, nr_cpdoms) {
		if (dsq_id >= LAVD_CPDOM_MAX_NR)
			break;

		cpdomc = MEMBER_VPTR(cpdom_ctxs, [dsq_id]);

		util = (cpdomc->cur_util_sum << LAVD_SHIFT) / cpdomc->nr_active_cpus;
		q_len = (cpdomc->nr_queued_task << (LAVD_SHIFT * 3)) / cpdomc->cap_sum_active_cpus;
		cpdomc->sc_load = q_len + util;

		if (cpdomc->sc_load > 0) {
			avg_sc_load += cpdomc->sc_load;
			nr_nz_cpdoms++;
		}
	}
	if (nr_nz_cpdoms)
		avg_sc_load /= nr_nz_cpdoms;

	/*
	 * Determine stealer and stealee domains.
	 */
	x_mig_delta = avg_sc_load >> LAVD_CPDOM_MIGRATION_SHIFT;
	stealer_threshold = avg_sc_load - x_mig_delta;
	stealee_threshold = avg_sc_load + x_mig_delta;

	bpf_for(dsq_id, 0, nr_cpdoms) {
		if (dsq_id >= LAVD_CPDOM_MAX_NR)
			break;

		cpdomc = MEMBER_VPTR(cpdom_ctxs, [dsq_id]);

		/*
		 * Under-loaded active domains become a stealer.
		 */
		if (cpdomc->nr_active_cpus &&
		    cpdomc->nr_q_tasks_per_cpu < stealer_threshold) {
			WRITE_ONCE(cpdomc->is_stealer, true);
			WRITE_ONCE(cpdomc->is_stealee, false);
			continue;
		}

		/*
		 * Over-loaded or non-active domains become a stealee.
		 */
		if (!cpdomc->nr_active_cpus ||
		    cpdomc->nr_q_tasks_per_cpu > stealee_threshold) {
			WRITE_ONCE(cpdomc->is_stealer, false);
			WRITE_ONCE(cpdomc->is_stealee, true);
			nr_stealee++;
			continue;
		}

		/*
		 * Otherwise, keep tasks as it is.
		 */
		WRITE_ONCE(cpdomc->is_stealer, false);
		WRITE_ONCE(cpdomc->is_stealee, false);
	}

	sys_stat.nr_stealee = nr_stealee;
}

static bool consume_dsq(u64 dsq_id)
{
	/*
	 * Try to consume a task on the associated DSQ.
	 */
	return scx_bpf_dsq_move_to_local(dsq_id);
}

static bool try_to_steal_task(struct cpdom_ctx *cpdomc)
{
	struct cpdom_ctx *cpdomc_pick;
	s64 nr_nbr, dsq_id;
	s64 nuance;

	/*
	 * If all CPUs are not used -- i.e., the system is under-utilized,
	 * there is no point of load balancing. It is better to make an
	 * effort to increase the system utilization.
	 */
	if (!use_full_cpus())
		return false;

	/*
	 * Probabilistically make a go or no go decision to avoid the
	 * thundering herd problem. In other words, one out of nr_cpus
	 * will try to steal a task at a moment.
	 */
	if (!prob_x_out_of_y(1, cpdomc->nr_cpus * LAVD_CPDOM_X_PROB_FT))
		return false;

	/*
	 * Traverse neighbor compute domains in distance order.
	 */
	nuance = bpf_get_prandom_u32();
	for (int i = 0; i < LAVD_CPDOM_MAX_DIST; i++) {
		nr_nbr = min(cpdomc->nr_neighbors[i], LAVD_CPDOM_MAX_NR);
		if (nr_nbr == 0)
			break;

		/*
		 * Traverse neighbor in the same distance in arbitrary order.
		 */
		for (int j = 0; j < LAVD_CPDOM_MAX_NR; j++, nuance = dsq_id + 1) {
			if (j >= nr_nbr)
				break;

			dsq_id = pick_any_bit(cpdomc->neighbor_bits[i], nuance);
			if (dsq_id < 0)
				continue;

			cpdomc_pick = MEMBER_VPTR(cpdom_ctxs, [dsq_id]);
			if (!cpdomc_pick) {
				scx_bpf_error("Failed to lookup cpdom_ctx for %llu", dsq_id);
				return false;
			}

			if (!cpdomc_pick->is_stealee || !cpdomc_pick->is_valid)
				continue;

			/*
			 * If task stealing is successful, mark the stealer
			 * and the stealee's job done. By marking done,
			 * those compute domains would not be involved in
			 * load balancing until the end of this round,
			 * so this helps gradual migration. Note that multiple
			 * stealers can steal tasks from the same stealee.
			 * However, we don't coordinate concurrent stealing
			 * because the chance is low and there is no harm
			 * in slight over-stealing.
			 */
			if (consume_dsq(dsq_id)) {
				WRITE_ONCE(cpdomc_pick->is_stealee, false);
				WRITE_ONCE(cpdomc->is_stealer, false);
				return true;
			}
		}

		/*
		 * Now, we need to steal a task from a farther neighbor
		 * for load balancing. Since task migration from a farther
		 * neighbor is more expensive (e.g., crossing a NUMA boundary),
		 * we will do this with a lot of hesitation. The chance of
		 * further migration will decrease exponentially as distance
		 * increases, so, on the other hand, it increases the chance
		 * of closer migration.
		 */
		if (!prob_x_out_of_y(1, LAVD_CPDOM_X_PROB_FT))
			break;
	}

	return false;
}

static bool force_to_steal_task(struct cpdom_ctx *cpdomc)
{
	struct cpdom_ctx *cpdomc_pick;
	s64 nr_nbr, dsq_id;
	s64 nuance;

	/*
	 * Traverse neighbor compute domains in distance order.
	 */
	nuance = bpf_get_prandom_u32();
	for (int i = 0; i < LAVD_CPDOM_MAX_DIST; i++) {
		nr_nbr = min(cpdomc->nr_neighbors[i], LAVD_CPDOM_MAX_NR);
		if (nr_nbr == 0)
			break;

		/*
		 * Traverse neighbor in the same distance in arbitrary order.
		 */
		for (int j = 0; j < LAVD_CPDOM_MAX_NR; j++, nuance = dsq_id + 1) {
			if (j >= nr_nbr)
				break;

			dsq_id = pick_any_bit(cpdomc->neighbor_bits[i], nuance);
			if (dsq_id < 0)
				continue;

			cpdomc_pick = MEMBER_VPTR(cpdom_ctxs, [dsq_id]);
			if (!cpdomc_pick) {
				scx_bpf_error("Failed to lookup cpdom_ctx for %llu", dsq_id);
				return false;
			}

			if (!cpdomc_pick->is_valid)
				continue;

			if (consume_dsq(dsq_id))
				return true;
		}
	}

	return false;
}

static bool consume_task(u64 dsq_id)
{
	struct cpdom_ctx *cpdomc;

	cpdomc = MEMBER_VPTR(cpdom_ctxs, [dsq_id]);
	if (!cpdomc) {
		scx_bpf_error("Failed to lookup cpdom_ctx for %llu", dsq_id);
		return false;
	}

	/*
	 * If the current compute domain is a stealer, try to steal
	 * a task from any of stealee domains probabilistically.
	 */
	if (nr_cpdoms > 1 && READ_ONCE(cpdomc->is_stealer) &&
	    try_to_steal_task(cpdomc))
		goto x_domain_migration_out;

	/*
	 * Try to consume a task from CPU's associated DSQ.
	 */
	if (consume_dsq(dsq_id))
		return true;

	/*
	 * If there is no task in the assssociated DSQ, traverse neighbor
	 * compute domains in distance order -- task stealing.
	 */
	if (nr_cpdoms > 1 && force_to_steal_task(cpdomc))
		goto x_domain_migration_out;

	return false;

	/*
	 * Task migration across compute domains happens.
	 */
x_domain_migration_out:
	return true;
}
