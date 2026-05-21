/* SPDX-License-Identifier: GPL-2.0 */
#include <scx/common.bpf.h>
#include "intf.h"
#include "lavd.bpf.h"
#include "util.bpf.h"
#include <errno.h>
#include <stdbool.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


/*
 * Preemption related ones
 */
struct preemption_info {
	u64		est_stopping_clk;
	u64		lat_cri;
	struct cpu_ctx	*cpuc;
};

__hidden
u64 get_est_stopping_clk(task_ctx *taskc, u64 now)
{
	/*
	 * Estimate the future wall-clock time when the task will stop running.
	 * avg_runtime_wall (wall clock) is used here because we are computing
	 * a future timestamp by adding a duration to `now` (wall clock).
	 * slice_wall is also wall-clock based, so both are in the same unit.
	 */
	return now + min(taskc->avg_runtime_wall, taskc->slice_wall);
}

static bool can_x_kick_y(struct preemption_info *prm_x,
			 struct preemption_info *prm_y)
{
	/*
	 * A caller should ensure that Y is not a lock holder.
	 */

	/*
	 * Check one's latency criticality and deadline.
	 */
	if ((prm_x->lat_cri > prm_y->lat_cri) &&
	    (prm_x->est_stopping_clk < prm_y->est_stopping_clk))
		return true;
	return false;
}

static bool can_x_kick_cpu2(struct preemption_info *prm_x,
			    struct preemption_info *prm_cpu2,
			    struct cpu_ctx *cpuc2)
{
	/*
	 * A CPU taken by an RT/DL task cannot be a victim.
	 */
	if (is_rt_or_dl_task_running(cpuc2->cpu_id))
		return false;

	/*
	 * Never preeempt a CPU running a lock holder.
	 */
	if (is_lock_holder_running(cpuc2))
		return false;

	/*
	 * Set a CPU information
	 */
	prm_cpu2->est_stopping_clk = cpuc2->est_stopping_clk;
	prm_cpu2->lat_cri = cpuc2->lat_cri;
	prm_cpu2->cpuc = cpuc2;

	/*
	 * If that CPU runs a lower priority task, that's a victim
	 * candidate.
	 */
	return can_x_kick_y(prm_x, prm_cpu2);
}

static void init_prm_by_task(struct preemption_info *prm_task,
			     task_ctx *taskc, u64 now)
{
	prm_task->est_stopping_clk = get_est_stopping_clk(taskc, now);
	prm_task->lat_cri = taskc->lat_cri;
	prm_task->cpuc = NULL;
}

static bool is_worth_kick_other_task(task_ctx *taskc)
{
	/*
	 * Preemption is not free. It is expensive involving context switching,
	 * etc. Hence, we first judiciously check whether it is worth trying to
	 * victimize another CPU as the current task is urgent enough.
	 */
	return (taskc->lat_cri >= sys_stat.thr_lat_cri);
}

static struct cpu_ctx *find_victim_cpu(const struct cpumask *cpumask,
				       s32 preferred_cpu,
				       task_ctx *taskc, u64 now)
{
	/*
	 * We see preemption as a load-balancing problem. In a system with N
	 * CPUs, ideally, the top N tasks with the highest latency priorities
	 * should run on the N CPUs all the time. This is the same as the
	 * load-balancing problem; the load-balancing problem finds a least
	 * loaded server, and the preemption problem finds a CPU running a
	 * least latency critical task. Hence, we use the 'power of two random
	 * choices' technique.
	 */
	struct cpu_ctx *cpuc;
	struct preemption_info prm_task, prm_cpus[2], *victim_cpu;
	int cpu, nr_cpus;
	int i, v = 0;
	int ret;

	/*
	 * Get task's preemption information for comparison.
	 */
	init_prm_by_task(&prm_task, taskc, now);

	/*
	 * If there is a preferred CPU on which a task wants to run,
	 * check that CPU first.
	 */
	if (preferred_cpu >= 0 && (cpuc = get_cpu_ctx_id(preferred_cpu))) {
		if (can_x_kick_cpu2(&prm_task, &prm_cpus[v], cpuc))
			v++;
	}

	/*
	 * Randomly find _two_ CPUs that run lower-priority tasks than @p. To
	 * traverse CPUs in a random order, we start from a random CPU ID in a
	 * random direction (left or right). The random-order traversal helps
	 * to mitigate the thundering herd problem. Otherwise, all CPUs may end
	 * up finding the same victim CPU.
	 *
	 * In the worst case, the current logic traverses _all_ CPUs. It would
	 * be too expensive to perform every task queue. We need to revisit
	 * this if the traversal cost becomes problematic.
	 */
	nr_cpus = bpf_cpumask_weight(cpumask);
	bpf_for(i, 0, nr_cpus) {

		/*
		 * Decide a CPU ID to examine.
		 */
		cpu = bpf_cpumask_any_distribute(cpumask);
		if (cpu >= nr_cpu_ids || cpu == preferred_cpu)
			continue;

		/*
		 * Check whether that CPU is qualified to run @p.
		 */
		cpuc = get_cpu_ctx_id(cpu);
		if (!cpuc) {
			scx_bpf_error("Failed to lookup cpu_ctx: %d", cpu);
			goto null_out;
		}

		if (!cpuc->is_online)
			continue;

		/*
		 * If that CPU runs a lower priority task, that's a victim
		 * candidate.
		 *
		 * Note that a task running on cpu 2 (prm_cpus[v]) cannot
		 * be a lock holder.
		 */
		ret = can_x_kick_cpu2(&prm_task, &prm_cpus[v], cpuc);
		if (ret == true && ++v >= 2)
			break;
	}

	/*
	 * Choose a final victim CPU.
	 */
	switch(v) {
	case 2:	/* two candidates */
		victim_cpu = can_x_kick_y(&prm_cpus[0], &prm_cpus[1]) ?
				&prm_cpus[0] : &prm_cpus[1];
		goto bingo_out;
	case 1:	/* one candidate */
		victim_cpu = &prm_cpus[0];
		goto bingo_out;
	case 0:	/* no candidate */
		goto null_out;
	default:/* something wrong */
		goto null_out;
	}

bingo_out:
	return victim_cpu->cpuc;

null_out:
	return NULL;
}

static void ask_cpu_yield_after(struct cpu_ctx *victim_cpuc, u64 new_slice)
{
	bpf_rcu_read_lock();
	/*
	 * Note that we avoid using scx_bpf_kick_cpu() on purpose.
	 * While scx_bpf_kick_cpu() can trigger a task preemption immediately,
	 * it incurs an expensive IPI operation. Furthermore, an IPI operation
	 * is more costly in certain processor architectures or in older
	 * generations of processors, causing performance variations among
	 * processors. Thus, let's avoid using the IPI, scx_bpf_kick_cpu(), and
	 * set the victim task's time slice to zero so the victim task yields
	 * the CPU in the next scheduling point.
	 */
	struct task_struct *victim_p = __COMPAT_scx_bpf_cpu_curr(victim_cpuc->cpu_id);

	if (victim_p) {
		/*
		 * Finding a victim is racy, but we do not coordinate. Thus,
		 * two different CPUs can choose the same victim CPU. We do not
		 * coordinate this on purpose because such a race is rare, but
		 * controlling it would impose high synchronization overhead.
		 *
		 * Instead, we set the victim's est_stopping_clk to zero
		 * atomically to avoid the same victim CPU can be chosen
		 * repeatedly. In addition, once updating the
		 * est_stopping_clk to zero succeeds, that means this CPU
		 * wins in preempting the victim CPU. Hence, let's set the
		 * victim task's time slice to one (not zero).
		 *
		 * Why not set the time slice to zero? We avoid setting the
		 * time slice to zero because the sched_ext core in the kernel
		 * fixes the zero time slice to the default time slice
		 * (SCX_SLICE_DFL, 20 msec).
		 */
		u64 old = victim_cpuc->est_stopping_clk;
		if (!old) {
			bpf_rcu_read_unlock();
			return;
		}

		/*
		 * If the new slice is one, this is the last time to be kicked,
		 * so set est_stopping_clk to zero. Otherwise, do not update
		 * est_stopping_clk so that the task can be kicked again with
		 * a shorter time slice later.
		 */
		new_slice = max(new_slice, 1);
		if (new_slice == 1) {
			bool ret = __sync_bool_compare_and_swap(
				&victim_cpuc->est_stopping_clk, old, 0);
			if (ret)
				WRITE_ONCE(victim_p->scx.slice, new_slice);
		} else {
			if (victim_p->scx.slice > new_slice)
				WRITE_ONCE(victim_p->scx.slice, new_slice);
		}

		/*
		 * __COMPAT_scx_bpf_cpu_curr() yields an untrusted_ptr that
		 * bpf_task_storage_get() refuses; re-acquire via pid to get
		 * a trusted reference, then release after setting the flag.
		 */
		victim_p = bpf_task_from_pid(victim_p->pid);
		if (victim_p) {
			task_ctx *victim_taskc = get_task_ctx(victim_p);
			if (victim_taskc)
				set_task_flag(victim_taskc, LAVD_FLAG_PREEMPTED);
			bpf_task_release(victim_p);
		}
	}
	bpf_rcu_read_unlock();
}

__hidden
int shrink_boosted_slice_remote(struct cpu_ctx *cpuc, u64 now)
{
	u64 duration_wall, new_slice_wall = 0;
	u64 target_slice_wall;

	/*
	 * Shrink the time slice of the slice-boosted task into a regular
	 * slice. If a task has already overrun, kick it immediately using
	 * IPI. Otherwise, just reduce the remaining time slice to the
	 * regular one.
	 */
	reset_cpu_flag(cpuc, LAVD_FLAG_SLICE_BOOST);

	/*
	 * If pinned_slice_ns is enabled and there are pinned tasks
	 * waiting on this CPU, use pinned slice instead of regular slice.
	 */
	target_slice_wall = (pinned_slice_ns && cpuc->nr_pinned_tasks) ?
				pinned_slice_ns : sys_stat.slice_wall;

	duration_wall = time_delta(now, cpuc->running_clk);
	if (target_slice_wall > duration_wall)
		new_slice_wall = time_delta(target_slice_wall, duration_wall);

	if (!new_slice_wall)
		scx_bpf_kick_cpu(cpuc->cpu_id, SCX_KICK_PREEMPT);
	else
		ask_cpu_yield_after(cpuc, new_slice_wall);

	cpuc->nr_preempt++;

	return 0;
}

__hidden
void shrink_slice_at_tick(struct task_struct *p, struct cpu_ctx *cpuc, u64 now)
{
	u64 ub_wall, duration_wall, new_slice_wall;

	/*
	 * Calculate the upper bound of running this task
	 * since it is scheduled this time.
	 */
	if (pinned_slice_ns)
		ub_wall = min(pinned_slice_ns, sys_stat.slice_wall);
	else
		ub_wall = sys_stat.slice_wall;

	/*
	 * Calculate how long the task has been running
	 * since it was scheduled.
	 */
	duration_wall = time_delta(now, cpuc->running_clk);

	/* Limit the task's time slice. */
	if (duration_wall >= ub_wall) {
		/*
		 * If the task is running beyond the current upper bound,
		 * stop it right now. Note that it is okay to set p->scx.slice
		 * to zero since this is supposed to be called by ops.tick(),
		 * which is the scheduling point.
		 */
		new_slice_wall = 0;
	} else {
		/*
		 * When pinned tasks are waiting to run, any task should not
		 * go beyond the current upper bound.
		 */
		new_slice_wall = time_delta(ub_wall, duration_wall);
	}

	scx_bpf_task_set_slice(p, new_slice_wall);
	reset_cpu_flag(cpuc, LAVD_FLAG_SLICE_BOOST);
	cpuc->nr_preempt++;
}

__hidden
void preempt_at_tick(struct task_struct *p, struct cpu_ctx *cpuc)
{
	reset_cpu_flag(cpuc, LAVD_FLAG_SLICE_BOOST);
	scx_bpf_task_set_slice(p, 0);

	cpuc->nr_preempt++;
}

__hidden
void try_find_and_kick_victim_cpu(struct task_struct *p,
					 task_ctx *taskc,
					 s32 preferred_cpu,
					 u64 cpdom_id)
{
	struct preemption_info prm_t, prm_c;
	struct bpf_cpumask *cd_cpumask, *cpumask;
	struct cpdom_ctx *cpdomc;
	struct cpu_ctx *cpuc_victim;
	struct cpu_ctx *cpuc_cur = NULL;
	u64 now, duration_wall, new_slice_wall = 0;

	/* Greedy tasks never preempt. */
	if (test_task_flag(taskc, LAVD_FLAG_IS_GREEDY))
		return;
	now = scx_bpf_now();

	/*
	 * Fast path for effectively-pinned tasks (a stricter subset of
	 * affinitized): they can run on a single CPU, so target that CPU
	 * directly -- no lat_cri worth-kick gate, no power-of-2 search,
	 * no soft "finish normal slice" treatment. Runs ahead of the
	 * slice-boost handling below so a wider-pinned victim doesn't
	 * get the soft "cancel boost + finish normal slice" landing
	 * just because it had been slice-boosted.
	 *
	 * The point is to let the pinned task and the displaced
	 * (wider-pinned) task run concurrently on different CPUs:
	 * preempting the wider-pinned task here means it migrates to
	 * another CPU in its own cpumask via its select_cpu/enqueue path
	 * on the next dispatch, rather than the pinned task sitting
	 * idle waiting for the wider-pinned task's slice to expire.
	 *
	 * Example: task A is pinned to CPUs 1..4 and running on CPU 1;
	 * task B is pinned to CPU 1 and just woke up. Without this
	 * fast path, B waits until A's slice expires on CPU 1. With
	 * it, A is preempted immediately and lands on CPU 2..4 via its
	 * own enqueue and select_cpu on the next dispatch, while B
	 * starts on CPU 1 right away -- both run concurrently instead
	 * of serializing.
	 *
	 * See the dispatch-side complement in consume_task()
	 * (balance.bpf.c): once this CPU yields, consume_task() biases
	 * toward cpu_dsq when the previous task was non-pinned (or when
	 * cpu_dsq has piled up), so the singly-pinned task actually wins
	 * the next dispatch on this CPU rather than losing by vtime to
	 * a cpdom_dsq task. The two halves are designed together: this
	 * yields the CPU, consume_task() makes sure the pinned task
	 * gets it.
	 */
	if (!no_pinned_preempt && is_effectively_pinned(taskc)) {
		if (preferred_cpu < 0)
			return;
		cpuc_victim = get_cpu_ctx_id(preferred_cpu);
		if (!cpuc_victim)
			return;

		if (is_lock_holder_running(cpuc_victim)) {
			/*
			 * Don't preempt a lock holder. But if it is
			 * slice-boosted, cancel the boost so its slice
			 * shrinks to a normal one; the pinned task waits
			 * less after the lock is released.
			 */
			if (test_cpu_flag(cpuc_victim, LAVD_FLAG_SLICE_BOOST)) {
				duration_wall = time_delta(now,
						cpuc_victim->running_clk);
				if (sys_stat.slice_wall > duration_wall) {
					new_slice_wall = time_delta(
							sys_stat.slice_wall,
							duration_wall);
					ask_cpu_yield_after(cpuc_victim,
							    new_slice_wall);
				}
				reset_cpu_flag(cpuc_victim,
					       LAVD_FLAG_SLICE_BOOST);
			}
			return;
		}

		/* Don't displace another effectively-pinned task. */
		if (test_cpu_flag(cpuc_victim, LAVD_FLAG_IS_EFFECTIVELY_PINNED))
			return;

		/*
		 * new_slice_wall stays 0 -> ask_cpu_yield_after clamps to 1
		 * -> immediate yield at the next scheduling point.
		 */
		goto kick_out;
	}

	/*
	 * Non-pinned path. Preemption is not free -- context switch,
	 * possibly an IPI, and a hit to the victim's cache locality --
	 * so check whether the enqueuing task is latency-critical
	 * enough to be worth the effort before falling into the
	 * slice-boost handling and the power-of-2 victim search below.
	 */
	if (!is_worth_kick_other_task(taskc))
		return;

	/*
	 * If a slice-boosted task is running on the preferred CPU, check
	 * if it is necessary to preempt the task immediately or reduce
	 * its time slice.
	 */
	if (!no_slice_boost &&
	    (preferred_cpu >= 0) &&
	    (cpuc_victim = get_cpu_ctx_id(preferred_cpu)) &&
	    test_cpu_flag(cpuc_victim, LAVD_FLAG_SLICE_BOOST)) {
		/*
		 * If the enqueuing task is more latency-critical, let's
		 * cancel the slice boosting and kick the boosted task
		 * immediately.
		 */
		duration_wall = time_delta(now, cpuc_victim->running_clk);
		if (duration_wall >= sys_stat.slice_wall) {
			init_prm_by_task(&prm_t, taskc, now);
			if (can_x_kick_cpu2(&prm_t, &prm_c, cpuc_victim)) {
				reset_cpu_flag(cpuc_victim, LAVD_FLAG_SLICE_BOOST);
				goto kick_out;
			}
		}

		/*
		 * If the enqueuing task is affinitized, it should run on
		 * the preferred CPU. To avoid the affinitized task being
		 * delayed too long, let's cancel the slice boosting so that
		 * the currently running task on the preferred CPU is
		 * scheduled out, just like other regular tasks.
		 */
		if (test_task_flag(taskc, LAVD_FLAG_IS_AFFINITIZED)) {
			if (sys_stat.slice_wall > duration_wall) {
				new_slice_wall = time_delta(
							sys_stat.slice_wall,
							duration_wall);
			}
			reset_cpu_flag(cpuc_victim, LAVD_FLAG_SLICE_BOOST);
			goto kick_out;
		}
	}

	/*
	 * Prepare a cpumak so we find a victim in @p's compute domain.
	 */
	cpuc_cur = get_cpu_ctx();
	if (!cpuc_cur)
		return;

	cpumask = cpuc_cur->temp_mask;
	cpdomc = MEMBER_VPTR(cpdom_ctxs, [cpdom_id]);
	cd_cpumask = MEMBER_VPTR(cpdom_cpumask, [cpdom_id]);
	if (!cpdomc || !cd_cpumask || !cpumask)
		return;

	bpf_cpumask_and(cpumask, cast_mask(cd_cpumask), p->cpus_ptr);

	/*
	 * Find a victim CPU among CPUs that run lower-priority tasks.
	 */
	cpuc_victim = find_victim_cpu(cast_mask(cpumask), preferred_cpu, taskc, now);

	/*
	 * If a victim CPU is chosen, preempt the victim by kicking it.
	 */
	if (cpuc_victim) {
kick_out:
		ask_cpu_yield_after(cpuc_victim, new_slice_wall);

		if (cpuc_cur || (cpuc_cur = get_cpu_ctx()))
			cpuc_cur->nr_preempt++;
	}
}

__hidden
void reset_cpu_preemption_info(struct cpu_ctx *cpuc)
{
	/*
	 * When the CPU is idle, set things easy to preempt.
	 */
	cpuc->flags = 0;
	cpuc->lat_cri = 0;
	cpuc->est_stopping_clk = SCX_SLICE_INF;
}
