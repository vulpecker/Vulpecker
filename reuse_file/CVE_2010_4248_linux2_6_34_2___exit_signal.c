static void CVE_2010_4248_linux2_6_34_2___exit_signal(struct task_struct *tsk)
{
	struct signal_struct *sig = tsk->signal;
	struct sighand_struct *sighand;

	BUG_ON(!sig);
	BUG_ON(!atomic_read(&sig->count));

	sighand = rcu_dereference_check(tsk->sighand,
					rcu_read_lock_held() ||
					lockdep_tasklist_lock_is_held());
	spin_lock(&sighand->siglock);

	posix_cpu_timers_exit(tsk);
	if (atomic_dec_and_test(&sig->count))
		posix_cpu_timers_exit_group(tsk);
	else {
		/*
		 * If there is any task waiting for the group exit
		 * then notify it:
		 */
		if (sig->group_exit_task && atomic_read(&sig->count) == sig->notify_count)
			wake_up_process(sig->group_exit_task);

		if (tsk == sig->curr_target)
			sig->curr_target = next_thread(tsk);
		/*
		 * Accumulate here the counters for all threads but the
		 * group leader as they die, so they can be added into
		 * the process-wide totals when those are taken.
		 * The group leader stays around as a zombie as long
		 * as there are other threads.  When it gets reaped,
		 * the exit.c code will add its counts into these totals.
		 * We won't ever get here for the group leader, since it
		 * will have been the last reference on the signal_struct.
		 */
		sig->utime = cputime_add(sig->utime, tsk->utime);
		sig->stime = cputime_add(sig->stime, tsk->stime);
		sig->gtime = cputime_add(sig->gtime, tsk->gtime);
		sig->min_flt += tsk->min_flt;
		sig->maj_flt += tsk->maj_flt;
		sig->nvcsw += tsk->nvcsw;
		sig->nivcsw += tsk->nivcsw;
		sig->inblock += task_io_get_inblock(tsk);
		sig->oublock += task_io_get_oublock(tsk);
		task_io_accounting_add(&sig->ioac, &tsk->ioac);
		sig->sum_sched_runtime += tsk->se.sum_exec_runtime;
		sig = NULL; /* Marker for below. */
	}

	__unhash_process(tsk);

	/*
	 * Do this under ->siglock, we can race with another thread
	 * doing sigqueue_free() if we have SIGQUEUE_PREALLOC signals.
	 */
	flush_sigqueue(&tsk->pending);

	tsk->signal = NULL;
	tsk->sighand = NULL;
	spin_unlock(&sighand->siglock);

	__cleanup_sighand(sighand);
	clear_tsk_thread_flag(tsk,TIF_SIGPENDING);
	if (sig) {
		flush_sigqueue(&sig->shared_pending);
		taskstats_tgid_free(sig);
		/*
		 * Make sure ->signal can't go away under rq->lock,
		 * see account_group_exec_runtime().
		 */
		task_rq_unlock_wait(tsk);
		__cleanup_signal(sig);
	}
}