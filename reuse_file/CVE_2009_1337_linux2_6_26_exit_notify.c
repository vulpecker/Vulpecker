static void CVE_2009_1337_linux2_6_26_exit_notify(struct task_struct *tsk, int group_dead)
{
	int state;

	/*
	 * This does two things:
	 *
  	 * A.  Make init inherit all the child processes
	 * B.  Check to see if any process groups have become orphaned
	 *	as a result of our exiting, and if they have any stopped
	 *	jobs, send them a SIGHUP and then a SIGCONT.  (POSIX 3.2.2.2)
	 */
	forget_original_parent(tsk);
	exit_task_namespaces(tsk);

	write_lock_irq(&tasklist_lock);
	if (group_dead)
		kill_orphaned_pgrp(tsk->group_leader, NULL);

	/* Let father know we died
	 *
	 * Thread signals are configurable, but you aren't going to use
	 * that to send signals to arbitary processes.
	 * That stops right now.
	 *
	 * If the parent exec id doesn't match the exec id we saved
	 * when we started then we know the parent has changed security
	 * domain.
	 *
	 * If our self_exec id doesn't match our parent_exec_id then
	 * we have changed execution domain as these two values started
	 * the same after a fork.
	 */
	if (tsk->exit_signal != SIGCHLD && !task_detached(tsk) &&
	    (tsk->parent_exec_id != tsk->real_parent->self_exec_id ||
	     tsk->self_exec_id != tsk->parent_exec_id) &&
	    !capable(CAP_KILL))
		tsk->exit_signal = SIGCHLD;

	/* If something other than our normal parent is ptracing us, then
	 * send it a SIGCHLD instead of honoring exit_signal.  exit_signal
	 * only has special meaning to our real parent.
	 */
	if (!task_detached(tsk) && thread_group_empty(tsk)) {
		int signal = ptrace_reparented(tsk) ?
				SIGCHLD : tsk->exit_signal;
		do_notify_parent(tsk, signal);
	} else if (tsk->ptrace) {
		do_notify_parent(tsk, SIGCHLD);
	}

	state = EXIT_ZOMBIE;
	if (task_detached(tsk) && likely(!tsk->ptrace))
		state = EXIT_DEAD;
	tsk->exit_state = state;

	/* mt-exec, de_thread() is waiting for us */
	if (thread_group_leader(tsk) &&
	    tsk->signal->notify_count < 0 &&
	    tsk->signal->group_exit_task)
		wake_up_process(tsk->signal->group_exit_task);

	write_unlock_irq(&tasklist_lock);

	/* If the process is dead, release it - nobody will wait for it */
	if (state == EXIT_DEAD)
		release_task(tsk);
}