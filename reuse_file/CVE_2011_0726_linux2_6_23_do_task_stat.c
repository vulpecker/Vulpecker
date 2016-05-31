
static int CVE_2011_0726_linux2_6_23_do_task_stat(struct task_struct *task, char *buffer, int whole)
{
	unsigned long vsize, eip, esp, wchan = ~0UL;
	long priority, nice;
	int tty_pgrp = -1, tty_nr = 0;
	sigset_t sigign, sigcatch;
	char state;
	int res;
	pid_t ppid = 0, pgid = -1, sid = -1;
	int num_threads = 0;
	struct mm_struct *mm;
	unsigned long long start_time;
	unsigned long cmin_flt = 0, cmaj_flt = 0;
	unsigned long  min_flt = 0,  maj_flt = 0;
	cputime_t cutime, cstime, utime, stime;
	unsigned long rsslim = 0;
	char tcomm[sizeof(task->comm)];
	unsigned long flags;

	state = *get_task_state(task);
	vsize = eip = esp = 0;
	mm = get_task_mm(task);
	if (mm) {
		vsize = task_vsize(mm);
		eip = KSTK_EIP(task);
		esp = KSTK_ESP(task);
	}

	get_task_comm(tcomm, task);

	sigemptyset(&sigign);
	sigemptyset(&sigcatch);
	cutime = cstime = utime = stime = cputime_zero;

	rcu_read_lock();
	if (lock_task_sighand(task, &flags)) {
		struct signal_struct *sig = task->signal;

		if (sig->tty) {
			tty_pgrp = pid_nr(sig->tty->pgrp);
			tty_nr = new_encode_dev(tty_devnum(sig->tty));
		}

		num_threads = atomic_read(&sig->count);
		collect_sigign_sigcatch(task, &sigign, &sigcatch);

		cmin_flt = sig->cmin_flt;
		cmaj_flt = sig->cmaj_flt;
		cutime = sig->cutime;
		cstime = sig->cstime;
		rsslim = sig->rlim[RLIMIT_RSS].rlim_cur;

		/* add up live thread stats at the group level */
		if (whole) {
			struct task_struct *t = task;
			do {
				min_flt += t->min_flt;
				maj_flt += t->maj_flt;
				utime = cputime_add(utime, task_utime(t));
				stime = cputime_add(stime, task_stime(t));
				t = next_thread(t);
			} while (t != task);

			min_flt += sig->min_flt;
			maj_flt += sig->maj_flt;
			utime = cputime_add(utime, sig->utime);
			stime = cputime_add(stime, sig->stime);
		}

		sid = signal_session(sig);
		pgid = process_group(task);
		ppid = rcu_dereference(task->real_parent)->tgid;

		unlock_task_sighand(task, &flags);
	}
	rcu_read_unlock();

	if (!whole || num_threads < 2)
		wchan = get_wchan(task);
	if (!whole) {
		min_flt = task->min_flt;
		maj_flt = task->maj_flt;
		utime = task_utime(task);
		stime = task_stime(task);
	}

	/* scale priority and nice values from timeslices to -20..20 */
	/* to make it look like a "normal" Unix priority/nice value  */
	priority = task_prio(task);
	nice = task_nice(task);

	/* Temporary variable needed for gcc-2.96 */
	/* convert timespec -> nsec*/
	start_time =
		(unsigned long long)task->real_start_time.tv_sec * NSEC_PER_SEC
				+ task->real_start_time.tv_nsec;
	/* convert nsec -> ticks */
	start_time = nsec_to_clock_t(start_time);

	res = sprintf(buffer, "%d (%s) %c %d %d %d %d %d %u %lu \
%lu %lu %lu %lu %lu %ld %ld %ld %ld %d 0 %llu %lu %ld %lu %lu %lu %lu %lu \
%lu %lu %lu %lu %lu %lu %lu %lu %d %d %u %u %llu\n",
		task->pid,
		tcomm,
		state,
		ppid,
		pgid,
		sid,
		tty_nr,
		tty_pgrp,
		task->flags,
		min_flt,
		cmin_flt,
		maj_flt,
		cmaj_flt,
		cputime_to_clock_t(utime),
		cputime_to_clock_t(stime),
		cputime_to_clock_t(cutime),
		cputime_to_clock_t(cstime),
		priority,
		nice,
		num_threads,
		start_time,
		vsize,
		mm ? get_mm_rss(mm) : 0,
		rsslim,
		mm ? mm->start_code : 0,
		mm ? mm->end_code : 0,
		mm ? mm->start_stack : 0,
		esp,
		eip,
		/* The signal information here is obsolete.
		 * It must be decimal for Linux 2.0 compatibility.
		 * Use /proc/#/status for real-time signals.
		 */
		task->pending.signal.sig[0] & 0x7fffffffUL,
		task->blocked.sig[0] & 0x7fffffffUL,
		sigign      .sig[0] & 0x7fffffffUL,
		sigcatch    .sig[0] & 0x7fffffffUL,
		wchan,
		0UL,
		0UL,
		task->exit_signal,
		task_cpu(task),
		task->rt_priority,
		task->policy,
		(unsigned long long)delayacct_blkio_ticks(task));
	if (mm)
		mmput(mm);
	return res;
}