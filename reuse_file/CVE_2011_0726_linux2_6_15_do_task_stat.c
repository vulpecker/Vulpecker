
static int CVE_2011_0726_linux2_6_15_do_task_stat(struct task_struct *task, char * buffer, int whole)
{
	unsigned long vsize, eip, esp, wchan = ~0UL;
	long priority, nice;
	int tty_pgrp = -1, tty_nr = 0;
	sigset_t sigign, sigcatch;
	char state;
	int res;
 	pid_t ppid, pgid = -1, sid = -1;
	int num_threads = 0;
	struct mm_struct *mm;
	unsigned long long start_time;
	unsigned long cmin_flt = 0, cmaj_flt = 0;
	unsigned long  min_flt = 0,  maj_flt = 0;
	cputime_t cutime, cstime, utime, stime;
	unsigned long rsslim = 0;
	unsigned long it_real_value = 0;
	struct task_struct *t;
	char tcomm[sizeof(task->comm)];

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
	read_lock(&tasklist_lock);
	if (task->sighand) {
		spin_lock_irq(&task->sighand->siglock);
		num_threads = atomic_read(&task->signal->count);
		collect_sigign_sigcatch(task, &sigign, &sigcatch);

		/* add up live thread stats at the group level */
		if (whole) {
			t = task;
			do {
				min_flt += t->min_flt;
				maj_flt += t->maj_flt;
				utime = cputime_add(utime, t->utime);
				stime = cputime_add(stime, t->stime);
				t = next_thread(t);
			} while (t != task);
		}

		spin_unlock_irq(&task->sighand->siglock);
	}
	if (task->signal) {
		if (task->signal->tty) {
			tty_pgrp = task->signal->tty->pgrp;
			tty_nr = new_encode_dev(tty_devnum(task->signal->tty));
		}
		pgid = process_group(task);
		sid = task->signal->session;
		cmin_flt = task->signal->cmin_flt;
		cmaj_flt = task->signal->cmaj_flt;
		cutime = task->signal->cutime;
		cstime = task->signal->cstime;
		rsslim = task->signal->rlim[RLIMIT_RSS].rlim_cur;
		if (whole) {
			min_flt += task->signal->min_flt;
			maj_flt += task->signal->maj_flt;
			utime = cputime_add(utime, task->signal->utime);
			stime = cputime_add(stime, task->signal->stime);
		}
		it_real_value = task->signal->it_real_value;
	}
	ppid = pid_alive(task) ? task->group_leader->real_parent->tgid : 0;
	read_unlock(&tasklist_lock);

	if (!whole || num_threads<2)
		wchan = get_wchan(task);
	if (!whole) {
		min_flt = task->min_flt;
		maj_flt = task->maj_flt;
		utime = task->utime;
		stime = task->stime;
	}

	/* scale priority and nice values from timeslices to -20..20 */
	/* to make it look like a "normal" Unix priority/nice value  */
	priority = task_prio(task);
	nice = task_nice(task);

	/* Temporary variable needed for gcc-2.96 */
	/* convert timespec -> nsec*/
	start_time = (unsigned long long)task->start_time.tv_sec * NSEC_PER_SEC
				+ task->start_time.tv_nsec;
	/* convert nsec -> ticks */
	start_time = nsec_to_clock_t(start_time);

	res = sprintf(buffer,"%d (%s) %c %d %d %d %d %d %lu %lu \
%lu %lu %lu %lu %lu %ld %ld %ld %ld %d %ld %llu %lu %ld %lu %lu %lu %lu %lu \
%lu %lu %lu %lu %lu %lu %lu %lu %d %d %lu %lu\n",
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
		jiffies_to_clock_t(it_real_value),
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
		task->policy);
	if(mm)
		mmput(mm);
	return res;
}