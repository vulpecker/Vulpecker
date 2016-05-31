__notrace_funcgraph struct task_struct *
CVE_2014_9419_linux2_6_34_2___switch_to(struct task_struct *prev_p, struct task_struct *next_p)
{
	struct thread_struct *prev = &prev_p->thread;
	struct thread_struct *next = &next_p->thread;
	int cpu = smp_processor_id();
	struct tss_struct *tss = &per_cpu(init_tss, cpu);
	unsigned fsindex, gsindex;
	bool preload_fpu;

	/*
	 * If the task has used fpu the last 5 timeslices, just do a full
	 * restore of the math state immediately to avoid the trap; the
	 * chances of needing FPU soon are obviously high now
	 */
	preload_fpu = tsk_used_math(next_p) && next_p->fpu_counter > 5;

	/* we're going to use this soon, after a few expensive things */
	if (preload_fpu)
		prefetch(next->xstate);

	/*
	 * Reload esp0, LDT and the page table pointer:
	 */
	load_sp0(tss, next);

	/*
	 * Switch DS and ES.
	 * This won't pick up thread selector changes, but I guess that is ok.
	 */
	savesegment(es, prev->es);
	if (unlikely(next->es | prev->es))
		loadsegment(es, next->es);

	savesegment(ds, prev->ds);
	if (unlikely(next->ds | prev->ds))
		loadsegment(ds, next->ds);


	/* We must save %fs and %gs before load_TLS() because
	 * %fs and %gs may be cleared by load_TLS().
	 *
	 * (e.g. xen_load_tls())
	 */
	savesegment(fs, fsindex);
	savesegment(gs, gsindex);

	load_TLS(next, cpu);

	/* Must be after DS reload */
	unlazy_fpu(prev_p);

	/* Make sure cpu is ready for new context */
	if (preload_fpu)
		clts();

	/*
	 * Leave lazy mode, flushing any hypercalls made here.
	 * This must be done before restoring TLS segments so
	 * the GDT and LDT are properly updated, and must be
	 * done before math_state_restore, so the TS bit is up
	 * to date.
	 */
	arch_end_context_switch(next_p);

	/*
	 * Switch FS and GS.
	 *
	 * Segment register != 0 always requires a reload.  Also
	 * reload when it has changed.  When prev process used 64bit
	 * base always reload to avoid an information leak.
	 */
	if (unlikely(fsindex | next->fsindex | prev->fs)) {
		loadsegment(fs, next->fsindex);
		/*
		 * Check if the user used a selector != 0; if yes
		 *  clear 64bit base, since overloaded base is always
		 *  mapped to the Null selector
		 */
		if (fsindex)
			prev->fs = 0;
	}
	/* when next process has a 64bit base use it */
	if (next->fs)
		wrmsrl(MSR_FS_BASE, next->fs);
	prev->fsindex = fsindex;

	if (unlikely(gsindex | next->gsindex | prev->gs)) {
		load_gs_index(next->gsindex);
		if (gsindex)
			prev->gs = 0;
	}
	if (next->gs)
		wrmsrl(MSR_KERNEL_GS_BASE, next->gs);
	prev->gsindex = gsindex;

	/*
	 * Switch the PDA and FPU contexts.
	 */
	prev->usersp = percpu_read(old_rsp);
	percpu_write(old_rsp, next->usersp);
	percpu_write(current_task, next_p);

	percpu_write(kernel_stack,
		  (unsigned long)task_stack_page(next_p) +
		  THREAD_SIZE - KERNEL_STACK_OFFSET);

	/*
	 * Now maybe reload the debug registers and handle I/O bitmaps
	 */
	if (unlikely(task_thread_info(next_p)->flags & _TIF_WORK_CTXSW_NEXT ||
		     task_thread_info(prev_p)->flags & _TIF_WORK_CTXSW_PREV))
		CVE_2014_9419_linux2_6_34_2___switch_to_xtra(prev_p, next_p, tss);

	/*
	 * Preload the FPU context, now that we've determined that the
	 * task is likely to be using it. 
	 */
	if (preload_fpu)
		__math_state_restore();

	return prev_p;
}