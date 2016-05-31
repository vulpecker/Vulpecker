asmlinkage long
CVE_2006_3741_linux2_6_10_sys_perfmonctl (int fd, int cmd, void __user *arg, int count, long arg5, long arg6, long arg7,
		long arg8, long stack)
{
	struct pt_regs *regs = (struct pt_regs *)&stack;
	struct file *file = NULL;
	pfm_context_t *ctx = NULL;
	unsigned long flags = 0UL;
	void *args_k = NULL;
	long ret; /* will expand int return types */
	size_t base_sz, sz, xtra_sz = 0;
	int narg, completed_args = 0, call_made = 0, cmd_flags;
	int (*func)(pfm_context_t *ctx, void *arg, int count, struct pt_regs *regs);
	int (*getsize)(void *arg, size_t *sz);
#define PFM_MAX_ARGSIZE	4096

	/*
	 * reject any call if perfmon was disabled at initialization
	 */
	if (unlikely(pmu_conf == NULL)) return -ENOSYS;

	if (unlikely(cmd < 0 || cmd >= PFM_CMD_COUNT)) {
		DPRINT(("invalid cmd=%d\n", cmd));
		return -EINVAL;
	}

	func      = pfm_cmd_tab[cmd].cmd_func;
	narg      = pfm_cmd_tab[cmd].cmd_narg;
	base_sz   = pfm_cmd_tab[cmd].cmd_argsize;
	getsize   = pfm_cmd_tab[cmd].cmd_getsize;
	cmd_flags = pfm_cmd_tab[cmd].cmd_flags;

	if (unlikely(func == NULL)) {
		DPRINT(("invalid cmd=%d\n", cmd));
		return -EINVAL;
	}

	DPRINT(("cmd=%s idx=%d narg=0x%x argsz=%lu count=%d\n",
		PFM_CMD_NAME(cmd),
		cmd,
		narg,
		base_sz,
		count));

	/*
	 * check if number of arguments matches what the command expects
	 */
	if (unlikely((narg == PFM_CMD_ARG_MANY && count <= 0) || (narg > 0 && narg != count)))
		return -EINVAL;

restart_args:
	sz = xtra_sz + base_sz*count;
	/*
	 * limit abuse to min page size
	 */
	if (unlikely(sz > PFM_MAX_ARGSIZE)) {
		printk(KERN_ERR "perfmon: [%d] argument too big %lu\n", current->pid, sz);
		return -E2BIG;
	}

	/*
	 * allocate default-sized argument buffer
	 */
	if (likely(count && args_k == NULL)) {
		args_k = kmalloc(PFM_MAX_ARGSIZE, GFP_KERNEL);
		if (args_k == NULL) return -ENOMEM;
	}

	ret = -EFAULT;

	/*
	 * copy arguments
	 *
	 * assume sz = 0 for command without parameters
	 */
	if (sz && copy_from_user(args_k, arg, sz)) {
		DPRINT(("cannot copy_from_user %lu bytes @%p\n", sz, arg));
		goto error_args;
	}

	/*
	 * check if command supports extra parameters
	 */
	if (completed_args == 0 && getsize) {
		/*
		 * get extra parameters size (based on main argument)
		 */
		ret = (*getsize)(args_k, &xtra_sz);
		if (ret) goto error_args;

		completed_args = 1;

		DPRINT(("restart_args sz=%lu xtra_sz=%lu\n", sz, xtra_sz));

		/* retry if necessary */
		if (likely(xtra_sz)) goto restart_args;
	}

	if (unlikely((cmd_flags & PFM_CMD_FD) == 0)) goto skip_fd;

	ret = -EBADF;

	file = fget(fd);
	if (unlikely(file == NULL)) {
		DPRINT(("invalid fd %d\n", fd));
		goto error_args;
	}
	if (unlikely(PFM_IS_FILE(file) == 0)) {
		DPRINT(("fd %d not related to perfmon\n", fd));
		goto error_args;
	}

	ctx = (pfm_context_t *)file->private_data;
	if (unlikely(ctx == NULL)) {
		DPRINT(("no context for fd %d\n", fd));
		goto error_args;
	}
	prefetch(&ctx->ctx_state);

	PROTECT_CTX(ctx, flags);

	/*
	 * check task is stopped
	 */
	ret = pfm_check_task_state(ctx, cmd, flags);
	if (unlikely(ret)) goto abort_locked;

skip_fd:
	ret = (*func)(ctx, args_k, count, regs);

	call_made = 1;

abort_locked:
	if (likely(ctx)) {
		DPRINT(("context unlocked\n"));
		UNPROTECT_CTX(ctx, flags);
		fput(file);
	}

	/* copy argument back to user, if needed */
	if (call_made && PFM_CMD_RW_ARG(cmd) && copy_to_user(arg, args_k, base_sz*count)) ret = -EFAULT;

error_args:
	if (args_k) kfree(args_k);

	DPRINT(("cmd=%s ret=%ld\n", PFM_CMD_NAME(cmd), ret));

	return ret;
}