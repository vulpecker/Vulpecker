
int CVE_2007_6206_linux2_6_10_do_coredump(long signr, int exit_code, struct pt_regs * regs)
{
	char corename[CORENAME_MAX_SIZE + 1];
	struct mm_struct *mm = current->mm;
	struct linux_binfmt * binfmt;
	struct inode * inode;
	struct file * file;
	int retval = 0;

	binfmt = current->binfmt;
	if (!binfmt || !binfmt->core_dump)
		goto fail;
	down_write(&mm->mmap_sem);
	if (!mm->dumpable) {
		up_write(&mm->mmap_sem);
		goto fail;
	}
	mm->dumpable = 0;
	init_completion(&mm->core_done);
	current->signal->group_exit = 1;
	current->signal->group_exit_code = exit_code;
	coredump_wait(mm);

	if (current->signal->rlim[RLIMIT_CORE].rlim_cur < binfmt->min_coredump)
		goto fail_unlock;

	/*
	 * lock_kernel() because format_corename() is controlled by sysctl, which
	 * uses lock_kernel()
	 */
 	lock_kernel();
	format_corename(corename, core_pattern, signr);
	unlock_kernel();
	file = filp_open(corename, O_CREAT | 2 | O_NOFOLLOW | O_LARGEFILE, 0600);
	if (IS_ERR(file))
		goto fail_unlock;
	inode = file->f_dentry->d_inode;
	if (inode->i_nlink > 1)
		goto close_fail;	/* multiple links - don't dump */
	if (d_unhashed(file->f_dentry))
		goto close_fail;

	if (!S_ISREG(inode->i_mode))
		goto close_fail;
	if (!file->f_op)
		goto close_fail;
	if (!file->f_op->write)
		goto close_fail;
	if (do_truncate(file->f_dentry, 0) != 0)
		goto close_fail;

	retval = binfmt->core_dump(signr, regs, file);

	if (retval)
		current->signal->group_exit_code |= 0x80;
close_fail:
	filp_close(file, NULL);
fail_unlock:
	complete_all(&mm->core_done);
fail:
	return retval;
}