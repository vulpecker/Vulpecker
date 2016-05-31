
int CVE_2010_4243_linux2_6_23_flush_old_exec(struct linux_binprm * bprm)
{
	char * name;
	int i, ch, retval;
	struct files_struct *files;
	char tcomm[sizeof(current->comm)];

	/*
	 * Make sure we have a private signal table and that
	 * we are unassociated from the previous thread group.
	 */
	retval = de_thread(current);
	if (retval)
		goto out;

	/*
	 * Make sure we have private file handles. Ask the
	 * fork helper to do the work for us and the exit
	 * helper to do the cleanup of the old one.
	 */
	files = current->files;		/* refcounted so safe to hold */
	retval = unshare_files();
	if (retval)
		goto out;
	/*
	 * Release all of the old mmap stuff
	 */
	retval = exec_mmap(bprm->mm);
	if (retval)
		goto mmap_failed;

	bprm->mm = NULL;		/* We're using it now */

	/* This is the point of no return */
	put_files_struct(files);

	current->sas_ss_sp = current->sas_ss_size = 0;

	if (current->euid == current->uid && current->egid == current->gid)
		set_dumpable(current->mm, 1);
	else
		set_dumpable(current->mm, suid_dumpable);

	name = bprm->filename;

	/* Copies the binary name from after last slash */
	for (i=0; (ch = *(name++)) != '\0';) {
		if (ch == '/')
			i = 0; /* overwrite what we wrote */
		else
			if (i < (sizeof(tcomm) - 1))
				tcomm[i++] = ch;
	}
	tcomm[i] = '\0';
	set_task_comm(current, tcomm);

	current->flags &= ~PF_RANDOMIZE;
	flush_thread();

	/* Set the new mm task size. We have to do that late because it may
	 * depend on TIF_32BIT which is only updated in flush_thread() on
	 * some architectures like powerpc
	 */
	current->mm->task_size = TASK_SIZE;

	if (bprm->e_uid != current->euid || bprm->e_gid != current->egid) {
		suid_keys(current);
		set_dumpable(current->mm, suid_dumpable);
		current->pdeath_signal = 0;
	} else if (file_permission(bprm->file, MAY_READ) ||
			(bprm->interp_flags & BINPRM_FLAGS_ENFORCE_NONDUMP)) {
		suid_keys(current);
		set_dumpable(current->mm, suid_dumpable);
	}

	/* An exec changes our domain. We are no longer part of the thread
	   group */

	current->self_exec_id++;
			
	flush_signal_handlers(current, 0);
	flush_old_files(current->files);

	return 0;

mmap_failed:
	reset_files_struct(current, files);
out:
	return retval;
}