int CVE_2012_2745_linux2_6_30_2_copy_creds(struct task_struct *p, unsigned long clone_flags)
{
#ifdef CONFIG_KEYS
	struct thread_group_cred *tgcred;
#endif
	struct cred *new;
	int ret;

	mutex_init(&p->cred_exec_mutex);

	if (
#ifdef CONFIG_KEYS
		!p->cred->thread_keyring &&
#endif
		clone_flags & CLONE_THREAD
	    ) {
		p->real_cred = get_cred(p->cred);
		get_cred(p->cred);
		atomic_inc(&p->cred->user->processes);
		return 0;
	}

	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	if (clone_flags & CLONE_NEWUSER) {
		ret = create_user_ns(new);
		if (ret < 0)
			goto error_put;
	}

#ifdef CONFIG_KEYS
	/* new threads get their own thread keyrings if their parent already
	 * had one */
	if (new->thread_keyring) {
		key_put(new->thread_keyring);
		new->thread_keyring = NULL;
		if (clone_flags & CLONE_THREAD)
			install_thread_keyring_to_cred(new);
	}

	/* we share the process and session keyrings between all the threads in
	 * a process - this is slightly icky as we violate COW credentials a
	 * bit */
	if (!(clone_flags & CLONE_THREAD)) {
		tgcred = kmalloc(sizeof(*tgcred), GFP_KERNEL);
		if (!tgcred) {
			ret = -ENOMEM;
			goto error_put;
		}
		atomic_set(&tgcred->usage, 1);
		spin_lock_init(&tgcred->lock);
		tgcred->process_keyring = NULL;
		tgcred->session_keyring = key_get(new->tgcred->session_keyring);

		release_tgcred(new);
		new->tgcred = tgcred;
	}
#endif

	atomic_inc(&new->user->processes);
	p->cred = p->real_cred = get_cred(new);
	return 0;

error_put:
	put_cred(new);
	return ret;
}