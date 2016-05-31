static struct dentry * CVE_2008_3275_linux2_4_25_real_lookup(struct dentry * parent, struct qstr * name, int flags)
{
	struct dentry * result;
	struct inode *dir = parent->d_inode;

	down(&dir->i_sem);
	/*
	 * First re-do the cached lookup just in case it was created
	 * while we waited for the directory semaphore..
	 *
	 * FIXME! This could use version numbering or similar to
	 * avoid unnecessary cache lookups.
	 */
	result = d_lookup(parent, name);
	if (!result) {
		struct dentry * dentry = d_alloc(parent, name);
		result = ERR_PTR(-ENOMEM);
		if (dentry) {
			lock_kernel();
			result = dir->i_op->lookup(dir, dentry);
			unlock_kernel();
			if (result)
				dput(dentry);
			else
				result = dentry;
		}
		up(&dir->i_sem);
		return result;
	}

	/*
	 * Uhhuh! Nasty case: the cache was re-populated while
	 * we waited on the semaphore. Need to revalidate.
	 */
	up(&dir->i_sem);
	if (result->d_op && result->d_op->d_revalidate) {
		if (!result->d_op->d_revalidate(result, flags) && !d_invalidate(result)) {
			dput(result);
			result = ERR_PTR(-ENOENT);
		}
	}
	return result;
}