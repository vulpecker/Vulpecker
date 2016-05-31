
static int CVE_2014_7975_linux2_4_25_do_umount(struct vfsmount *mnt, int flags)
{
	struct super_block * sb = mnt->mnt_sb;
	int retval = 0;

	/*
	 * If we may have to abort operations to get out of this
	 * mount, and they will themselves hold resources we must
	 * allow the fs to do things. In the Unix tradition of
	 * 'Gee thats tricky lets do it in userspace' the umount_begin
	 * might fail to complete on the first run through as other tasks
	 * must return, and the like. Thats for the mount program to worry
	 * about for the moment.
	 */

	lock_kernel();
	if( (flags&MNT_FORCE) && sb->s_op->umount_begin)
		sb->s_op->umount_begin(sb);
	unlock_kernel();

	/*
	 * No sense to grab the lock for this test, but test itself looks
	 * somewhat bogus. Suggestions for better replacement?
	 * Ho-hum... In principle, we might treat that as umount + switch
	 * to rootfs. GC would eventually take care of the old vfsmount.
	 * Actually it makes sense, especially if rootfs would contain a
	 * /reboot - static binary that would close all descriptors and
	 * call reboot(9). Then init(8) could umount root and exec /reboot.
	 */
	if (mnt == current->fs->rootmnt && !(flags & MNT_DETACH)) {
		/*
		 * Special case for "unmounting" root ...
		 * we just try to remount it readonly.
		 */
		down_write(&sb->s_umount);
		if (!(sb->s_flags & MS_RDONLY)) {
			lock_kernel();
			retval = do_remount_sb(sb, MS_RDONLY, 0);
			unlock_kernel();
		}
		up_write(&sb->s_umount);
		return retval;
	}

	down_write(&current->namespace->sem);
	spin_lock(&dcache_lock);

	if (atomic_read(&sb->s_active) == 1) {
		/* last instance - try to be smart */
		spin_unlock(&dcache_lock);
		lock_kernel();
		DQUOT_OFF(sb);
		acct_auto_close(sb->s_dev);
		unlock_kernel();
		spin_lock(&dcache_lock);
	}
	retval = -EBUSY;
	if (atomic_read(&mnt->mnt_count) == 2 || flags & MNT_DETACH) {
		if (!list_empty(&mnt->mnt_list))
			umount_tree(mnt);
		retval = 0;
	}
	spin_unlock(&dcache_lock);
	up_write(&current->namespace->sem);
	return retval;
}