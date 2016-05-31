int
CVE_2010_2226_linux2_6_27_31_xfs_swapext(
	CVE_2010_2226_linux2_6_27_31_xfs_swapext_t	__user *sxu)
{
	CVE_2010_2226_linux2_6_27_31_xfs_swapext_t	*sxp;
	xfs_inode_t     *ip, *tip;
	struct file	*file, *target_file;
	int		error = 0;

	sxp = kmem_alloc(sizeof(CVE_2010_2226_linux2_6_27_31_xfs_swapext_t), KM_MAYFAIL);
	if (!sxp) {
		error = XFS_ERROR(ENOMEM);
		goto out;
	}

	if (copy_from_user(sxp, sxu, sizeof(CVE_2010_2226_linux2_6_27_31_xfs_swapext_t))) {
		error = XFS_ERROR(EFAULT);
		goto out_free_sxp;
	}

	/* Pull information for the target fd */
	file = fget((int)sxp->sx_fdtarget);
	if (!file) {
		error = XFS_ERROR(EINVAL);
		goto out_free_sxp;
	}

	if (!(file->f_mode & FMODE_WRITE) || (file->f_flags & O_APPEND)) {
		error = XFS_ERROR(EBADF);
		goto out_put_file;
	}

	target_file = fget((int)sxp->sx_fdtmp);
	if (!target_file) {
		error = XFS_ERROR(EINVAL);
		goto out_put_file;
	}

	if (!(target_file->f_mode & FMODE_WRITE) ||
	    (target_file->f_flags & O_APPEND)) {
		error = XFS_ERROR(EBADF);
		goto out_put_target_file;
	}

	ip = XFS_I(file->f_path.dentry->d_inode);
	tip = XFS_I(target_file->f_path.dentry->d_inode);

	if (ip->i_mount != tip->i_mount) {
		error = XFS_ERROR(EINVAL);
		goto out_put_target_file;
	}

	if (ip->i_ino == tip->i_ino) {
		error = XFS_ERROR(EINVAL);
		goto out_put_target_file;
	}

	if (XFS_FORCED_SHUTDOWN(ip->i_mount)) {
		error = XFS_ERROR(EIO);
		goto out_put_target_file;
	}

	error = xfs_swap_extents(ip, tip, sxp);

 out_put_target_file:
	fput(target_file);
 out_put_file:
	fput(file);
 out_free_sxp:
	kmem_free(sxp);
 out:
	return error;
}