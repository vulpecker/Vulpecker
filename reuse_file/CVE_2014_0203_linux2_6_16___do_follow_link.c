
static __always_inline int CVE_2014_0203_linux2_6_16___do_follow_link(struct path *path, struct nameidata *nd)
{
	int error;
	void *cookie;
	struct dentry *dentry = path->dentry;

	touch_atime(path->mnt, dentry);
	nd_set_link(nd, NULL);

	if (path->mnt == nd->mnt)
		mntget(path->mnt);
	cookie = dentry->d_inode->i_op->follow_link(dentry, nd);
	error = PTR_ERR(cookie);
	if (!IS_ERR(cookie)) {
		char *s = nd_get_link(nd);
		error = 0;
		if (s)
			error = __vfs_follow_link(nd, s);
		if (dentry->d_inode->i_op->put_link)
			dentry->d_inode->i_op->put_link(dentry, nd, cookie);
	}
	dput(dentry);
	mntput(path->mnt);

	return error;
}