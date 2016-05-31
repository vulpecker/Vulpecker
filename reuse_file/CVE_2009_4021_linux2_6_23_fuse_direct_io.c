
static ssize_t CVE_2009_4021_linux2_6_23_fuse_direct_io(struct file *file, const char __user *buf,
			      size_t count, loff_t *ppos, int write)
{
	struct inode *inode = file->f_path.dentry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	size_t nmax = write ? fc->max_write : fc->max_read;
	loff_t pos = *ppos;
	ssize_t res = 0;
	struct fuse_req *req;

	if (is_bad_inode(inode))
		return -EIO;

	req = fuse_get_req(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	while (count) {
		size_t nres;
		size_t nbytes = min(count, nmax);
		int err = fuse_get_user_pages(req, buf, nbytes, !write);
		if (err) {
			res = err;
			break;
		}
		nbytes = (req->num_pages << PAGE_SHIFT) - req->page_offset;
		nbytes = min(count, nbytes);
		if (write)
			nres = fuse_send_write(req, file, inode, pos, nbytes);
		else
			nres = fuse_send_read(req, file, inode, pos, nbytes);
		fuse_release_user_pages(req, !write);
		if (req->out.h.error) {
			if (!res)
				res = req->out.h.error;
			break;
		} else if (nres > nbytes) {
			res = -EIO;
			break;
		}
		count -= nres;
		res += nres;
		pos += nres;
		buf += nres;
		if (nres != nbytes)
			break;
		if (count) {
			fuse_put_request(fc, req);
			req = fuse_get_req(fc);
			if (IS_ERR(req))
				break;
		}
	}
	fuse_put_request(fc, req);
	if (res > 0) {
		if (write) {
			spin_lock(&fc->lock);
			if (pos > inode->i_size)
				i_size_write(inode, pos);
			spin_unlock(&fc->lock);
		}
		*ppos = pos;
	}
	fuse_invalidate_attr(inode);

	return res;
}