
int
CVE_2010_1148_linux2_6_29_cifs_create(struct inode *inode, struct dentry *direntry, int mode,
		struct nameidata *nd)
{
	int rc = -ENOENT;
	int xid;
	int create_options = CREATE_NOT_DIR;
	int oplock = 0;
	int oflags;
	/*
	 * BB below access is probably too much for mknod to request
	 *    but we have to do query and setpathinfo so requesting
	 *    less could fail (unless we want to request getatr and setatr
	 *    permissions (only).  At least for POSIX we do not have to
	 *    request so much.
	 */
	int desiredAccess = GENERIC_READ | GENERIC_WRITE;
	__u16 fileHandle;
	struct cifs_sb_info *cifs_sb;
	struct cifsTconInfo *tcon;
	char *full_path = NULL;
	FILE_ALL_INFO *buf = NULL;
	struct inode *newinode = NULL;
	struct cifsInodeInfo *pCifsInode;
	int disposition = FILE_OVERWRITE_IF;
	bool write_only = false;

	xid = GetXid();

	cifs_sb = CIFS_SB(inode->i_sb);
	tcon = cifs_sb->tcon;

	full_path = build_path_from_dentry(direntry);
	if (full_path == NULL) {
		FreeXid(xid);
		return -ENOMEM;
	}

	mode &= ~current->fs->umask;
	if (oplockEnabled)
		oplock = REQ_OPLOCK;

	if (nd && (nd->flags & LOOKUP_OPEN))
		oflags = nd->intent.open.flags;
	else
		oflags = FMODE_READ;

	if (tcon->unix_ext && (tcon->ses->capabilities & CAP_UNIX) &&
	    (CIFS_UNIX_POSIX_PATH_OPS_CAP &
			le64_to_cpu(tcon->fsUnixInfo.Capability))) {
		rc = cifs_posix_open(full_path, &newinode, inode->i_sb,
				     mode, oflags, &oplock, &fileHandle, xid);
		/* EIO could indicate that (posix open) operation is not
		   supported, despite what server claimed in capability
		   negotation.  EREMOTE indicates DFS junction, which is not
		   handled in posix open */

		if ((rc == 0) && (newinode == NULL))
			goto CVE_2010_1148_linux2_6_29_cifs_create_get_file_info; /* query inode info */
		else if (rc == 0) /* success, no need to query */
			goto CVE_2010_1148_linux2_6_29_cifs_create_set_dentry;
		else if ((rc != -EIO) && (rc != -EREMOTE) &&
			 (rc != -EOPNOTSUPP)) /* path not found or net err */
			goto CVE_2010_1148_linux2_6_29_cifs_create_out;
		/* else fallthrough to retry, using older open call, this is
		   case where server does not support this SMB level, and
		   falsely claims capability (also get here for DFS case
		   which should be rare for path not covered on files) */
	}

	if (nd && (nd->flags & LOOKUP_OPEN)) {
		/* if the file is going to stay open, then we
		   need to set the desired access properly */
		desiredAccess = 0;
		if (oflags & FMODE_READ)
			desiredAccess |= GENERIC_READ; /* is this too little? */
		if (oflags & FMODE_WRITE) {
			desiredAccess |= GENERIC_WRITE;
			if (!(oflags & FMODE_READ))
				write_only = true;
		}

		if ((oflags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL))
			disposition = FILE_CREATE;
		else if ((oflags & (O_CREAT | O_TRUNC)) == (O_CREAT | O_TRUNC))
			disposition = FILE_OVERWRITE_IF;
		else if ((oflags & O_CREAT) == O_CREAT)
			disposition = FILE_OPEN_IF;
		else
			cFYI(1, ("Create flag not set in create function"));
	}

	/* BB add processing to set equivalent of mode - e.g. via CreateX with
	   ACLs */

	buf = kmalloc(sizeof(FILE_ALL_INFO), GFP_KERNEL);
	if (buf == NULL) {
		kfree(full_path);
		FreeXid(xid);
		return -ENOMEM;
	}

	/*
	 * if we're not using unix extensions, see if we need to set
	 * ATTR_READONLY on the create call
	 */
	if (!tcon->unix_ext && (mode & S_IWUGO) == 0)
		create_options |= CREATE_OPTION_READONLY;

	if (cifs_sb->tcon->ses->capabilities & CAP_NT_SMBS)
		rc = CIFSSMBOpen(xid, tcon, full_path, disposition,
			 desiredAccess, create_options,
			 &fileHandle, &oplock, buf, cifs_sb->local_nls,
			 cifs_sb->mnt_cifs_flags & CIFS_MOUNT_MAP_SPECIAL_CHR);
	else
		rc = -EIO; /* no NT SMB support fall into legacy open below */

	if (rc == -EIO) {
		/* old server, retry the open legacy style */
		rc = SMBLegacyOpen(xid, tcon, full_path, disposition,
			desiredAccess, create_options,
			&fileHandle, &oplock, buf, cifs_sb->local_nls,
			cifs_sb->mnt_cifs_flags & CIFS_MOUNT_MAP_SPECIAL_CHR);
	}
	if (rc) {
		cFYI(1, ("CVE_2010_1148_linux2_6_29_cifs_create returned 0x%x", rc));
		goto CVE_2010_1148_linux2_6_29_cifs_create_out;
	}

	/* If Open reported that we actually created a file
	   then we now have to set the mode if possible */
	if ((tcon->unix_ext) && (oplock & CIFS_CREATE_ACTION)) {
		struct cifs_unix_set_info_args args = {
				.mode	= mode,
				.ctime	= NO_CHANGE_64,
				.atime	= NO_CHANGE_64,
				.mtime	= NO_CHANGE_64,
				.device	= 0,
		};

		if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_SET_UID) {
			args.uid = (__u64) current_fsuid();
			if (inode->i_mode & S_ISGID)
				args.gid = (__u64) inode->i_gid;
			else
				args.gid = (__u64) current_fsgid();
		} else {
			args.uid = NO_CHANGE_64;
			args.gid = NO_CHANGE_64;
		}
		CIFSSMBUnixSetInfo(xid, tcon, full_path, &args,
			cifs_sb->local_nls,
			cifs_sb->mnt_cifs_flags & CIFS_MOUNT_MAP_SPECIAL_CHR);
	} else {
		/* BB implement mode setting via Windows security
		   descriptors e.g. */
		/* CIFSSMBWinSetPerms(xid,tcon,path,mode,-1,-1,nls);*/

		/* Could set r/o dos attribute if mode & 0222 == 0 */
	}

CVE_2010_1148_linux2_6_29_cifs_create_get_file_info:
	/* server might mask mode so we have to query for it */
	if (tcon->unix_ext)
		rc = cifs_get_inode_info_unix(&newinode, full_path,
					      inode->i_sb, xid);
	else {
		rc = cifs_get_inode_info(&newinode, full_path, buf,
					 inode->i_sb, xid, &fileHandle);
		if (newinode) {
			if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_DYNPERM)
				newinode->i_mode = mode;
			if ((oplock & CIFS_CREATE_ACTION) &&
			    (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_SET_UID)) {
				newinode->i_uid = current_fsuid();
				if (inode->i_mode & S_ISGID)
					newinode->i_gid = inode->i_gid;
				else
					newinode->i_gid = current_fsgid();
			}
		}
	}

CVE_2010_1148_linux2_6_29_cifs_create_set_dentry:
	if (rc == 0)
		setup_cifs_dentry(tcon, direntry, newinode);
	else
		cFYI(1, ("Create worked, get_inode_info failed rc = %d", rc));

	/* nfsd case - nfs srv does not set nd */
	if ((nd == NULL) || (!(nd->flags & LOOKUP_OPEN))) {
		/* mknod case - do not leave file open */
		CIFSSMBClose(xid, tcon, fileHandle);
	} else if (newinode) {
		struct cifsFileInfo *pCifsFile =
			kzalloc(sizeof(struct cifsFileInfo), GFP_KERNEL);

		if (pCifsFile == NULL)
			goto CVE_2010_1148_linux2_6_29_cifs_create_out;
		pCifsFile->netfid = fileHandle;
		pCifsFile->pid = current->tgid;
		pCifsFile->pInode = newinode;
		pCifsFile->invalidHandle = false;
		pCifsFile->closePend     = false;
		init_MUTEX(&pCifsFile->fh_sem);
		mutex_init(&pCifsFile->lock_mutex);
		INIT_LIST_HEAD(&pCifsFile->llist);
		atomic_set(&pCifsFile->wrtPending, 0);

		/* set the following in open now
				pCifsFile->pfile = file; */
		write_lock(&GlobalSMBSeslock);
		list_add(&pCifsFile->tlist, &tcon->openFileList);
		pCifsInode = CIFS_I(newinode);
		if (pCifsInode) {
			/* if readable file instance put first in list*/
			if (write_only) {
				list_add_tail(&pCifsFile->flist,
					      &pCifsInode->openFileList);
			} else {
				list_add(&pCifsFile->flist,
					 &pCifsInode->openFileList);
			}
			if ((oplock & 0xF) == OPLOCK_EXCLUSIVE) {
				pCifsInode->clientCanCacheAll = true;
				pCifsInode->clientCanCacheRead = true;
				cFYI(1, ("Exclusive Oplock inode %p",
					newinode));
			} else if ((oplock & 0xF) == OPLOCK_READ)
				pCifsInode->clientCanCacheRead = true;
		}
		write_unlock(&GlobalSMBSeslock);
	}
CVE_2010_1148_linux2_6_29_cifs_create_out:
	kfree(buf);
	kfree(full_path);
	FreeXid(xid);
	return rc;
}