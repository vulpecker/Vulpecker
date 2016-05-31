
int
CVE_2011_3363_linux2_6_34_2_cifs_mount(struct super_block *sb, struct cifs_sb_info *cifs_sb,
		char *mount_data_global, const char *devname)
{
	int rc;
	int xid;
	struct smb_vol *volume_info;
	struct cifsSesInfo *pSesInfo;
	struct cifsTconInfo *tcon;
	struct TCP_Server_Info *srvTcp;
	char   *full_path;
	char *mount_data = mount_data_global;
#ifdef CONFIG_CIFS_DFS_UPCALL
	struct dfs_info3_param *referrals = NULL;
	unsigned int num_referrals = 0;
	int referral_walks_count = 0;
try_mount_again:
#endif
	rc = 0;
	tcon = NULL;
	pSesInfo = NULL;
	srvTcp = NULL;
	full_path = NULL;

	xid = GetXid();

	volume_info = kzalloc(sizeof(struct smb_vol), GFP_KERNEL);
	if (!volume_info) {
		rc = -ENOMEM;
		goto out;
	}

	if (cifs_parse_mount_options(mount_data, devname, volume_info)) {
		rc = -EINVAL;
		goto out;
	}

	if (volume_info->nullauth) {
		cFYI(1, ("null user"));
		volume_info->username = "";
	} else if (volume_info->username) {
		/* BB fixme parse for domain name here */
		cFYI(1, ("Username: %s", volume_info->username));
	} else {
		cifserror("No username specified");
	/* In userspace mount helper we can get user name from alternate
	   locations such as env variables and files on disk */
		rc = -EINVAL;
		goto out;
	}


	/* this is needed for ASCII cp to Unicode converts */
	if (volume_info->iocharset == NULL) {
		cifs_sb->local_nls = load_nls_default();
	/* load_nls_default can not return null */
	} else {
		cifs_sb->local_nls = load_nls(volume_info->iocharset);
		if (cifs_sb->local_nls == NULL) {
			cERROR(1, ("CIFS mount error: iocharset %s not found",
				 volume_info->iocharset));
			rc = -ELIBACC;
			goto out;
		}
	}

	/* get a reference to a tcp session */
	srvTcp = cifs_get_tcp_session(volume_info);
	if (IS_ERR(srvTcp)) {
		rc = PTR_ERR(srvTcp);
		goto out;
	}

	pSesInfo = cifs_find_smb_ses(srvTcp, volume_info->username);
	if (pSesInfo) {
		cFYI(1, ("Existing smb sess found (status=%d)",
			pSesInfo->status));
		/*
		 * The existing SMB session already has a reference to srvTcp,
		 * so we can put back the extra one we got before
		 */
		cifs_put_tcp_session(srvTcp);

		mutex_lock(&pSesInfo->session_mutex);
		if (pSesInfo->need_reconnect) {
			cFYI(1, ("Session needs reconnect"));
			rc = cifs_setup_session(xid, pSesInfo,
						cifs_sb->local_nls);
		}
		mutex_unlock(&pSesInfo->session_mutex);
	} else if (!rc) {
		cFYI(1, ("Existing smb sess not found"));
		pSesInfo = sesInfoAlloc();
		if (pSesInfo == NULL) {
			rc = -ENOMEM;
			goto mount_fail_check;
		}

		/* new SMB session uses our srvTcp ref */
		pSesInfo->server = srvTcp;
		if (srvTcp->addr.sockAddr6.sin6_family == AF_INET6)
			sprintf(pSesInfo->serverName, "%pI6",
				&srvTcp->addr.sockAddr6.sin6_addr);
		else
			sprintf(pSesInfo->serverName, "%pI4",
				&srvTcp->addr.sockAddr.sin_addr.s_addr);

		write_lock(&cifs_tcp_ses_lock);
		list_add(&pSesInfo->smb_ses_list, &srvTcp->smb_ses_list);
		write_unlock(&cifs_tcp_ses_lock);

		/* volume_info->password freed at unmount */
		if (volume_info->password) {
			pSesInfo->password = kstrdup(volume_info->password,
						     GFP_KERNEL);
			if (!pSesInfo->password) {
				rc = -ENOMEM;
				goto mount_fail_check;
			}
		}
		if (volume_info->username)
			strncpy(pSesInfo->userName, volume_info->username,
				MAX_USERNAME_SIZE);
		if (volume_info->domainname) {
			int len = strlen(volume_info->domainname);
			pSesInfo->domainName = kmalloc(len + 1, GFP_KERNEL);
			if (pSesInfo->domainName)
				strcpy(pSesInfo->domainName,
					volume_info->domainname);
		}
		pSesInfo->linux_uid = volume_info->linux_uid;
		pSesInfo->overrideSecFlg = volume_info->secFlg;
		mutex_lock(&pSesInfo->session_mutex);

		/* BB FIXME need to pass vol->secFlgs BB */
		rc = cifs_setup_session(xid, pSesInfo,
					cifs_sb->local_nls);
		mutex_unlock(&pSesInfo->session_mutex);
	}

	/* search for existing tcon to this server share */
	if (!rc) {
		setup_cifs_sb(volume_info, cifs_sb);

		tcon = cifs_find_tcon(pSesInfo, volume_info->UNC);
		if (tcon) {
			cFYI(1, ("Found match on UNC path"));
			/* existing tcon already has a reference */
			cifs_put_smb_ses(pSesInfo);
			if (tcon->seal != volume_info->seal)
				cERROR(1, ("transport encryption setting "
					   "conflicts with existing tid"));
		} else {
			tcon = tconInfoAlloc();
			if (tcon == NULL) {
				rc = -ENOMEM;
				goto mount_fail_check;
			}

			tcon->ses = pSesInfo;
			if (volume_info->password) {
				tcon->password = kstrdup(volume_info->password,
							 GFP_KERNEL);
				if (!tcon->password) {
					rc = -ENOMEM;
					goto mount_fail_check;
				}
			}

			if ((strchr(volume_info->UNC + 3, '\\') == NULL)
			    && (strchr(volume_info->UNC + 3, '/') == NULL)) {
				cERROR(1, ("Missing share name"));
				rc = -ENODEV;
				goto mount_fail_check;
			} else {
				/* BB Do we need to wrap sesSem around
				 * this TCon call and Unix SetFS as
				 * we do on SessSetup and reconnect? */
				rc = CIFSTCon(xid, pSesInfo, volume_info->UNC,
					      tcon, cifs_sb->local_nls);
				cFYI(1, ("CIFS Tcon rc = %d", rc));
				if (volume_info->nodfs) {
					tcon->Flags &= ~SMB_SHARE_IS_IN_DFS;
					cFYI(1, ("DFS disabled (%d)",
						tcon->Flags));
				}
			}
			if (rc)
				goto remote_path_check;
			tcon->seal = volume_info->seal;
			write_lock(&cifs_tcp_ses_lock);
			list_add(&tcon->tcon_list, &pSesInfo->tcon_list);
			write_unlock(&cifs_tcp_ses_lock);
		}

		/* we can have only one retry value for a connection
		   to a share so for resources mounted more than once
		   to the same server share the last value passed in
		   for the retry flag is used */
		tcon->retry = volume_info->retry;
		tcon->nocase = volume_info->nocase;
		tcon->local_lease = volume_info->local_lease;
	}
	if (pSesInfo) {
		if (pSesInfo->capabilities & CAP_LARGE_FILES)
			sb->s_maxbytes = MAX_LFS_FILESIZE;
		else
			sb->s_maxbytes = MAX_NON_LFS;
	}

	/* BB FIXME fix time_gran to be larger for LANMAN sessions */
	sb->s_time_gran = 100;

	if (rc)
		goto remote_path_check;

	cifs_sb->tcon = tcon;

	/* do not care if following two calls succeed - informational */
	if (!tcon->ipc) {
		CIFSSMBQFSDeviceInfo(xid, tcon);
		CIFSSMBQFSAttributeInfo(xid, tcon);
	}

	/* tell server which Unix caps we support */
	if (tcon->ses->capabilities & CAP_UNIX)
		/* reset of caps checks mount to see if unix extensions
		   disabled for just this mount */
		reset_cifs_unix_caps(xid, tcon, sb, volume_info);
	else
		tcon->unix_ext = 0; /* server does not support them */

	/* convert forward to back slashes in prepath here if needed */
	if ((cifs_sb->mnt_cifs_flags & CIFS_MOUNT_POSIX_PATHS) == 0)
		convert_delimiter(cifs_sb->prepath, CIFS_DIR_SEP(cifs_sb));

	if ((tcon->unix_ext == 0) && (cifs_sb->rsize > (1024 * 127))) {
		cifs_sb->rsize = 1024 * 127;
		cFYI(DBG2, ("no very large read support, rsize now 127K"));
	}
	if (!(tcon->ses->capabilities & CAP_LARGE_WRITE_X))
		cifs_sb->wsize = min(cifs_sb->wsize,
			       (tcon->ses->server->maxBuf - MAX_CIFS_HDR_SIZE));
	if (!(tcon->ses->capabilities & CAP_LARGE_READ_X))
		cifs_sb->rsize = min(cifs_sb->rsize,
			       (tcon->ses->server->maxBuf - MAX_CIFS_HDR_SIZE));

remote_path_check:
	/* check if a whole path (including prepath) is not remote */
	if (!rc && cifs_sb->prepathlen && tcon) {
		/* build_path_to_root works only when we have a valid tcon */
		full_path = cifs_build_path_to_root(cifs_sb);
		if (full_path == NULL) {
			rc = -ENOMEM;
			goto mount_fail_check;
		}
		rc = is_path_accessible(xid, tcon, cifs_sb, full_path);
		if (rc != -EREMOTE) {
			kfree(full_path);
			goto mount_fail_check;
		}
		kfree(full_path);
	}

	/* get referral if needed */
	if (rc == -EREMOTE) {
#ifdef CONFIG_CIFS_DFS_UPCALL
		if (referral_walks_count > MAX_NESTED_LINKS) {
			/*
			 * BB: when we implement proper loop detection,
			 *     we will remove this check. But now we need it
			 *     to prevent an indefinite loop if 'DFS tree' is
			 *     misconfigured (i.e. has loops).
			 */
			rc = -ELOOP;
			goto mount_fail_check;
		}
		/* convert forward to back slashes in prepath here if needed */
		if ((cifs_sb->mnt_cifs_flags & CIFS_MOUNT_POSIX_PATHS) == 0)
			convert_delimiter(cifs_sb->prepath,
					CIFS_DIR_SEP(cifs_sb));
		full_path = build_unc_path_to_root(volume_info, cifs_sb);
		if (IS_ERR(full_path)) {
			rc = PTR_ERR(full_path);
			goto mount_fail_check;
		}

		cFYI(1, ("Getting referral for: %s", full_path));
		rc = get_dfs_path(xid, pSesInfo , full_path + 1,
			cifs_sb->local_nls, &num_referrals, &referrals,
			cifs_sb->mnt_cifs_flags & CIFS_MOUNT_MAP_SPECIAL_CHR);
		if (!rc && num_referrals > 0) {
			char *fake_devname = NULL;

			if (mount_data != mount_data_global)
				kfree(mount_data);

			mount_data = cifs_compose_mount_options(
					cifs_sb->mountdata, full_path + 1,
					referrals, &fake_devname);

			free_dfs_info_array(referrals, num_referrals);
			kfree(fake_devname);
			kfree(full_path);

			if (IS_ERR(mount_data)) {
				rc = PTR_ERR(mount_data);
				mount_data = NULL;
				goto mount_fail_check;
			}

			if (tcon)
				cifs_put_tcon(tcon);
			else if (pSesInfo)
				cifs_put_smb_ses(pSesInfo);

			cleanup_volume_info(&volume_info);
			referral_walks_count++;
			FreeXid(xid);
			goto try_mount_again;
		}
#else /* No DFS support, return error on mount */
		rc = -EOPNOTSUPP;
#endif
	}

mount_fail_check:
	/* on error free sesinfo and tcon struct if needed */
	if (rc) {
		if (mount_data != mount_data_global)
			kfree(mount_data);
		/* If find_unc succeeded then rc == 0 so we can not end */
		/* up accidently freeing someone elses tcon struct */
		if (tcon)
			cifs_put_tcon(tcon);
		else if (pSesInfo)
			cifs_put_smb_ses(pSesInfo);
		else
			cifs_put_tcp_session(srvTcp);
		goto out;
	}

	/* volume_info->password is freed above when existing session found
	(in which case it is not needed anymore) but when new sesion is created
	the password ptr is put in the new session structure (in which case the
	password will be freed at unmount time) */
out:
	/* zero out password before freeing */
	cleanup_volume_info(&volume_info);
	FreeXid(xid);
	return rc;
}