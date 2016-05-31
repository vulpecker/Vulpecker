static int CVE_2011_1833_linux2_6_27_31_ecryptfs_parse_options(struct super_block *sb, char *options)
{
	char *p;
	int rc = 0;
	int sig_set = 0;
	int cipher_name_set = 0;
	int cipher_key_bytes;
	int cipher_key_bytes_set = 0;
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat =
		&ecryptfs_superblock_to_private(sb)->mount_crypt_stat;
	substring_t args[MAX_OPT_ARGS];
	int token;
	char *sig_src;
	char *cipher_name_dst;
	char *cipher_name_src;
	char *cipher_key_bytes_src;

	if (!options) {
		rc = -EINVAL;
		goto out;
	}
	ecryptfs_init_mount_crypt_stat(mount_crypt_stat);
	while ((p = strsep(&options, ",")) != NULL) {
		if (!*p)
			continue;
		token = match_token(p, tokens, args);
		switch (token) {
		case ecryptfs_opt_sig:
		case ecryptfs_opt_ecryptfs_sig:
			sig_src = args[0].from;
			rc = ecryptfs_add_global_auth_tok(mount_crypt_stat,
							  sig_src);
			if (rc) {
				printk(KERN_ERR "Error attempting to register "
				       "global sig; rc = [%d]\n", rc);
				goto out;
			}
			sig_set = 1;
			break;
		case ecryptfs_opt_cipher:
		case ecryptfs_opt_ecryptfs_cipher:
			cipher_name_src = args[0].from;
			cipher_name_dst =
				mount_crypt_stat->
				global_default_cipher_name;
			strncpy(cipher_name_dst, cipher_name_src,
				ECRYPTFS_MAX_CIPHER_NAME_SIZE);
			ecryptfs_printk(KERN_DEBUG,
					"The mount_crypt_stat "
					"global_default_cipher_name set to: "
					"[%s]\n", cipher_name_dst);
			cipher_name_set = 1;
			break;
		case ecryptfs_opt_ecryptfs_key_bytes:
			cipher_key_bytes_src = args[0].from;
			cipher_key_bytes =
				(int)simple_strtol(cipher_key_bytes_src,
						   &cipher_key_bytes_src, 0);
			mount_crypt_stat->global_default_cipher_key_size =
				cipher_key_bytes;
			ecryptfs_printk(KERN_DEBUG,
					"The mount_crypt_stat "
					"global_default_cipher_key_size "
					"set to: [%d]\n", mount_crypt_stat->
					global_default_cipher_key_size);
			cipher_key_bytes_set = 1;
			break;
		case ecryptfs_opt_passthrough:
			mount_crypt_stat->flags |=
				ECRYPTFS_PLAINTEXT_PASSTHROUGH_ENABLED;
			break;
		case ecryptfs_opt_xattr_metadata:
			mount_crypt_stat->flags |=
				ECRYPTFS_XATTR_METADATA_ENABLED;
			break;
		case ecryptfs_opt_encrypted_view:
			mount_crypt_stat->flags |=
				ECRYPTFS_XATTR_METADATA_ENABLED;
			mount_crypt_stat->flags |=
				ECRYPTFS_ENCRYPTED_VIEW_ENABLED;
			break;
		case ecryptfs_opt_err:
		default:
			ecryptfs_printk(KERN_WARNING,
					"eCryptfs: unrecognized option '%s'\n",
					p);
		}
	}
	if (!sig_set) {
		rc = -EINVAL;
		ecryptfs_printk(KERN_ERR, "You must supply at least one valid "
				"auth tok signature as a mount "
				"parameter; see the eCryptfs README\n");
		goto out;
	}
	if (!cipher_name_set) {
		int cipher_name_len = strlen(ECRYPTFS_DEFAULT_CIPHER);

		BUG_ON(cipher_name_len >= ECRYPTFS_MAX_CIPHER_NAME_SIZE);

		strcpy(mount_crypt_stat->global_default_cipher_name,
		       ECRYPTFS_DEFAULT_CIPHER);
	}
	if (!cipher_key_bytes_set) {
		mount_crypt_stat->global_default_cipher_key_size = 0;
	}
	mutex_lock(&key_tfm_list_mutex);
	if (!ecryptfs_tfm_exists(mount_crypt_stat->global_default_cipher_name,
				 NULL))
		rc = ecryptfs_add_new_key_tfm(
			NULL, mount_crypt_stat->global_default_cipher_name,
			mount_crypt_stat->global_default_cipher_key_size);
	mutex_unlock(&key_tfm_list_mutex);
	if (rc) {
		printk(KERN_ERR "Error attempting to initialize cipher with "
		       "name = [%s] and key size = [%td]; rc = [%d]\n",
		       mount_crypt_stat->global_default_cipher_name,
		       mount_crypt_stat->global_default_cipher_key_size, rc);
		rc = -EINVAL;
		goto out;
	}
	rc = ecryptfs_init_global_auth_toks(mount_crypt_stat);
	if (rc) {
		printk(KERN_WARNING "One or more global auth toks could not "
		       "properly register; rc = [%d]\n", rc);
	}
out:
	return rc;
}