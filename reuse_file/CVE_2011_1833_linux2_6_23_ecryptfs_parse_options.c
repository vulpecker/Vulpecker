static int CVE_2011_1833_linux2_6_23_ecryptfs_parse_options(struct super_block *sb, char *options)
{
	char *p;
	int rc = 0;
	int sig_set = 0;
	int cipher_name_set = 0;
	int cipher_key_bytes;
	int cipher_key_bytes_set = 0;
	struct key *auth_tok_key = NULL;
	struct ecryptfs_auth_tok *auth_tok = NULL;
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat =
		&ecryptfs_superblock_to_private(sb)->mount_crypt_stat;
	substring_t args[MAX_OPT_ARGS];
	int token;
	char *sig_src;
	char *sig_dst;
	char *debug_src;
	char *cipher_name_dst;
	char *cipher_name_src;
	char *cipher_key_bytes_src;
	int cipher_name_len;

	if (!options) {
		rc = -EINVAL;
		goto out;
	}
	while ((p = strsep(&options, ",")) != NULL) {
		if (!*p)
			continue;
		token = match_token(p, tokens, args);
		switch (token) {
		case ecryptfs_opt_sig:
		case ecryptfs_opt_ecryptfs_sig:
			sig_src = args[0].from;
			sig_dst =
				mount_crypt_stat->global_auth_tok_sig;
			memcpy(sig_dst, sig_src, ECRYPTFS_SIG_SIZE_HEX);
			sig_dst[ECRYPTFS_SIG_SIZE_HEX] = '\0';
			ecryptfs_printk(KERN_DEBUG,
					"The mount_crypt_stat "
					"global_auth_tok_sig set to: "
					"[%s]\n", sig_dst);
			sig_set = 1;
			break;
		case ecryptfs_opt_debug:
		case ecryptfs_opt_ecryptfs_debug:
			debug_src = args[0].from;
			ecryptfs_verbosity =
				(int)simple_strtol(debug_src, &debug_src,
						   0);
			ecryptfs_printk(KERN_DEBUG,
					"Verbosity set to [%d]" "\n",
					ecryptfs_verbosity);
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
	/* Do not support lack of mount-wide signature in 0.1
	 * release */
	if (!sig_set) {
		rc = -EINVAL;
		ecryptfs_printk(KERN_ERR, "You must supply a valid "
				"passphrase auth tok signature as a mount "
				"parameter; see the eCryptfs README\n");
		goto out;
	}
	if (!cipher_name_set) {
		cipher_name_len = strlen(ECRYPTFS_DEFAULT_CIPHER);
		if (unlikely(cipher_name_len
			     >= ECRYPTFS_MAX_CIPHER_NAME_SIZE)) {
			rc = -EINVAL;
			BUG();
			goto out;
		}
		memcpy(mount_crypt_stat->global_default_cipher_name,
		       ECRYPTFS_DEFAULT_CIPHER, cipher_name_len);
		mount_crypt_stat->global_default_cipher_name[cipher_name_len]
		    = '\0';
	}
	if (!cipher_key_bytes_set) {
		mount_crypt_stat->global_default_cipher_key_size = 0;
	}
	rc = ecryptfs_process_cipher(
		&mount_crypt_stat->global_key_tfm,
		mount_crypt_stat->global_default_cipher_name,
		&mount_crypt_stat->global_default_cipher_key_size);
	if (rc) {
		printk(KERN_ERR "Error attempting to initialize cipher [%s] "
		       "with key size [%Zd] bytes; rc = [%d]\n",
		       mount_crypt_stat->global_default_cipher_name,
		       mount_crypt_stat->global_default_cipher_key_size, rc);
		mount_crypt_stat->global_key_tfm = NULL;
		mount_crypt_stat->global_auth_tok_key = NULL;
		rc = -EINVAL;
		goto out;
	}
	mutex_init(&mount_crypt_stat->global_key_tfm_mutex);
	ecryptfs_printk(KERN_DEBUG, "Requesting the key with description: "
			"[%s]\n", mount_crypt_stat->global_auth_tok_sig);
	/* The reference to this key is held until umount is done The
	 * call to key_put is done in ecryptfs_put_super() */
	auth_tok_key = request_key(&key_type_user,
				   mount_crypt_stat->global_auth_tok_sig,
				   NULL);
	if (!auth_tok_key || IS_ERR(auth_tok_key)) {
		ecryptfs_printk(KERN_ERR, "Could not find key with "
				"description: [%s]\n",
				mount_crypt_stat->global_auth_tok_sig);
		process_request_key_err(PTR_ERR(auth_tok_key));
		rc = -EINVAL;
		goto out;
	}
	auth_tok = ecryptfs_get_key_payload_data(auth_tok_key);
	if (ecryptfs_verify_version(auth_tok->version)) {
		ecryptfs_printk(KERN_ERR, "Data structure version mismatch. "
				"Userspace tools must match eCryptfs kernel "
				"module with major version [%d] and minor "
				"version [%d]\n", ECRYPTFS_VERSION_MAJOR,
				ECRYPTFS_VERSION_MINOR);
		rc = -EINVAL;
		goto out;
	}
	if (auth_tok->token_type != ECRYPTFS_PASSWORD
	    && auth_tok->token_type != ECRYPTFS_PRIVATE_KEY) {
		ecryptfs_printk(KERN_ERR, "Invalid auth_tok structure "
				"returned from key query\n");
		rc = -EINVAL;
		goto out;
	}
	mount_crypt_stat->global_auth_tok_key = auth_tok_key;
	mount_crypt_stat->global_auth_tok = auth_tok;
out:
	return rc;
}