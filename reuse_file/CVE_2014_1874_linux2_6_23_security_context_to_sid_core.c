
static int CVE_2014_1874_linux2_6_23_security_context_to_sid_core(char *scontext, u32 scontext_len, u32 *sid, u32 def_sid)
{
	char *scontext2;
	struct context context;
	struct role_datum *role;
	struct type_datum *typdatum;
	struct user_datum *usrdatum;
	char *scontextp, *p, oldc;
	int rc = 0;

	if (!ss_initialized) {
		int i;

		for (i = 1; i < SECINITSID_NUM; i++) {
			if (!strcmp(initial_sid_to_string[i], scontext)) {
				*sid = i;
				goto out;
			}
		}
		*sid = SECINITSID_KERNEL;
		goto out;
	}
	*sid = SECSID_NULL;

	/* Copy the string so that we can modify the copy as we parse it.
	   The string should already by null terminated, but we append a
	   null suffix to the copy to avoid problems with the existing
	   attr package, which doesn't view the null terminator as part
	   of the attribute value. */
	scontext2 = kmalloc(scontext_len+1,GFP_KERNEL);
	if (!scontext2) {
		rc = -ENOMEM;
		goto out;
	}
	memcpy(scontext2, scontext, scontext_len);
	scontext2[scontext_len] = 0;

	context_init(&context);
	*sid = SECSID_NULL;

	POLICY_RDLOCK;

	/* Parse the security context. */

	rc = -EINVAL;
	scontextp = (char *) scontext2;

	/* Extract the user. */
	p = scontextp;
	while (*p && *p != ':')
		p++;

	if (*p == 0)
		goto out_unlock;

	*p++ = 0;

	usrdatum = hashtab_search(policydb.p_users.table, scontextp);
	if (!usrdatum)
		goto out_unlock;

	context.user = usrdatum->value;

	/* Extract role. */
	scontextp = p;
	while (*p && *p != ':')
		p++;

	if (*p == 0)
		goto out_unlock;

	*p++ = 0;

	role = hashtab_search(policydb.p_roles.table, scontextp);
	if (!role)
		goto out_unlock;
	context.role = role->value;

	/* Extract type. */
	scontextp = p;
	while (*p && *p != ':')
		p++;
	oldc = *p;
	*p++ = 0;

	typdatum = hashtab_search(policydb.p_types.table, scontextp);
	if (!typdatum)
		goto out_unlock;

	context.type = typdatum->value;

	rc = mls_context_to_sid(oldc, &p, &context, &sidtab, def_sid);
	if (rc)
		goto out_unlock;

	if ((p - scontext2) < scontext_len) {
		rc = -EINVAL;
		goto out_unlock;
	}

	/* Check the validity of the new context. */
	if (!policydb_context_isvalid(&policydb, &context)) {
		rc = -EINVAL;
		goto out_unlock;
	}
	/* Obtain the new sid. */
	rc = sidtab_context_to_sid(&sidtab, &context, sid);
out_unlock:
	POLICY_RDUNLOCK;
	context_destroy(&context);
	kfree(scontext2);
out:
	return rc;
}