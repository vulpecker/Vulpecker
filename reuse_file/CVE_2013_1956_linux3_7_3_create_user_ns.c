int CVE_2013_1956_linux3_7_3_create_user_ns(struct cred *new)
{
	struct user_namespace *ns, *parent_ns = new->user_ns;
	kuid_t owner = new->euid;
	kgid_t group = new->egid;

	/* The creator needs a mapping in the parent user namespace
	 * or else we won't be able to reasonably tell userspace who
	 * created a user_namespace.
	 */
	if (!kuid_has_mapping(parent_ns, owner) ||
	    !kgid_has_mapping(parent_ns, group))
		return -EPERM;

	ns = kmem_cache_zalloc(user_ns_cachep, GFP_KERNEL);
	if (!ns)
		return -ENOMEM;

	kref_init(&ns->kref);
	ns->parent = parent_ns;
	ns->owner = owner;
	ns->group = group;

	/* Start with the same capabilities as init but useless for doing
	 * anything as the capabilities are bound to the new user namespace.
	 */
	new->securebits = SECUREBITS_DEFAULT;
	new->cap_inheritable = CAP_EMPTY_SET;
	new->cap_permitted = CAP_FULL_SET;
	new->cap_effective = CAP_FULL_SET;
	new->cap_bset = CAP_FULL_SET;
#ifdef CONFIG_KEYS
	key_put(new->request_key_auth);
	new->request_key_auth = NULL;
#endif
	/* tgcred will be cleared in our caller bc CLONE_THREAD won't be set */

	/* Leave the new->user_ns reference with the new user namespace. */
	/* Leave the reference to our user_ns with the new cred. */
	new->user_ns = ns;

	return 0;
}