
static int
CVE_2011_1171_linux2_6_23_do_replace(void __user *user, unsigned int len)
{
	int ret;
	struct ipt_replace tmp;
	struct xt_table_info *newinfo;
	void *loc_cpu_entry;

	if (copy_from_user(&tmp, user, sizeof(tmp)) != 0)
		return -EFAULT;

	/* Hack: Causes ipchains to give correct error msg --RR */
	if (len != sizeof(tmp) + tmp.size)
		return -ENOPROTOOPT;

	/* overflow check */
	if (tmp.size >= (INT_MAX - sizeof(struct xt_table_info)) / NR_CPUS -
			SMP_CACHE_BYTES)
		return -ENOMEM;
	if (tmp.num_counters >= INT_MAX / sizeof(struct xt_counters))
		return -ENOMEM;

	newinfo = xt_alloc_table_info(tmp.size);
	if (!newinfo)
		return -ENOMEM;

	/* choose the copy that is our node/cpu */
	loc_cpu_entry = newinfo->entries[raw_smp_processor_id()];
	if (copy_from_user(loc_cpu_entry, user + sizeof(tmp),
			   tmp.size) != 0) {
		ret = -EFAULT;
		goto free_newinfo;
	}

	ret = translate_table(tmp.name, tmp.valid_hooks,
			      newinfo, loc_cpu_entry, tmp.size, tmp.num_entries,
			      tmp.hook_entry, tmp.underflow);
	if (ret != 0)
		goto free_newinfo;

	duprintf("ip_tables: Translated table\n");

	ret = __CVE_2011_1171_linux2_6_23_do_replace(tmp.name, tmp.valid_hooks,
			      newinfo, tmp.num_counters,
			      tmp.counters);
	if (ret)
		goto free_newinfo_untrans;
	return 0;

 free_newinfo_untrans:
	IPT_ENTRY_ITERATE(loc_cpu_entry, newinfo->size, cleanup_entry,NULL);
 free_newinfo:
	xt_free_table_info(newinfo);
	return ret;
}