
static int CVE_2010_3084_linux2_6_31_2_niu_get_ethtool_tcam_all(struct niu *np,
				    struct ethtool_rxnfc *nfc,
				    u32 *rule_locs)
{
	struct niu_parent *parent = np->parent;
	struct niu_tcam_entry *tp;
	int i, idx, cnt;
	u16 n_entries;
	unsigned long flags;


	/* put the tcam size here */
	nfc->data = tcam_get_size(np);

	niu_lock_parent(np, flags);
	n_entries = nfc->rule_cnt;
	for (cnt = 0, i = 0; i < nfc->data; i++) {
		idx = tcam_get_index(np, i);
		tp = &parent->tcam[idx];
		if (!tp->valid)
			continue;
		rule_locs[cnt] = i;
		cnt++;
	}
	niu_unlock_parent(np, flags);

	if (n_entries != cnt) {
		/* print warning, this should not happen */
		pr_info(PFX "niu%d: %s In CVE_2010_3084_linux2_6_31_2_niu_get_ethtool_tcam_all, "
			"n_entries[%d] != cnt[%d]!!!\n\n",
			np->parent->index, np->dev->name, n_entries, cnt);
	}

	return 0;
}