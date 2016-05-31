
static int CVE_2013_1767_linux2_6_23_shmem_remount_fs(struct super_block *sb, int *flags, char *data)
{
	struct shmem_sb_info *sbinfo = SHMEM_SB(sb);
	unsigned long max_blocks = sbinfo->max_blocks;
	unsigned long max_inodes = sbinfo->max_inodes;
	int policy = sbinfo->policy;
	nodemask_t policy_nodes = sbinfo->policy_nodes;
	unsigned long blocks;
	unsigned long inodes;
	int error = -EINVAL;

	if (shmem_parse_options(data, NULL, NULL, NULL, &max_blocks,
				&max_inodes, &policy, &policy_nodes))
		return error;

	spin_lock(&sbinfo->stat_lock);
	blocks = sbinfo->max_blocks - sbinfo->free_blocks;
	inodes = sbinfo->max_inodes - sbinfo->free_inodes;
	if (max_blocks < blocks)
		goto out;
	if (max_inodes < inodes)
		goto out;
	/*
	 * Those tests also disallow limited->unlimited while any are in
	 * use, so i_blocks will always be zero when max_blocks is zero;
	 * but we must separately disallow unlimited->limited, because
	 * in that case we have no record of how much is already in use.
	 */
	if (max_blocks && !sbinfo->max_blocks)
		goto out;
	if (max_inodes && !sbinfo->max_inodes)
		goto out;

	error = 0;
	sbinfo->max_blocks  = max_blocks;
	sbinfo->free_blocks = max_blocks - blocks;
	sbinfo->max_inodes  = max_inodes;
	sbinfo->free_inodes = max_inodes - inodes;
	sbinfo->policy = policy;
	sbinfo->policy_nodes = policy_nodes;
out:
	spin_unlock(&sbinfo->stat_lock);
	return error;
}