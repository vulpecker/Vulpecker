
static int CVE_2009_4307_linux2_6_28_ext4_fill_flex_info(struct super_block *sb)
{
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	struct ext4_group_desc *gdp = NULL;
	struct buffer_head *bh;
	ext4_group_t flex_group_count;
	ext4_group_t flex_group;
	int groups_per_flex = 0;
	__u64 block_bitmap = 0;
	int i;

	if (!sbi->s_es->s_log_groups_per_flex) {
		sbi->s_log_groups_per_flex = 0;
		return 1;
	}

	sbi->s_log_groups_per_flex = sbi->s_es->s_log_groups_per_flex;
	groups_per_flex = 1 << sbi->s_log_groups_per_flex;

	/* We allocate both existing and potentially added groups */
	flex_group_count = ((sbi->s_groups_count + groups_per_flex - 1) +
			((le16_to_cpu(sbi->s_es->s_reserved_gdt_blocks) + 1) <<
			      EXT4_DESC_PER_BLOCK_BITS(sb))) / groups_per_flex;
	sbi->s_flex_groups = kzalloc(flex_group_count *
				     sizeof(struct flex_groups), GFP_KERNEL);
	if (sbi->s_flex_groups == NULL) {
		printk(KERN_ERR "EXT4-fs: not enough memory for "
				"%lu flex groups\n", flex_group_count);
		goto failed;
	}

	gdp = ext4_get_group_desc(sb, 1, &bh);
	block_bitmap = ext4_block_bitmap(sb, gdp) - 1;

	for (i = 0; i < sbi->s_groups_count; i++) {
		gdp = ext4_get_group_desc(sb, i, &bh);

		flex_group = ext4_flex_group(sbi, i);
		sbi->s_flex_groups[flex_group].free_inodes +=
			le16_to_cpu(gdp->bg_free_inodes_count);
		sbi->s_flex_groups[flex_group].free_blocks +=
			le16_to_cpu(gdp->bg_free_blocks_count);
	}

	return 1;
failed:
	return 0;
}