
int CVE_2010_3015_linux2_6_19_ext4_ext_get_blocks(handle_t *handle, struct inode *inode,
			ext4_fsblk_t iblock,
			unsigned long max_blocks, struct buffer_head *bh_result,
			int create, int extend_disksize)
{
	struct ext4_ext_path *path = NULL;
	struct ext4_extent newex, *ex;
	ext4_fsblk_t goal, newblock;
	int err = 0, depth;
	unsigned long allocated = 0;

	__clear_bit(BH_New, &bh_result->b_state);
	ext_debug("blocks %d/%lu requested for inode %u\n", (int) iblock,
			max_blocks, (unsigned) inode->i_ino);
	mutex_lock(&EXT4_I(inode)->truncate_mutex);

	/* check in cache */
	if ((goal = ext4_ext_in_cache(inode, iblock, &newex))) {
		if (goal == EXT4_EXT_CACHE_GAP) {
			if (!create) {
				/* block isn't allocated yet and
				 * user doesn't want to allocate it */
				goto out2;
			}
			/* we should allocate requested block */
		} else if (goal == EXT4_EXT_CACHE_EXTENT) {
			/* block is already allocated */
		        newblock = iblock
		                   - le32_to_cpu(newex.ee_block)
			           + ext_pblock(&newex);
			/* number of remaining blocks in the extent */
			allocated = le16_to_cpu(newex.ee_len) -
					(iblock - le32_to_cpu(newex.ee_block));
			goto out;
		} else {
			BUG();
		}
	}

	/* find extent for this block */
	path = ext4_ext_find_extent(inode, iblock, NULL);
	if (IS_ERR(path)) {
		err = PTR_ERR(path);
		path = NULL;
		goto out2;
	}

	depth = ext_depth(inode);

	/*
	 * consistent leaf must not be empty;
	 * this situation is possible, though, _during_ tree modification;
	 * this is why assert can't be put in ext4_ext_find_extent()
	 */
	BUG_ON(path[depth].p_ext == NULL && depth != 0);

	if ((ex = path[depth].p_ext)) {
	        unsigned long ee_block = le32_to_cpu(ex->ee_block);
		ext4_fsblk_t ee_start = ext_pblock(ex);
		unsigned short ee_len  = le16_to_cpu(ex->ee_len);

		/*
		 * Allow future support for preallocated extents to be added
		 * as an RO_COMPAT feature:
		 * Uninitialized extents are treated as holes, except that
		 * we avoid (fail) allocating new blocks during a write.
		 */
		if (ee_len > EXT_MAX_LEN)
			goto out2;
		/* if found extent covers block, simply return it */
	        if (iblock >= ee_block && iblock < ee_block + ee_len) {
			newblock = iblock - ee_block + ee_start;
			/* number of remaining blocks in the extent */
			allocated = ee_len - (iblock - ee_block);
			ext_debug("%d fit into %lu:%d -> %llu\n", (int) iblock,
					ee_block, ee_len, newblock);
			ext4_ext_put_in_cache(inode, ee_block, ee_len,
						ee_start, EXT4_EXT_CACHE_EXTENT);
			goto out;
		}
	}

	/*
	 * requested block isn't allocated yet;
	 * we couldn't try to create block if create flag is zero
	 */
	if (!create) {
		/* put just found gap into cache to speed up
		 * subsequent requests */
		ext4_ext_put_gap_in_cache(inode, path, iblock);
		goto out2;
	}
	/*
	 * Okay, we need to do block allocation.  Lazily initialize the block
	 * allocation info here if necessary.
	 */
	if (S_ISREG(inode->i_mode) && (!EXT4_I(inode)->i_block_alloc_info))
		ext4_init_block_alloc_info(inode);

	/* allocate new block */
	goal = ext4_ext_find_goal(inode, path, iblock);
	allocated = max_blocks;
	newblock = ext4_new_blocks(handle, inode, goal, &allocated, &err);
	if (!newblock)
		goto out2;
	ext_debug("allocate new block: goal %llu, found %llu/%lu\n",
			goal, newblock, allocated);

	/* try to insert new extent into found leaf and return */
	newex.ee_block = cpu_to_le32(iblock);
	ext4_ext_store_pblock(&newex, newblock);
	newex.ee_len = cpu_to_le16(allocated);
	err = ext4_ext_insert_extent(handle, inode, path, &newex);
	if (err)
		goto out2;

	if (extend_disksize && inode->i_size > EXT4_I(inode)->i_disksize)
		EXT4_I(inode)->i_disksize = inode->i_size;

	/* previous routine could use block we allocated */
	newblock = ext_pblock(&newex);
	__set_bit(BH_New, &bh_result->b_state);

	ext4_ext_put_in_cache(inode, iblock, allocated, newblock,
				EXT4_EXT_CACHE_EXTENT);
out:
	if (allocated > max_blocks)
		allocated = max_blocks;
	ext4_ext_show_leaf(inode, path);
	__set_bit(BH_Mapped, &bh_result->b_state);
	bh_result->b_bdev = inode->i_sb->s_bdev;
	bh_result->b_blocknr = newblock;
out2:
	if (path) {
		ext4_ext_drop_refs(path);
		kfree(path);
	}
	mutex_unlock(&EXT4_I(inode)->truncate_mutex);

	return err ? err : allocated;
}