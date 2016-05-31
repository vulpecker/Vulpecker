
static int CVE_2006_4813_linux2_6_10___block_prepare_write(struct inode *inode, struct page *page,
		unsigned from, unsigned to, get_block_t *get_block)
{
	unsigned block_start, block_end;
	sector_t block;
	int err = 0;
	unsigned blocksize, bbits;
	struct buffer_head *bh, *head, *wait[2], **wait_bh=wait;

	BUG_ON(!PageLocked(page));
	BUG_ON(from > PAGE_CACHE_SIZE);
	BUG_ON(to > PAGE_CACHE_SIZE);
	BUG_ON(from > to);

	blocksize = 1 << inode->i_blkbits;
	if (!page_has_buffers(page))
		create_empty_buffers(page, blocksize, 0);
	head = page_buffers(page);

	bbits = inode->i_blkbits;
	block = (sector_t)page->index << (PAGE_CACHE_SHIFT - bbits);

	for(bh = head, block_start = 0; bh != head || !block_start;
	    block++, block_start=block_end, bh = bh->b_this_page) {
		block_end = block_start + blocksize;
		if (block_end <= from || block_start >= to) {
			if (PageUptodate(page)) {
				if (!buffer_uptodate(bh))
					set_buffer_uptodate(bh);
			}
			continue;
		}
		if (buffer_new(bh))
			clear_buffer_new(bh);
		if (!buffer_mapped(bh)) {
			err = get_block(inode, block, bh, 1);
			if (err)
				goto out;
			if (buffer_new(bh)) {
				clear_buffer_new(bh);
				unmap_underlying_metadata(bh->b_bdev,
							bh->b_blocknr);
				if (PageUptodate(page)) {
					set_buffer_uptodate(bh);
					continue;
				}
				if (block_end > to || block_start < from) {
					void *kaddr;

					kaddr = kmap_atomic(page, KM_USER0);
					if (block_end > to)
						memset(kaddr+to, 0,
							block_end-to);
					if (block_start < from)
						memset(kaddr+block_start,
							0, from-block_start);
					flush_dcache_page(page);
					kunmap_atomic(kaddr, KM_USER0);
				}
				continue;
			}
		}
		if (PageUptodate(page)) {
			if (!buffer_uptodate(bh))
				set_buffer_uptodate(bh);
			continue; 
		}
		if (!buffer_uptodate(bh) && !buffer_delay(bh) &&
		     (block_start < from || block_end > to)) {
			ll_rw_block(READ, 1, &bh);
			*wait_bh++=bh;
		}
	}
	/*
	 * If we issued read requests - let them complete.
	 */
	while(wait_bh > wait) {
		wait_on_buffer(*--wait_bh);
		if (!buffer_uptodate(*wait_bh))
			return -EIO;
	}
	return 0;
out:
	/*
	 * Zero out any newly allocated blocks to avoid exposing stale
	 * data.  If BH_New is set, we know that the block was newly
	 * allocated in the above loop.
	 */
	bh = head;
	block_start = 0;
	do {
		block_end = block_start+blocksize;
		if (block_end <= from)
			goto next_bh;
		if (block_start >= to)
			break;
		if (buffer_new(bh)) {
			void *kaddr;

			clear_buffer_new(bh);
			kaddr = kmap_atomic(page, KM_USER0);
			memset(kaddr+block_start, 0, bh->b_size);
			kunmap_atomic(kaddr, KM_USER0);
			set_buffer_uptodate(bh);
			mark_buffer_dirty(bh);
		}
next_bh:
		block_start = block_end;
		bh = bh->b_this_page;
	} while (bh != head);
	return err;
}