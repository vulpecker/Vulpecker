 * CVE_2011_1776_linux2_6_23_is_gpt_valid() - tests one GPT header and PTEs for validity
 * @bdev
 * @lba is the logical block address of the GPT header to test
 * @gpt is a GPT header ptr, filled on return.
 * @ptes is a PTEs ptr, filled on return.
 *
 * Description: returns 1 if valid,  0 on error.
 * If valid, returns pointers to newly allocated GPT header and PTEs.
 */
static int
CVE_2011_1776_linux2_6_23_is_gpt_valid(struct block_device *bdev, u64 lba,
	     gpt_header **gpt, gpt_entry **ptes)
{
	u32 crc, origcrc;
	u64 lastlba;

	if (!bdev || !gpt || !ptes)
		return 0;
	if (!(*gpt = alloc_read_gpt_header(bdev, lba)))
		return 0;

	/* Check the GUID Partition Table signature */
	if (le64_to_cpu((*gpt)->signature) != GPT_HEADER_SIGNATURE) {
		Dprintk("GUID Partition Table Header signature is wrong:"
			"%lld != %lld\n",
			(unsigned long long)le64_to_cpu((*gpt)->signature),
			(unsigned long long)GPT_HEADER_SIGNATURE);
		goto fail;
	}

	/* Check the GUID Partition Table CRC */
	origcrc = le32_to_cpu((*gpt)->header_crc32);
	(*gpt)->header_crc32 = 0;
	crc = efi_crc32((const unsigned char *) (*gpt), le32_to_cpu((*gpt)->header_size));

	if (crc != origcrc) {
		Dprintk
		    ("GUID Partition Table Header CRC is wrong: %x != %x\n",
		     crc, origcrc);
		goto fail;
	}
	(*gpt)->header_crc32 = cpu_to_le32(origcrc);

	/* Check that the my_lba entry points to the LBA that contains
	 * the GUID Partition Table */
	if (le64_to_cpu((*gpt)->my_lba) != lba) {
		Dprintk("GPT my_lba incorrect: %lld != %lld\n",
			(unsigned long long)le64_to_cpu((*gpt)->my_lba),
			(unsigned long long)lba);
		goto fail;
	}

	/* Check the first_usable_lba and last_usable_lba are
	 * within the disk.
	 */
	lastlba = last_lba(bdev);
	if (le64_to_cpu((*gpt)->first_usable_lba) > lastlba) {
		Dprintk("GPT: first_usable_lba incorrect: %lld > %lld\n",
			(unsigned long long)le64_to_cpu((*gpt)->first_usable_lba),
			(unsigned long long)lastlba);
		goto fail;
	}
	if (le64_to_cpu((*gpt)->last_usable_lba) > lastlba) {
		Dprintk("GPT: last_usable_lba incorrect: %lld > %lld\n",
			(unsigned long long)le64_to_cpu((*gpt)->last_usable_lba),
			(unsigned long long)lastlba);
		goto fail;
	}

	if (!(*ptes = alloc_read_gpt_entries(bdev, *gpt)))
		goto fail;

	/* Check the GUID Partition Entry Array CRC */
	crc = efi_crc32((const unsigned char *) (*ptes),
			le32_to_cpu((*gpt)->num_partition_entries) *
			le32_to_cpu((*gpt)->sizeof_partition_entry));

	if (crc != le32_to_cpu((*gpt)->partition_entry_array_crc32)) {
		Dprintk("GUID Partitition Entry Array CRC check failed.\n");
		goto fail_ptes;
	}

	/* We're done, all's well */
	return 1;

 fail_ptes:
	kfree(*ptes);
	*ptes = NULL;
 fail:
	kfree(*gpt);
	*gpt = NULL;
	return 0;
}