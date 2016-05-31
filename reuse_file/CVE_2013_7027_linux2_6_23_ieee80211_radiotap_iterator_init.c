
int CVE_2013_7027_linux2_6_23_ieee80211_radiotap_iterator_init(
    struct ieee80211_radiotap_iterator *iterator,
    struct ieee80211_radiotap_header *radiotap_header,
    int max_length)
{
	/* Linux only supports version 0 radiotap format */
	if (radiotap_header->it_version)
		return -EINVAL;

	/* sanity check for allowed length and radiotap length field */
	if (max_length < le16_to_cpu(get_unaligned(&radiotap_header->it_len)))
		return -EINVAL;

	iterator->rtheader = radiotap_header;
	iterator->max_length = le16_to_cpu(get_unaligned(
						&radiotap_header->it_len));
	iterator->arg_index = 0;
	iterator->bitmap_shifter = le32_to_cpu(get_unaligned(
						&radiotap_header->it_present));
	iterator->arg = (u8 *)radiotap_header + sizeof(*radiotap_header);
	iterator->this_arg = NULL;

	/* find payload start allowing for extended bitmap(s) */

	if (unlikely(iterator->bitmap_shifter & (1<<IEEE80211_RADIOTAP_EXT))) {
		while (le32_to_cpu(get_unaligned((__le32 *)iterator->arg)) &
				   (1<<IEEE80211_RADIOTAP_EXT)) {
			iterator->arg += sizeof(u32);

			/*
			 * check for insanity where the present bitmaps
			 * keep claiming to extend up to or even beyond the
			 * stated radiotap header length
			 */

			if (((ulong)iterator->arg -
			     (ulong)iterator->rtheader) > iterator->max_length)
				return -EINVAL;
		}

		iterator->arg += sizeof(u32);

		/*
		 * no need to check again for blowing past stated radiotap
		 * header length, because ieee80211_radiotap_iterator_next
		 * checks it before it is dereferenced
		 */
	}

	/* we are all initialized happily */

	return 0;
}