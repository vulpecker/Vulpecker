
int netmon_open(wtap *wth, int *err, gchar **err_info)
{
	int bytes_read;
	char magic[sizeof netmon_1_x_magic];
	struct netmon_hdr hdr;
	int file_type;
	struct tm tm;
	guint32 frame_table_offset;
	guint32 frame_table_length;
	guint32 frame_table_size;
	guint32 *frame_table;
#ifdef WORDS_BIGENDIAN
	unsigned int i;
#endif
	netmon_t *netmon;

	/* Read in the string that should be at the start of a Network
	 * Monitor file */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(magic, sizeof magic, wth->fh);
	if (bytes_read != sizeof magic) {
		*err = file_error(wth->fh, err_info);
		if (*err != 0)
			return -1;
		return 0;
	}

	if (memcmp(magic, netmon_1_x_magic, sizeof netmon_1_x_magic) != 0
	 && memcmp(magic, netmon_2_x_magic, sizeof netmon_1_x_magic) != 0) {
		return 0;
	}

	/* Read the rest of the header. */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&hdr, sizeof hdr, wth->fh);
	if (bytes_read != sizeof hdr) {
		*err = file_error(wth->fh, err_info);
		if (*err != 0)
			return -1;
		return 0;
	}

	switch (hdr.ver_major) {

	case 1:
		file_type = WTAP_FILE_NETMON_1_x;
		break;

	case 2:
		file_type = WTAP_FILE_NETMON_2_x;
		break;

	default:
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = g_strdup_printf("netmon: major version %u unsupported", hdr.ver_major);
		return -1;
	}

	hdr.network = pletohs(&hdr.network);
	if (hdr.network >= NUM_NETMON_ENCAPS
	    || netmon_encap[hdr.network] == WTAP_ENCAP_UNKNOWN) {
		*err = WTAP_ERR_UNSUPPORTED_ENCAP;
		*err_info = g_strdup_printf("netmon: network type %u unknown or unsupported",
		    hdr.network);
		return -1;
	}

	/* This is a netmon file */
	wth->file_type = file_type;
	netmon = (netmon_t *)g_malloc(sizeof(netmon_t));
	wth->priv = (void *)netmon;
	wth->subtype_read = netmon_read;
	wth->subtype_seek_read = netmon_seek_read;
	wth->subtype_sequential_close = netmon_sequential_close;

	/* NetMon capture file formats v2.1+ use per-packet encapsulation types.  NetMon 3 sets the value in
	 * the header to 1 (Ethernet) for backwards compability. */
	if((hdr.ver_major == 2 && hdr.ver_minor >= 1) || hdr.ver_major > 2)
		wth->file_encap = WTAP_ENCAP_PER_PACKET;
	else
		wth->file_encap = netmon_encap[hdr.network];

	wth->snapshot_length = 0;	/* not available in header */
	/*
	 * Convert the time stamp to a "time_t" and a number of
	 * milliseconds.
	 */
	tm.tm_year = pletohs(&hdr.ts_year) - 1900;
	tm.tm_mon = pletohs(&hdr.ts_month) - 1;
	tm.tm_mday = pletohs(&hdr.ts_day);
	tm.tm_hour = pletohs(&hdr.ts_hour);
	tm.tm_min = pletohs(&hdr.ts_min);
	tm.tm_sec = pletohs(&hdr.ts_sec);
	tm.tm_isdst = -1;
	netmon->start_secs = mktime(&tm);
	/*
	 * XXX - what if "secs" is -1?  Unlikely, but if the capture was
	 * done in a time zone that switches between standard and summer
	 * time sometime other than when we do, and thus the time was one
	 * that doesn't exist here because a switch from standard to summer
	 * time zips over it, it could happen.
	 *
	 * On the other hand, if the capture was done in a different time
	 * zone, this won't work right anyway; unfortunately, the time
	 * zone isn't stored in the capture file (why the hell didn't
	 * they stuff a FILETIME, which is the number of 100-nanosecond
	 * intervals since 1601-01-01 00:00:00 "UTC", there, instead
	 * of stuffing a SYSTEMTIME, which is time-zone-dependent, there?).
	 */
	netmon->start_nsecs = pletohs(&hdr.ts_msec)*1000000;

	netmon->version_major = hdr.ver_major;
	netmon->version_minor = hdr.ver_minor;

	/*
	 * Get the offset of the frame index table.
	 */
	frame_table_offset = pletohl(&hdr.frametableoffset);

	/*
	 * It appears that some NetMon 2.x files don't have the
	 * first packet starting exactly 128 bytes into the file.
	 *
	 * Furthermore, it also appears that there are "holes" in
	 * the file, i.e. frame N+1 doesn't always follow immediately
	 * after frame N.
	 *
	 * Therefore, we must read the frame table, and use the offsets
	 * in it as the offsets of the frames.
	 */
	frame_table_length = pletohl(&hdr.frametablelength);
	frame_table_size = frame_table_length / (guint32)sizeof (guint32);
	if ((frame_table_size * sizeof (guint32)) != frame_table_length) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("netmon: frame table length is %u, which is not a multiple of the size of an entry",
		    frame_table_length);
		g_free(netmon);
		return -1;
	}
	if (frame_table_size == 0) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("netmon: frame table length is %u, which means it's less than one entry in size",
		    frame_table_length);
		g_free(netmon);
		return -1;
	}
	/*
	 * XXX - clamp the size of the frame table, so that we don't
	 * attempt to allocate a huge frame table and fail.
	 *
	 * Given that file offsets in the frame table are 32-bit,
	 * a NetMon file cannot be bigger than 2^32 bytes.
	 * Given that a NetMon 1.x-format packet header is 8 bytes,
	 * that means a NetMon file cannot have more than
	 * 512*2^20 packets.  We'll pick that as the limit for
	 * now; it's 1/8th of a 32-bit address space, which is
	 * probably not going to exhaust the address space all by
	 * itself, and probably won't exhaust the backing store.
	 */
	if (frame_table_size > 512*1024*1024) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("netmon: frame table length is %u, which is larger than we support",
		    frame_table_length);
		g_free(netmon);
		return -1;
	}
	if (file_seek(wth->fh, frame_table_offset, SEEK_SET, err) == -1) {
		g_free(netmon);
		return -1;
	}
	frame_table = (guint32 *)g_malloc(frame_table_length);
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(frame_table, frame_table_length, wth->fh);
	if ((guint32)bytes_read != frame_table_length) {
		*err = file_error(wth->fh, err_info);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		g_free(frame_table);
		g_free(netmon);
		return -1;
	}
	netmon->frame_table_size = frame_table_size;
	netmon->frame_table = frame_table;

#ifdef WORDS_BIGENDIAN
	/*
	 * OK, now byte-swap the frame table.
	 */
	for (i = 0; i < frame_table_size; i++)
		frame_table[i] = pletohl(&frame_table[i]);
#endif

	/* Set up to start reading at the first frame. */
	netmon->current_frame = 0;
	switch (netmon->version_major) {

	case 1:
		/*
		 * Version 1.x of the file format supports
		 * millisecond precision.
		 */
		wth->tsprecision = WTAP_FILE_TSPREC_MSEC;
		break;

	case 2:
		/*
		 * Version 1.x of the file format supports
		 * 100-nanosecond precision; we don't
		 * currently support that, so say
		 * "nanosecond precision" for now.
		 */
		wth->tsprecision = WTAP_FILE_TSPREC_NSEC;
		break;
	}
	return 1;
}