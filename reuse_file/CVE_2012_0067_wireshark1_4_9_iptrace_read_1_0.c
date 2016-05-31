static gboolean iptrace_read_1_0(wtap *wth, int *err, gchar **err_info _U_,
    gint64 *data_offset)
{
	int			ret;
	guint32			packet_size;
	guint8			header[IPTRACE_1_0_PHDR_SIZE];
	guint8			*data_ptr;
	iptrace_1_0_phdr	pkt_hdr;
	guchar			fddi_padding[3];

	/* Read the descriptor data */
	*data_offset = wth->data_offset;
	ret = iptrace_read_rec_header(wth->fh, header, IPTRACE_1_0_PHDR_SIZE,
	    err);
	if (ret <= 0) {
		/* Read error or EOF */
		return FALSE;
	}
	wth->data_offset += IPTRACE_1_0_PHDR_SIZE;

	/*
	 * Byte 28 of the frame header appears to be a BSD-style IFT_xxx
	 * value giving the type of the interface.  Check out the
	 * <net/if_types.h> header file.
	 */
	pkt_hdr.if_type = header[28];
	wth->phdr.pkt_encap = wtap_encap_ift(pkt_hdr.if_type);

	/* Read the packet data */
	packet_size = pntohl(&header[0]) - IPTRACE_1_0_PDATA_SIZE;

	/*
	 * AIX appears to put 3 bytes of padding in front of FDDI
	 * frames; strip that crap off.
	 */
	if (wth->phdr.pkt_encap == WTAP_ENCAP_FDDI_BITSWAPPED) {
		/*
		 * The packet size is really a record size and includes
		 * the padding.
		 */
		packet_size -= 3;
		wth->data_offset += 3;

		/*
		 * Read the padding.
		 */
		if (!iptrace_read_rec_data(wth->fh, fddi_padding, 3, err))
			return FALSE;	/* Read error */
	}

	buffer_assure_space( wth->frame_buffer, packet_size );
	data_ptr = buffer_start_ptr( wth->frame_buffer );
	if (!iptrace_read_rec_data(wth->fh, data_ptr, packet_size, err))
		return FALSE;	/* Read error */
	wth->data_offset += packet_size;

	wth->phdr.len = packet_size;
	wth->phdr.caplen = packet_size;
	wth->phdr.ts.secs = pntohl(&header[4]);
	wth->phdr.ts.nsecs = 0;

	if (wth->phdr.pkt_encap == WTAP_ENCAP_UNKNOWN) {
		*err = WTAP_ERR_UNSUPPORTED_ENCAP;
		*err_info = g_strdup_printf("iptrace: interface type IFT=0x%02x unknown or unsupported",
		    pkt_hdr.if_type);
		return FALSE;
	}

	/* Fill in the pseudo-header. */
	fill_in_pseudo_header(wth->phdr.pkt_encap, data_ptr, wth->phdr.caplen,
	    &wth->pseudo_header, header);

	/* If the per-file encapsulation isn't known, set it to this
	   packet's encapsulation.

	   If it *is* known, and it isn't this packet's encapsulation,
	   set it to WTAP_ENCAP_PER_PACKET, as this file doesn't
	   have a single encapsulation for all packets in the file. */
	if (wth->file_encap == WTAP_ENCAP_UNKNOWN)
		wth->file_encap = wth->phdr.pkt_encap;
	else {
		if (wth->file_encap != wth->phdr.pkt_encap)
			wth->file_encap = WTAP_ENCAP_PER_PACKET;
	}

	return TRUE;
}