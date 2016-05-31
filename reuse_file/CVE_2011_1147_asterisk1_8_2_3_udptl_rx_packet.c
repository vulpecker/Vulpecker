
static int CVE_2011_1147_asterisk1_8_2_3_udptl_rx_packet(struct ast_udptl *s, uint8_t *buf, unsigned int len)
{
	int stat1;
	int stat2;
	int i;
	int j;
	int k;
	int l;
	int m;
	int x;
	int limit;
	int which;
	unsigned int ptr;
	unsigned int count;
	int total_count;
	int seq_no;
	const uint8_t *ifp;
	const uint8_t *data;
	unsigned int ifp_len;
	int repaired[16];
	const uint8_t *bufs[16];
	unsigned int lengths[16];
	int span;
	int entries;
	int ifp_no;

	ptr = 0;
	ifp_no = 0;
	memset(&s->f[0], 0, sizeof(s->f[0]));

	/* Decode seq_number */
	if (ptr + 2 > len)
		return -1;
	seq_no = (buf[0] << 8) | buf[1];
	ptr += 2;

	/* Break out the primary packet */
	if ((stat1 = decode_open_type(buf, len, &ptr, &ifp, &ifp_len)) != 0)
		return -1;
	/* Decode error_recovery */
	if (ptr + 1 > len)
		return -1;
	if ((buf[ptr++] & 0x80) == 0) {
		/* Secondary packet mode for error recovery */
		if (seq_no > s->rx_seq_no) {
			/* We received a later packet than we expected, so we need to check if we can fill in the gap from the
			   secondary packets. */
			total_count = 0;
			do {
				if ((stat2 = decode_length(buf, len, &ptr, &count)) < 0)
					return -1;
				for (i = 0; i < count; i++) {
					if ((stat1 = decode_open_type(buf, len, &ptr, &bufs[total_count + i], &lengths[total_count + i])) != 0)
						return -1;
				}
				total_count += count;
			}
			while (stat2 > 0);
			/* Step through in reverse order, so we go oldest to newest */
			for (i = total_count; i > 0; i--) {
				if (seq_no - i >= s->rx_seq_no) {
					/* This one wasn't seen before */
					/* Decode the secondary IFP packet */
					//fprintf(stderr, "Secondary %d, len %d\n", seq_no - i, lengths[i - 1]);
					s->f[ifp_no].frametype = AST_FRAME_MODEM;
					s->f[ifp_no].subclass.codec = AST_MODEM_T38;

					s->f[ifp_no].mallocd = 0;
					s->f[ifp_no].seqno = seq_no - i;
					s->f[ifp_no].datalen = lengths[i - 1];
					s->f[ifp_no].data.ptr = (uint8_t *) bufs[i - 1];
					s->f[ifp_no].offset = 0;
					s->f[ifp_no].src = "UDPTL";
					if (ifp_no > 0)
						AST_LIST_NEXT(&s->f[ifp_no - 1], frame_list) = &s->f[ifp_no];
					AST_LIST_NEXT(&s->f[ifp_no], frame_list) = NULL;
					ifp_no++;
				}
			}
		}
	}
	else
	{
		/* FEC mode for error recovery */
		/* Our buffers cannot tolerate overlength IFP packets in FEC mode */
		if (ifp_len > LOCAL_FAX_MAX_DATAGRAM)
			return -1;
		/* Update any missed slots in the buffer */
		for ( ; seq_no > s->rx_seq_no; s->rx_seq_no++) {
			x = s->rx_seq_no & UDPTL_BUF_MASK;
			s->rx[x].buf_len = -1;
			s->rx[x].fec_len[0] = 0;
			s->rx[x].fec_span = 0;
			s->rx[x].fec_entries = 0;
		}

		x = seq_no & UDPTL_BUF_MASK;

		memset(repaired, 0, sizeof(repaired));

		/* Save the new IFP packet */
		memcpy(s->rx[x].buf, ifp, ifp_len);
		s->rx[x].buf_len = ifp_len;
		repaired[x] = TRUE;

		/* Decode the FEC packets */
		/* The span is defined as an unconstrained integer, but will never be more
		   than a small value. */
		if (ptr + 2 > len)
			return -1;
		if (buf[ptr++] != 1)
			return -1;
		span = buf[ptr++];
		s->rx[x].fec_span = span;

		/* The number of entries is defined as a length, but will only ever be a small
		   value. Treat it as such. */
		if (ptr + 1 > len)
			return -1;
		entries = buf[ptr++];
		s->rx[x].fec_entries = entries;

		/* Decode the elements */
		for (i = 0; i < entries; i++) {
			if ((stat1 = decode_open_type(buf, len, &ptr, &data, &s->rx[x].fec_len[i])) != 0)
				return -1;
			if (s->rx[x].fec_len[i] > LOCAL_FAX_MAX_DATAGRAM)
				return -1;

			/* Save the new FEC data */
			memcpy(s->rx[x].fec[i], data, s->rx[x].fec_len[i]);
#if 0
			fprintf(stderr, "FEC: ");
			for (j = 0; j < s->rx[x].fec_len[i]; j++)
				fprintf(stderr, "%02X ", data[j]);
			fprintf(stderr, "\n");
#endif
		}

		/* See if we can reconstruct anything which is missing */
		/* TODO: this does not comprehensively hunt back and repair everything that is possible */
		for (l = x; l != ((x - (16 - span*entries)) & UDPTL_BUF_MASK); l = (l - 1) & UDPTL_BUF_MASK) {
			if (s->rx[l].fec_len[0] <= 0)
				continue;
			for (m = 0; m < s->rx[l].fec_entries; m++) {
				limit = (l + m) & UDPTL_BUF_MASK;
				for (which = -1, k = (limit - s->rx[l].fec_span * s->rx[l].fec_entries) & UDPTL_BUF_MASK; k != limit; k = (k + s->rx[l].fec_entries) & UDPTL_BUF_MASK) {
					if (s->rx[k].buf_len <= 0)
						which = (which == -1) ? k : -2;
				}
				if (which >= 0) {
					/* Repairable */
					for (j = 0; j < s->rx[l].fec_len[m]; j++) {
						s->rx[which].buf[j] = s->rx[l].fec[m][j];
						for (k = (limit - s->rx[l].fec_span * s->rx[l].fec_entries) & UDPTL_BUF_MASK; k != limit; k = (k + s->rx[l].fec_entries) & UDPTL_BUF_MASK)
							s->rx[which].buf[j] ^= (s->rx[k].buf_len > j) ? s->rx[k].buf[j] : 0;
					}
					s->rx[which].buf_len = s->rx[l].fec_len[m];
					repaired[which] = TRUE;
				}
			}
		}
		/* Now play any new packets forwards in time */
		for (l = (x + 1) & UDPTL_BUF_MASK, j = seq_no - UDPTL_BUF_MASK; l != x; l = (l + 1) & UDPTL_BUF_MASK, j++) {
			if (repaired[l]) {
				//fprintf(stderr, "Fixed packet %d, len %d\n", j, l);
				s->f[ifp_no].frametype = AST_FRAME_MODEM;
				s->f[ifp_no].subclass.codec = AST_MODEM_T38;
			
				s->f[ifp_no].mallocd = 0;
				s->f[ifp_no].seqno = j;
				s->f[ifp_no].datalen = s->rx[l].buf_len;
				s->f[ifp_no].data.ptr = s->rx[l].buf;
				s->f[ifp_no].offset = 0;
				s->f[ifp_no].src = "UDPTL";
				if (ifp_no > 0)
					AST_LIST_NEXT(&s->f[ifp_no - 1], frame_list) = &s->f[ifp_no];
				AST_LIST_NEXT(&s->f[ifp_no], frame_list) = NULL;
				ifp_no++;
			}
		}
	}

	/* If packets are received out of sequence, we may have already processed this packet from the error
	   recovery information in a packet already received. */
	if (seq_no >= s->rx_seq_no) {
		/* Decode the primary IFP packet */
		s->f[ifp_no].frametype = AST_FRAME_MODEM;
		s->f[ifp_no].subclass.codec = AST_MODEM_T38;
		
		s->f[ifp_no].mallocd = 0;
		s->f[ifp_no].seqno = seq_no;
		s->f[ifp_no].datalen = ifp_len;
		s->f[ifp_no].data.ptr = (uint8_t *) ifp;
		s->f[ifp_no].offset = 0;
		s->f[ifp_no].src = "UDPTL";
		if (ifp_no > 0)
			AST_LIST_NEXT(&s->f[ifp_no - 1], frame_list) = &s->f[ifp_no];
		AST_LIST_NEXT(&s->f[ifp_no], frame_list) = NULL;

		ifp_no++;
	}

	s->rx_seq_no = seq_no + 1;
	return ifp_no;
}