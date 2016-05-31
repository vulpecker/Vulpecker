int CVE_2015_0206_openssl1_0_0_dtls1_get_record(SSL *s)
	{
	int ssl_major,ssl_minor;
	int i,n;
	SSL3_RECORD *rr;
	SSL_SESSION *sess;
	unsigned char *p = NULL;
	unsigned short version;
	DTLS1_BITMAP *bitmap;
	unsigned int is_next_epoch;

	rr= &(s->s3->rrec);
	sess=s->session;

	/* The epoch may have changed.  If so, process all the
	 * pending records.  This is a non-blocking operation. */
	if ( ! dtls1_process_buffered_records(s))
            return 0;

	/* if we're renegotiating, then there may be buffered records */
	if (dtls1_get_processed_record(s))
		return 1;

	/* get something from the wire */
again:
	/* check if we have the header */
	if (	(s->rstate != SSL_ST_READ_BODY) ||
		(s->packet_length < DTLS1_RT_HEADER_LENGTH)) 
		{
		n=ssl3_read_n(s, DTLS1_RT_HEADER_LENGTH, s->s3->rbuf.len, 0);
		/* read timeout is handled by dtls1_read_bytes */
		if (n <= 0) return(n); /* error or non-blocking */

		/* this packet contained a partial record, dump it */
		if (s->packet_length != DTLS1_RT_HEADER_LENGTH)
			{
			s->packet_length = 0;
			goto again;
			}

		s->rstate=SSL_ST_READ_BODY;

		p=s->packet;

		/* Pull apart the header into the DTLS1_RECORD */
		rr->type= *(p++);
		ssl_major= *(p++);
		ssl_minor= *(p++);
		version=(ssl_major<<8)|ssl_minor;

		/* sequence number is 64 bits, with top 2 bytes = epoch */ 
		n2s(p,rr->epoch);

		memcpy(&(s->s3->read_sequence[2]), p, 6);
		p+=6;

		n2s(p,rr->length);

		/* Lets check version */
		if (!s->first_packet)
			{
			if (version != s->version)
				{
				/* unexpected version, silently discard */
				rr->length = 0;
				s->packet_length = 0;
				goto again;
				}
			}

		if ((version & 0xff00) != (s->version & 0xff00))
			{
			/* wrong version, silently discard record */
			rr->length = 0;
			s->packet_length = 0;
			goto again;
			}

		if (rr->length > SSL3_RT_MAX_ENCRYPTED_LENGTH)
			{
			/* record too long, silently discard it */
			rr->length = 0;
			s->packet_length = 0;
			goto again;
			}

		/* now s->rstate == SSL_ST_READ_BODY */
		}

	/* s->rstate == SSL_ST_READ_BODY, get and decode the data */

	if (rr->length > s->packet_length-DTLS1_RT_HEADER_LENGTH)
		{
		/* now s->packet_length == DTLS1_RT_HEADER_LENGTH */
		i=rr->length;
		n=ssl3_read_n(s,i,i,1);
		if (n <= 0) return(n); /* error or non-blocking io */

		/* this packet contained a partial record, dump it */
		if ( n != i)
			{
			rr->length = 0;
			s->packet_length = 0;
			goto again;
			}

		/* now n == rr->length,
		 * and s->packet_length == DTLS1_RT_HEADER_LENGTH + rr->length */
		}
	s->rstate=SSL_ST_READ_HEADER; /* set state for later operations */

	/* match epochs.  NULL means the packet is dropped on the floor */
	bitmap = dtls1_get_bitmap(s, rr, &is_next_epoch);
	if ( bitmap == NULL)
		{
		rr->length = 0;
		s->packet_length = 0;  /* dump this record */
		goto again;   /* get another record */
		}

	/* Check whether this is a repeat, or aged record.
	 * Don't check if we're listening and this message is
	 * a ClientHello. They can look as if they're replayed,
	 * since they arrive from different connections and
	 * would be dropped unnecessarily.
	 */
	if (!(s->d1->listen && rr->type == SSL3_RT_HANDSHAKE &&
		*p == SSL3_MT_CLIENT_HELLO) &&
		!dtls1_record_replay_check(s, bitmap))
		{
		rr->length = 0;
		s->packet_length=0; /* dump this record */
		goto again;     /* get another record */
		}

	/* just read a 0 length packet */
	if (rr->length == 0) goto again;

	/* If this record is from the next epoch (either HM or ALERT),
	 * buffer it since it cannot be processed at this time. Records
	 * from the next epoch are marked as received even though they
	 * are not processed, so as to prevent any potential resource
	 * DoS attack */
	if (is_next_epoch)
		{
		dtls1_record_bitmap_update(s, bitmap);
		dtls1_buffer_record(s, &(s->d1->unprocessed_rcds), rr->seq_num);
		rr->length = 0;
		s->packet_length = 0;
		goto again;
		}

	if ( ! dtls1_process_record(s))
		return(0);

	dtls1_clear_timeouts(s);  /* done waiting */
	return(1);

	}