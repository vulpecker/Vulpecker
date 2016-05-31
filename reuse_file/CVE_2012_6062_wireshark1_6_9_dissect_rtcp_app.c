
static int
dissect_rtcp_app( tvbuff_t *tvb,packet_info *pinfo, int offset, proto_tree *tree,
                  unsigned int padding, unsigned int packet_len, guint rtcp_subtype,
                  guint32 app_length )
{
	unsigned int counter = 0;
	char ascii_name[5];
	guint sdes_type		= 0;
	guint item_len		= 0;
	guint items_start_offset;
	proto_tree *PoC1_tree;
	proto_item *PoC1_item;

	/* XXX If more application types are to be dissected it may be useful to use a table like in packet-sip.c */
	static const char poc1_app_name_str[] = "PoC1";
	static const char mux_app_name_str[] = "3GPP";


	/* SSRC / CSRC */
	proto_tree_add_item( tree, hf_rtcp_ssrc_source, tvb, offset, 4, FALSE );
	offset += 4;
	packet_len -= 4;

	/* Application Name (ASCII) */
	for( counter = 0; counter < 4; counter++ )
	    ascii_name[ counter ] = tvb_get_guint8( tvb, offset + counter );
	/* g_strlcpy( ascii_name, pd + offset, 4 ); */
	ascii_name[4] = '\0';
	proto_tree_add_string( tree, hf_rtcp_name_ascii, tvb, offset, 4,
	                       ascii_name );

	/* See if we can handle this application type */
	if ( g_ascii_strncasecmp(ascii_name, poc1_app_name_str,4 ) == 0 )
	{
		/* PoC1 Application */
		guint8 t2timer_code, participants_code;
		proto_item *item;
		item = proto_tree_add_uint( tree, hf_rtcp_app_poc1_subtype, tvb, offset - 8, 1, rtcp_subtype );
		PROTO_ITEM_SET_GENERATED(item);
		col_add_fstr(pinfo->cinfo, COL_INFO,"(%s) %s",ascii_name,
		             val_to_str(rtcp_subtype,rtcp_app_poc1_floor_cnt_type_vals,"unknown (%u)") );
		offset += 4;
		packet_len -= 4;
		app_length = app_length -8;
		if ( packet_len == 0 )
			return offset; /* No more data */
		/* Applications specific data */
		if ( padding ) {
			/* If there's padding present, we have to remove that from the data part
			* The last octet of the packet contains the length of the padding
			*/
			packet_len -= tvb_get_guint8( tvb, offset + packet_len - 1 );
		}
		/* Create a subtree for the PoC1 Application items; we don't yet know
		   the length */
		items_start_offset = offset;

		/* Top-level poc tree */
		PoC1_item = proto_tree_add_item(tree, hf_rtcp_app_poc1, tvb, offset, packet_len, FALSE);
		PoC1_tree = proto_item_add_subtree( PoC1_item, ett_PoC1 );

		/* Dissect it according to its subtype */
		switch ( rtcp_subtype ) {

			case TBCP_BURST_REQUEST:
				{
				guint8 code;
				guint16 priority;

				/* Both items here are optional */
				if (tvb_reported_length_remaining( tvb, offset) == 0)
				{
					return offset;
				}

				/* Look for a code in the first byte */
				code = tvb_get_guint8(tvb, offset);
				offset += 1;
				packet_len -=1;

				/* Priority (optional) */
				if (code == 102)
				{
					item_len = tvb_get_guint8(tvb, offset);
					offset += 1;
					packet_len -= 1;
					if (item_len != 2) /* SHALL be 2 */
						return offset;

					priority = tvb_get_ntohs(tvb, offset);
					proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_priority, tvb, offset, 2, FALSE );
					offset += 2;
					packet_len -= 2;

					col_append_fstr(pinfo->cinfo, COL_INFO,
					               " \"%s\"",
					               val_to_str(priority,
					                          rtcp_app_poc1_qsresp_priority_vals,
					                          "Unknown"));

					/* Look for (optional) next code */
					if (tvb_reported_length_remaining( tvb, offset) == 0)
					{
						return offset;
					}
					code = tvb_get_guint8(tvb, offset);
					offset += 1;
					packet_len -=1;

				}

				/* Request timestamp (optional) */
				if (code == 103)
				{
					const gchar *buff;

					item_len = tvb_get_guint8(tvb, offset);
					offset += 1;
					packet_len -= 1;
					if (item_len != 8) /* SHALL be 8 */
						return offset;

					proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_request_ts,
					                    tvb, offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
					buff = tvb_ntp_fmt_ts(tvb, offset);

					offset += 8;
					packet_len -=8;

					col_append_fstr(pinfo->cinfo, COL_INFO, " ts=\"%s\"", buff);
				}
				}
				break;

			case TBCP_BURST_GRANTED:
				{
				proto_item *ti;
				guint16 stop_talking_time;
				guint16 participants;

				/* Stop talking timer (now mandatory) */
				t2timer_code = tvb_get_guint8(tvb, offset);
				offset += 1;
				packet_len -=1;
				if (t2timer_code != 101) /* SHALL be 101 */
					return offset;

				item_len = tvb_get_guint8(tvb, offset);
				offset += 1;
				packet_len -= 1;
				if (item_len != 2) /* SHALL be 2 */
					return offset;

				stop_talking_time = tvb_get_ntohs(tvb, offset);
				ti = proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_stt, tvb, offset, 2, FALSE );

				/* Append text with meanings of value */
				switch (stop_talking_time)
				{
					case 0:
						proto_item_append_text(ti, " unknown");
						break;
					case 65535:
						proto_item_append_text(ti, " infinity");
						break;
					default:
						proto_item_append_text(ti, " seconds");
						break;
				}
				offset += item_len;
				packet_len -= item_len;

				col_append_fstr(pinfo->cinfo, COL_INFO, " stop-talking-time=%u",
				                stop_talking_time);

				/* Participants (optional) */
				if (tvb_reported_length_remaining( tvb, offset) == 0)
				{
					return offset;
				}
				participants_code = tvb_get_guint8(tvb, offset);
				offset += 1;
				packet_len -=1;
				if (participants_code != 100) /* SHALL be 100 */
					return offset;

				item_len = tvb_get_guint8(tvb, offset);
				offset += 1;
				packet_len -= 1;
				if (item_len != 2) /* SHALL be 2 */
					return offset;

				participants = tvb_get_ntohs(tvb, offset);
				ti = proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_partic, tvb, offset, 2, FALSE );

				/* Append text with meanings of extreme values */
				switch (participants)
				{
					case 0:
						proto_item_append_text(ti, " (not known)");
						break;
					case 65535:
						proto_item_append_text(ti, " (or more)");
						break;
					default:
						break;
				}
				offset += item_len;
				packet_len -= item_len;

				col_append_fstr(pinfo->cinfo, COL_INFO, " participants=%u",
				                participants);
				}
				break;

			case TBCP_BURST_TAKEN_EXPECT_NO_REPLY:
			case TBCP_BURST_TAKEN_EXPECT_REPLY:
				{
				guint16 participants;
				proto_item *ti;

				/* SSRC of PoC client */
				proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_ssrc_granted, tvb, offset, 4, FALSE );
				offset += 4;
				packet_len -= 4;

				/* SDES type (must be CNAME) */
				sdes_type = tvb_get_guint8( tvb, offset );
				proto_tree_add_item( PoC1_tree, hf_rtcp_sdes_type, tvb, offset, 1, FALSE );
				offset++;
				packet_len--;
				if (sdes_type != RTCP_SDES_CNAME)
				{
					return offset;
				}

				/* SIP URI */
				item_len = tvb_get_guint8( tvb, offset );
				/* Item len of 1 because its an FT_UINT_STRING... */
				proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_sip_uri,
				                    tvb, offset, 1, FALSE );
				offset++;

				col_append_fstr(pinfo->cinfo, COL_INFO, " CNAME=\"%s\"",
				                tvb_get_ephemeral_string(tvb, offset, item_len));

				offset += item_len;
				packet_len = packet_len - item_len - 1;

				/* In the application dependent data, the TBCP Talk Burst Taken message SHALL carry
				 * a SSRC field and SDES items, CNAME and MAY carry SDES item NAME to identify the
				 * PoC Client that has been granted permission to send a Talk Burst.
				 *
				 * The SDES item NAME SHALL be included if it is known by the PoC Server.
				 * Therefore the length of the packet will vary depending on number of SDES items
				 * and the size of the SDES items.
				 */
				if ( packet_len == 0 )
					return offset;

				/* SDES type (must be NAME if present) */
				sdes_type = tvb_get_guint8( tvb, offset );
				if (sdes_type == RTCP_SDES_NAME) {
					proto_tree_add_item( PoC1_tree, hf_rtcp_sdes_type, tvb, offset, 1, FALSE );
					offset++;
					packet_len--;

					/* Display name */
					item_len = tvb_get_guint8( tvb, offset );
					/* Item len of 1 because its an FT_UINT_STRING... */
					proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_disp_name,
					                    tvb, offset, 1, FALSE);
					offset++;

					col_append_fstr(pinfo->cinfo, COL_INFO, " DISPLAY-NAME=\"%s\"",
					                tvb_get_ephemeral_string(tvb, offset, item_len));

					offset += item_len;
					packet_len = packet_len - item_len - 1;

					if (packet_len == 0) {
						return offset;
					}

					/* Move onto next 4-byte boundary */
					if (offset % 4) {
						int padding2 = (4-(offset%4));
						offset += padding2;
						packet_len -= padding2;
					}
				}

				/* Participants (optional) */
				if (tvb_reported_length_remaining( tvb, offset) == 0) {
					return offset;
				}
				participants_code = tvb_get_guint8(tvb, offset);
				offset += 1;
				packet_len -=1;
				if (participants_code != 100) { /* SHALL be 100 */
					return offset;
				}
				item_len = tvb_get_guint8(tvb, offset);
				offset += 1;
				packet_len -= 1;
				if (item_len != 2) { /* SHALL be 2 */
					return offset;
				}

				participants = tvb_get_ntohs(tvb, offset);
				ti = proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_partic, tvb, offset, 2, FALSE );

				/* Append text with meanings of extreme values */
				switch (participants) {
					case 0:
						proto_item_append_text(ti, " (not known)");
						break;
					case 65535:
						proto_item_append_text(ti, " (or more)");
						break;
					default:
						break;
				}

				col_append_fstr(pinfo->cinfo, COL_INFO, " Participants=%u",
				                participants);
				offset += item_len;
				packet_len -= item_len;
				}
				break;

			case TBCP_BURST_DENY:
				{
				guint8 reason_code;

				/* Reason code */
				reason_code = tvb_get_guint8(tvb, offset);
				proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_reason_code1, tvb, offset, 1, FALSE );
				offset++;
				packet_len--;

				col_append_fstr(pinfo->cinfo, COL_INFO, " reason-code=\"%s\"",
				                val_to_str(reason_code,
				                           rtcp_app_poc1_reason_code1_vals,
				                           "Unknown"));

				/* Reason phrase */
				item_len = tvb_get_guint8( tvb, offset );
				if ( item_len != 0 )
					proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_reason1_phrase, tvb, offset, 1, FALSE );

				offset += (item_len+1);
				packet_len -= (item_len+1);
				}
				break;

			case TBCP_BURST_RELEASE:
				{
				guint16 last_seq_no;
				guint16 ignore_last_seq_no;

				/* Sequence number of last RTP packet in burst */
				proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_last_pkt_seq_no, tvb, offset, 2, FALSE );
				last_seq_no = tvb_get_ntohs(tvb, offset);

				/* Bit 16 is ignore flag */
				offset += 2;
				proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_ignore_seq_no, tvb, offset, 2, FALSE );
				ignore_last_seq_no = (tvb_get_ntohs(tvb, offset) & 0x8000);

				col_append_fstr(pinfo->cinfo, COL_INFO, " last_rtp_seq_no=%u",
				                last_seq_no);

				/* 15 bits of padding follows */

				offset += 2;
				packet_len-=4;
				}
				break;

			case TBCP_BURST_IDLE:
				break;

			case TBCP_BURST_REVOKE:
				{
					/* Reason code */
					guint16 reason_code = tvb_get_ntohs(tvb, offset);
					proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_reason_code2, tvb, offset, 2, FALSE );

					/* The meaning of this field depends upon the reason code... */
					switch (reason_code)
					{
						case 1: /* Only one user */
							/* No additional info */
							break;
						case 2: /* Talk burst too long */
							/* Additional info is 16 bits with time (in seconds) client can request */
							proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_new_time_request, tvb, offset + 2, 2, FALSE );
							break;
						case 3: /* No permission */
							/* No additional info */
							break;
						case 4: /* Pre-empted */
							/* No additional info */
							break;
					}

					col_append_fstr(pinfo->cinfo, COL_INFO, " reason-code=\"%s\"",
					                val_to_str(reason_code,
					                           rtcp_app_poc1_reason_code2_vals,
					                           "Unknown"));
					offset += 4;
					packet_len-=4;
				}
				break;

			case TBCP_BURST_ACKNOWLEDGMENT:
				{
				guint8 subtype;

				/* Code of message being acknowledged */
				subtype = (tvb_get_guint8(tvb, offset) & 0xf8) >> 3;
				proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_ack_subtype, tvb, offset, 1, FALSE );

				col_append_fstr(pinfo->cinfo, COL_INFO, " (for %s)",
				                val_to_str(subtype,
				                           rtcp_app_poc1_floor_cnt_type_vals,
				                           "Unknown"));

				/* Reason code only seen if subtype was Connect */
				if (subtype == TBCP_CONNECT)
				{
					proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_ack_reason_code, tvb, offset, 2, FALSE );
				}

				/* 16 bits of padding follow */
				offset += 4;
				packet_len -= 4;
				}
				break;

			case TBCP_QUEUE_STATUS_REQUEST:
				break;

			case TBCP_QUEUE_STATUS_RESPONSE:
				{
				guint16 position;
				proto_item *ti;

				/* Priority */
				proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_qsresp_priority, tvb, offset, 1, FALSE );

				/* Queue position. 65535 indicates 'position not available' */
				position = tvb_get_ntohs(tvb, offset+1);
				ti = proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_qsresp_position, tvb, offset+1, 2, FALSE );
				if (position == 0)
				{
					proto_item_append_text(ti, " (client is un-queued)");
				}
				if (position == 65535)
				{
					proto_item_append_text(ti, " (position not available)");
				}

				col_append_fstr(pinfo->cinfo, COL_INFO, " position=%u", position);

				/* 1 bytes of padding  follows */

				offset += 4;
				packet_len -= 4;
				}
			    break;

			case TBCP_DISCONNECT:
				break;

			case TBCP_CONNECT:
				{
				proto_item *content = proto_tree_add_text(PoC1_tree, tvb, offset, 2, "SDES item content");
				gboolean contents[5];
				unsigned int i;
				guint8 items_set = 0;

				proto_tree *content_tree = proto_item_add_subtree(content, ett_poc1_conn_contents);
				guint16 items_field = tvb_get_ntohs(tvb, offset );

				/* Dissect each defined bit flag in the SDES item content */
				for ( i = 0; i < 5; i++)
				{
					proto_tree_add_item( content_tree, hf_rtcp_app_poc1_conn_content[i], tvb, offset, 2, FALSE );
					contents[i] = items_field & (1 << (15-i));
					if (contents[i]) ++items_set;
				}

				/* Show how many flags were set */
				proto_item_append_text(content, " (%u items)", items_set);

				/* Session type */
				proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_conn_session_type, tvb, offset + 2, 1, FALSE );

				/* Additional indications */
				proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_conn_add_ind_mao, tvb, offset + 3, 1, FALSE );

				offset += 4;
				packet_len -= 4;

				/* One SDES item for every set flag in contents array */
				for ( i = 0; i < array_length(contents); ++i ) {
					if ( contents[i] ) {
						guint sdes_type2, sdes_len2;
						/* (sdes_type2 not currently used...).  Could complain if type
						   doesn't match expected for item... */
						sdes_type2 = tvb_get_guint8( tvb, offset++ );
						sdes_len2  = tvb_get_guint8( tvb, offset );

						/* Add SDES field indicated as present */
						proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_conn_sdes_items[i], tvb, offset, 1, FALSE );

						/* Move past field */
						offset += sdes_len2 + 1;
						packet_len -= (sdes_len2 + 2);
					}
				}
			    break;
			}

			default:
				break;
		}
		offset += packet_len;
		return offset;
	}
	else if ( g_ascii_strncasecmp(ascii_name, mux_app_name_str,4 ) == 0 )
	{
		/* 3GPP Nb protocol extension (3GPP 29.414) for RTP Multiplexing */
		col_append_fstr(pinfo->cinfo, COL_INFO,"( %s ) subtype=%u",ascii_name, rtcp_subtype);
		offset += 4;
		packet_len -= 4;
		/* Applications specific data */
		if ( padding ) {
			/* If there's padding present, we have to remove that from the data part
			* The last octet of the packet contains the length of the padding
			*/
			packet_len -= tvb_get_guint8( tvb, offset + packet_len - 1 );
		}
		if (packet_len == 4)
		{
			guint16 local_port = 0;

			proto_item* mux_item = proto_tree_add_item(tree, hf_rtcp_app_mux, tvb, offset, packet_len, FALSE);
			proto_tree* mux_tree = proto_item_add_subtree( mux_item, ett_mux );
			proto_tree_add_item( mux_tree, hf_rtcp_app_mux_mux, tvb, offset, 1, FALSE );
			proto_tree_add_item( mux_tree, hf_rtcp_app_mux_cp, tvb, offset, 1, FALSE );
			proto_tree_add_item( mux_tree, hf_rtcp_app_mux_selection, tvb, offset, 1, FALSE );
			local_port = tvb_get_ntohs( tvb, offset+2 );
			proto_tree_add_uint( mux_tree, hf_rtcp_app_mux_localmuxport, tvb, offset+2, 2, local_port*2 );
		}
		else
		{
			/* fall back to just showing the data if it's the wrong length */
			proto_tree_add_item( tree, hf_rtcp_app_data, tvb, offset, packet_len, FALSE );
		}
		offset += packet_len;

		return offset;
	}
	else
	{
		tvbuff_t *next_tvb;		/* tvb to pass to subdissector */
		/* tvb == Pass the entire APP payload so the subdissector can have access to the
		 * entire data set
		 */
		next_tvb = tvb_new_subset(tvb, offset-8, app_length+4, app_length+4);
		/* look for registered sub-dissectors */
		if (dissector_try_string(rtcp_dissector_table, ascii_name, next_tvb, pinfo, tree)) {
			/* found subdissector - return tvb_length */
			offset += 4;
			packet_len -= 4;
			if ( padding ) {
				/* If there's padding present, we have to remove that from the data part
				* The last octet of the packet contains the length of the padding
				*/
				packet_len -= tvb_get_guint8( tvb, offset + packet_len - 1 );
			}
			offset += packet_len;
			return offset;
		}
		else
		{
			/* Unhandled application type, just show app name and raw data */
			col_append_fstr(pinfo->cinfo, COL_INFO,"( %s ) subtype=%u",ascii_name, rtcp_subtype);
			offset += 4;
			packet_len -= 4;
			/* Applications specific data */
			if ( padding ) {
				/* If there's padding present, we have to remove that from the data part
				* The last octet of the packet contains the length of the padding
				*/
				packet_len -= tvb_get_guint8( tvb, offset + packet_len - 1 );
			}
			proto_tree_add_item( tree, hf_rtcp_app_data, tvb, offset, packet_len, FALSE );
			offset += packet_len;

			return offset;
		}
	}

}