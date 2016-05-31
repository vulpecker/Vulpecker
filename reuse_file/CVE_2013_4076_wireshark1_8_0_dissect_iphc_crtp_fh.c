static void
dissect_iphc_crtp_fh(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *fh_tree = NULL, *info_tree = NULL;
    proto_item *ti = NULL;
    guint     ip_hdr_len, flags;
    guint     length;
    guint     hdr_len;
    tvbuff_t *next_tvb;
    int       offset_seq;
    int       offset_cid;
    guint8    ip_version;
    guint8    next_protocol;
    guchar   *ip_packet;

    length = tvb_reported_length(tvb);

    col_set_str(pinfo->cinfo,COL_PROTOCOL, "CRTP");
    col_set_str(pinfo->cinfo, COL_INFO, "Full Header");

    /* only dissect IPv4 and UDP */
    ip_version = tvb_get_guint8(tvb, 0) >> 4;
    flags = (tvb_get_guint8(tvb, 2) & IPHC_CRTP_FH_FLAG_MASK) >>
        IPHC_CRTP_FH_FLAG_POS;
    next_protocol = tvb_get_guint8(tvb, 9);

    if (tree) {
        ti = proto_tree_add_protocol_format(tree, proto_iphc_crtp, tvb, 0, -1,
            "%s", val_to_str_ext_const(PPP_RTP_FH, &ppp_vals_ext, "Unknown"));
        fh_tree = proto_item_add_subtree(ti, ett_iphc_crtp);

        proto_tree_add_item(fh_tree, hf_iphc_crtp_fh_flags, tvb, 2, 1,
            ENC_BIG_ENDIAN);
        proto_tree_add_item(fh_tree, hf_iphc_crtp_gen, tvb, 2, 1,
            ENC_BIG_ENDIAN);

    }

    /* calculate length of IP header, assume IPv4 */
    ip_hdr_len = (tvb_get_guint8(tvb, 0) & 0x0f) * 4;

    if (tree) {
        /* calculate total hdr length, assume UDP */
        hdr_len = ip_hdr_len + 8;

        if (ip_version != 4) {
            proto_tree_add_text(fh_tree, tvb, 3, -1,
                "IP version is %u: the only supported version is 4",
                ip_version);
            return;
        }

        if (next_protocol != IP_PROTO_UDP) {
            proto_tree_add_text(fh_tree, tvb, 3, -1,
                "Next protocol is %s (%u): the only supported protocol is UDP",
                ipprotostr(next_protocol), next_protocol);
            return;
        }

        /* context id and sequence fields */
        switch (flags) {
        case IPHC_CRTP_FH_CID8:
            offset_cid = 3;
            offset_seq = ip_hdr_len + 5;
            proto_tree_add_item(fh_tree, hf_iphc_crtp_cid8, tvb, offset_cid, 1,
                ENC_BIG_ENDIAN);
            proto_tree_add_item(fh_tree, hf_iphc_crtp_seq, tvb, offset_seq, 1,
                ENC_BIG_ENDIAN);
            break;

        case IPHC_CRTP_FH_CID16:
            offset_seq = 3;
            offset_cid = ip_hdr_len + 4;
            proto_tree_add_item(fh_tree, hf_iphc_crtp_seq, tvb, offset_seq, 1,
                ENC_BIG_ENDIAN);
            proto_tree_add_item(fh_tree, hf_iphc_crtp_cid16, tvb, offset_cid,
                2, ENC_BIG_ENDIAN);
            break;

        default:
            /* TODO? */
            break;
        }

        /* information field */
        tvb_ensure_bytes_exist (tvb, 0, hdr_len);
        ti = proto_tree_add_text(fh_tree, tvb, 0,length,"Information Field");
        info_tree = proto_item_add_subtree(ti,ett_iphc_crtp_info);
    }

    /* allocate a copy of the IP packet */
    ip_packet = tvb_memdup(tvb, 0, length);

    /* restore the proper values to the IP and UDP length fields */
    ip_packet[2] = length >> 8;
    ip_packet[3] = length;

    ip_packet[ip_hdr_len + 4] = (length - ip_hdr_len) >> 8;
    ip_packet[ip_hdr_len + 5] = (length - ip_hdr_len);

    next_tvb = tvb_new_child_real_data(tvb, ip_packet, length, length);
    add_new_data_source(pinfo, next_tvb, "Decompressed Data");
    tvb_set_free_cb(next_tvb, g_free);

    if (!dissector_try_uint(ppp_subdissector_table, PPP_IP, next_tvb, pinfo,
        info_tree)) {
        call_dissector_only(data_handle, next_tvb, pinfo, info_tree);
    }
}