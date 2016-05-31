
static int
dissect_version_5_and_6_primary_header(packet_info *pinfo,
                                        proto_tree *primary_tree, tvbuff_t *tvb)
{
    guint64 bundle_processing_control_flags;
    guint8 cosflags;
    const guint8 *dict_ptr;
    int bundle_header_length;
    int bundle_header_dict_length;
    int offset;         /*Total offset into frame (frame_offset + convergence layer size)*/
    int sdnv_length;
    int dest_scheme_offset, dest_ssp_offset, source_scheme_offset, source_ssp_offset;
    int report_scheme_offset, report_ssp_offset, cust_scheme_offset, cust_ssp_offset;
    int dest_scheme_pos, source_scheme_pos, report_scheme_pos, cust_scheme_pos;
    int dest_scheme_len, source_scheme_len, report_scheme_len, cust_scheme_len;
    int dest_ssp_len, source_ssp_len, report_ssp_len, cust_ssp_len;
    int fragment_offset, total_adu_length;
    int timestamp;
    time_t time_since_2000;
    int timestamp_sequence;
    int lifetime;
    char *time_string;
    const gchar *src_node;
    const gchar *dst_node;
    guint8 srrflags;
    proto_item *srr_flag_item;
    proto_tree *srr_flag_tree;
    proto_item *gen_flag_item;
    proto_tree *gen_flag_tree;

    proto_item *proc_flag_item;
    proto_tree *proc_flag_tree;
    proto_item *cos_flag_item;
    proto_tree *cos_flag_tree;
    proto_item *dict_item;
    proto_tree *dict_tree;


    offset = 1;         /* Version Number already displayed */
    bundle_processing_control_flags = evaluate_sdnv_64(tvb, offset, &sdnv_length);

    /* Primary Header Processing Flags */
    pri_hdr_procflags = (guint8) (bundle_processing_control_flags & 0x7f);

    if (sdnv_length < 1) {
        expert_add_info_format(pinfo, primary_tree, PI_UNDECODED, PI_WARN,
                               "Wrong bundle control flag length: %d", sdnv_length);
        return 0;
    }
    proc_flag_item = proto_tree_add_item(primary_tree, hf_bundle_control_flags, tvb,
                                                offset, sdnv_length, FALSE);
    proc_flag_tree = proto_item_add_subtree(proc_flag_item, ett_proc_flags);

    gen_flag_item = proto_tree_add_text(proc_flag_tree, tvb, offset,
                                        sdnv_length, "General Flags");
    gen_flag_tree = proto_item_add_subtree(gen_flag_item, ett_gen_flags);

    proto_tree_add_boolean(gen_flag_tree, hf_bundle_procflags_fragment,
                                        tvb, offset, sdnv_length, pri_hdr_procflags);
    proto_tree_add_boolean(gen_flag_tree, hf_bundle_procflags_admin,
                                        tvb, offset, sdnv_length, pri_hdr_procflags);
    proto_tree_add_boolean(gen_flag_tree, hf_bundle_procflags_dont_fragment,
                                        tvb, offset, sdnv_length, pri_hdr_procflags);
    proto_tree_add_boolean(gen_flag_tree, hf_bundle_procflags_cust_xfer_req,
                                        tvb, offset, sdnv_length, pri_hdr_procflags);
    proto_tree_add_boolean(gen_flag_tree, hf_bundle_procflags_dest_singleton,
                                        tvb, offset, sdnv_length, pri_hdr_procflags);
    proto_tree_add_boolean(gen_flag_tree, hf_bundle_procflags_application_ack,
                                        tvb, offset, sdnv_length, pri_hdr_procflags);

    /* Primary Header COS Flags */
    cosflags = (guint8) ((bundle_processing_control_flags >> 7) & 0x7f);
    cos_flag_item = proto_tree_add_text(proc_flag_tree, tvb, offset,
                                        sdnv_length, "Class of Service Flags");
    cos_flag_tree = proto_item_add_subtree(cos_flag_item, ett_cos_flags);
    if((cosflags & BUNDLE_COSFLAGS_PRIORITY_MASK) == BUNDLE_COSFLAGS_PRIORITY_BULK) {
        proto_tree_add_text(cos_flag_tree, tvb, offset,
                                        sdnv_length, "00 -- Priority = Bulk");
    }
    else if((cosflags & BUNDLE_COSFLAGS_PRIORITY_MASK) ==
                                        BUNDLE_COSFLAGS_PRIORITY_NORMAL) {
        proto_tree_add_text(cos_flag_tree, tvb, offset,
                                        sdnv_length, "01 -- Priority = Normal");
    }
    else if((cosflags & BUNDLE_COSFLAGS_PRIORITY_MASK) ==
                                        BUNDLE_COSFLAGS_PRIORITY_EXP) {
        proto_tree_add_text(cos_flag_tree, tvb, offset,
                                        sdnv_length, "10 -- Priority = Expedited");
    }
    else {
        proto_tree_add_text(cos_flag_tree, tvb, offset,
                                        sdnv_length, "11 -- Invalid (Reserved)");
        return 0;
    }

    /* Status Report Request Flags */
    srrflags = (guint8) ((bundle_processing_control_flags >> 14) & 0x7f);
    srr_flag_item = proto_tree_add_text(proc_flag_tree, tvb, offset,
                                        sdnv_length, "Status Report Request Flags");
    srr_flag_tree = proto_item_add_subtree(srr_flag_item, ett_srr_flags);

    proto_tree_add_boolean(srr_flag_tree, hf_bundle_srrflags_report_receipt,
                                                tvb, offset, sdnv_length, srrflags);
    proto_tree_add_boolean(srr_flag_tree, hf_bundle_srrflags_report_cust_accept,
                                                tvb, offset, sdnv_length, srrflags);
    proto_tree_add_boolean(srr_flag_tree, hf_bundle_srrflags_report_forward,
                                                tvb, offset, sdnv_length, srrflags);
    proto_tree_add_boolean(srr_flag_tree, hf_bundle_srrflags_report_delivery,
                                                tvb, offset, sdnv_length, srrflags);
    proto_tree_add_boolean(srr_flag_tree, hf_bundle_srrflags_report_deletion,
                                                tvb, offset, sdnv_length, srrflags);
    offset += sdnv_length;

    /* -- hdr_length -- */
    bundle_header_length = evaluate_sdnv(tvb, offset, &sdnv_length);
    if(bundle_header_length < 0) {
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                            "Bundle Header Length: Error");
        return 0;
    }
    proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                        "Bundle Header Length: %d", bundle_header_length);
    tvb_ensure_bytes_exist(tvb, offset + sdnv_length, bundle_header_length);
    offset += sdnv_length;

    /*
     * Pick up offsets into dictionary (8 of them). Do rough sanity check that SDNV
     * hasn't told us to access way past the Primary Header.
     */

    /* -- dest_scheme -- */
    dest_scheme_offset = evaluate_sdnv(tvb, offset, &sdnv_length);
    dest_scheme_pos = offset;
    dest_scheme_len = sdnv_length;

    if((dest_scheme_offset < 0) || (dest_scheme_offset > bundle_header_length)) {
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                            "Destination Scheme Offset: Error");
        return 0;
    }
    proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                        "Destination Scheme Offset: %d", dest_scheme_offset);
    offset += sdnv_length;

    /* -- dest_ssp -- */
    dest_ssp_offset = evaluate_sdnv(tvb, offset, &sdnv_length);
    dest_ssp_len = sdnv_length;

    if((dest_ssp_offset < 0) || (dest_ssp_offset > bundle_header_length)) {
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                            "Destination SSP Offset: Error");
        return 0;
    }
    proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                        "Destination SSP Offset: %d", dest_ssp_offset);
    offset += sdnv_length;


    /* -- source_scheme -- */
    source_scheme_offset = evaluate_sdnv(tvb, offset, &sdnv_length);
    source_scheme_pos = offset;
    source_scheme_len = sdnv_length;

    if((source_scheme_offset < 0) || (source_scheme_offset > bundle_header_length)) {
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                            "Source Scheme Offset: Error");
        return 0;
    }
    proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                        "Source Scheme Offset: %d", source_scheme_offset);
    offset += sdnv_length;

    /* -- source_ssp -- */
    source_ssp_offset = evaluate_sdnv(tvb, offset, &sdnv_length);
    source_ssp_len = sdnv_length;

    if((source_ssp_offset < 0) || (source_ssp_offset > bundle_header_length)) {
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                            "Source SSP Offset: Error");
        return 0;
    }
    proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                        "Source SSP Offset: %d", source_ssp_offset);
    offset += sdnv_length;


    /* -- report_scheme -- */
    report_scheme_offset = evaluate_sdnv(tvb, offset, &sdnv_length);
    report_scheme_pos = offset;
    report_scheme_len = sdnv_length;

    if((report_scheme_offset < 0) || (report_scheme_offset > bundle_header_length)) {
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                            "Report Scheme Offset: Error");
        return 0;
    }
    proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                        "Report Scheme Offset: %d", report_scheme_offset);
    offset += sdnv_length;

    /* -- report_ssp -- */
    report_ssp_offset = evaluate_sdnv(tvb, offset, &sdnv_length);
    report_ssp_len = sdnv_length;

    if((report_ssp_offset < 0) || (report_ssp_offset > bundle_header_length)) {
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                            "Report SSP Offset: Error");
        return 0;
    }
    proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                        "Report SSP Offset: %d", report_ssp_offset);
    offset += sdnv_length;


    /* -- cust_scheme -- */
    cust_scheme_offset = evaluate_sdnv(tvb, offset, &sdnv_length);
    cust_scheme_pos = offset;
    cust_scheme_len = sdnv_length;

    if((cust_scheme_offset < 0) || (cust_scheme_offset > bundle_header_length)) {
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                            "Custodian Scheme Offset: Error");
        return 0;
    }
    proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                        "Custodian Scheme Offset: %d", cust_scheme_offset);
    offset += sdnv_length;

    /* -- cust_ssp -- */
    cust_ssp_offset = evaluate_sdnv(tvb, offset, &sdnv_length);
    cust_ssp_len = sdnv_length;

    if((cust_ssp_offset < 0) || (cust_ssp_offset > bundle_header_length)) {
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                            "Custodian SSP Offset: Error");
        return 0;
    }
    proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                        "Custodian SSP Offset: %d", cust_ssp_offset);
    offset += sdnv_length;


    /* -- timestamp -- */
    timestamp = evaluate_sdnv(tvb, offset, &sdnv_length);
    if(timestamp < 0) {
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                            "Timestamp: Error");
        return 0;
    }
    time_since_2000 = (time_t) (timestamp + 946684800);
    time_string = abs_time_secs_to_str(time_since_2000, ABSOLUTE_TIME_LOCAL, TRUE);
    proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                        "Timestamp: 0x%x [%s]", timestamp, time_string);
    offset += sdnv_length;

    /* -- timestamp_sequence -- */
    timestamp_sequence = evaluate_sdnv(tvb, offset, &sdnv_length);
    if(timestamp_sequence < 0) {
        gint64 ts_seq;

        if((ts_seq = evaluate_sdnv_64(tvb, offset, &sdnv_length)) < 0) {
            proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                                "Timestamp Sequence Number: Error");
            return 0;
        }
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                            "Timestamp Sequence Number: 0x%" G_GINT64_MODIFIER "x", ts_seq);
    }
    else {
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                            "Timestamp Sequence Number: %d", timestamp_sequence);
    }
    offset += sdnv_length;

    /* -- lifetime -- */
    lifetime = evaluate_sdnv(tvb, offset, &sdnv_length);
    if(lifetime < 0) {
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                            "Lifetime: Error");
        return 0;
    }
    proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                        "Lifetime: %d", lifetime);
    offset += sdnv_length;

    /* -- dict_length -- */
    bundle_header_dict_length = evaluate_sdnv(tvb, offset, &sdnv_length);
    if(bundle_header_dict_length < 0) {
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                            "Dictionary Length: Error");
        return 0;
    }
    proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                        "Dictionary Length: %d",bundle_header_dict_length);
    offset += sdnv_length;

    /*
     * Pull out stuff from the dictionary
     */

    tvb_ensure_bytes_exist(tvb, offset, bundle_header_dict_length);

    dict_item = proto_tree_add_text(primary_tree, tvb, offset, bundle_header_dict_length,
                                    "Dictionary");
    dict_tree = proto_item_add_subtree(dict_item, ett_dictionary);

    if(bundle_header_dict_length == 0)
    {
        /*
         * Destination info
         */
        proto_tree_add_text(dict_tree, tvb,
                            0, 0,
                            "Destination Scheme: %s",IPN_SCHEME_STR);
        if(dest_scheme_offset == 0 && dest_ssp_offset == 0)
        {
                proto_tree_add_text(dict_tree, tvb,
                                    dest_scheme_pos, dest_scheme_len + dest_ssp_len,
                                    "Destination: Null");
        }
        else
        {
                proto_tree_add_text(dict_tree, tvb,
                                    dest_scheme_pos, dest_scheme_len + dest_ssp_len,
                                    "Destination: %d.%d",dest_scheme_offset,dest_ssp_offset);
        }

        /*
         * Source info
         */
        proto_tree_add_text(dict_tree, tvb,
                            0, 0,
                            "Source Scheme: %s",IPN_SCHEME_STR);
        if(source_scheme_offset == 0 && source_ssp_offset == 0)
        {
                proto_tree_add_text(dict_tree, tvb,
                                    source_scheme_pos, source_scheme_len + source_ssp_len,
                                    "Source: Null");
        }
        else
        {
                proto_tree_add_text(dict_tree, tvb,
                                    source_scheme_pos, source_scheme_len + source_ssp_len,
                                    "Source: %d.%d",source_scheme_offset,source_ssp_offset);
        }

        /*
         * Report to info
         */
        proto_tree_add_text(dict_tree, tvb,
                            0, 0,
                            "Report Scheme: %s",IPN_SCHEME_STR);
        if((report_scheme_offset == 0) && (report_ssp_offset == 0))
        {
                proto_tree_add_text(dict_tree, tvb,
                                    report_scheme_pos, report_scheme_len + report_ssp_len,
                                    "Report: Null");
        }
        else
        {
                proto_tree_add_text(dict_tree, tvb,
                                    report_scheme_pos, report_scheme_len + report_ssp_len,
                                    "Report: %d.%d",report_scheme_offset,report_ssp_offset);
        }

        /*
         * Custodian info
         */
        proto_tree_add_text(dict_tree, tvb, 0,
                                        0, "Custodian Scheme: %s",IPN_SCHEME_STR);
        if(cust_scheme_offset == 0 && cust_ssp_offset == 0)
        {
                proto_tree_add_text(dict_tree, tvb,
                                    cust_scheme_pos, cust_scheme_len + cust_ssp_len,
                                    "Custodian: Null");
        }
        else
        {
                proto_tree_add_text(dict_tree, tvb, cust_scheme_pos,
                                cust_scheme_len + cust_ssp_len,
                                "Custodian: %d.%d",cust_scheme_offset,cust_ssp_offset);
        }

        if(source_scheme_offset == 0 && source_ssp_offset == 0)
        {
                src_node = "Null";
        }
        else
        {
                src_node = ep_strdup_printf("%s:%d.%d",IPN_SCHEME_STR, source_scheme_offset, source_ssp_offset);
        }
        if(dest_scheme_offset == 0 && dest_ssp_offset == 0)
        {
                dst_node = "Null";
        }
        else
        {
                dst_node = ep_strdup_printf("%s:%d.%d",IPN_SCHEME_STR, dest_scheme_offset, dest_ssp_offset);
        }

        col_add_fstr(pinfo->cinfo, COL_INFO, "%s > %s", src_node, dst_node);
    }
    else
    {
        /*
         * Note that the various "offset" pointers may address outside the packet boundaries.
         * proto_tree_add_item() will throw a "bounds exception" for invalid "offset" values.
         */

        /*
         * Destination info
         */

        proto_tree_add_item(dict_tree, hf_bundle_dest_scheme, tvb, offset + dest_scheme_offset, -1, FALSE);
        proto_tree_add_item(dict_tree, hf_bundle_dest_ssp, tvb, offset + dest_ssp_offset, -1, FALSE);

        /*
         * Source info
         */

        proto_tree_add_item(dict_tree, hf_bundle_source_scheme, tvb, offset + source_scheme_offset, -1, FALSE);
        proto_tree_add_item(dict_tree, hf_bundle_source_ssp, tvb, offset + source_ssp_offset, -1, FALSE);

        /*
         * Report to info
         */

        proto_tree_add_item(dict_tree, hf_bundle_report_scheme, tvb, offset + report_scheme_offset, -1, FALSE);
        proto_tree_add_item(dict_tree, hf_bundle_report_ssp, tvb, offset + report_ssp_offset, -1, FALSE);

        /*
         * Custodian info
         */

        proto_tree_add_item(dict_tree, hf_bundle_custodian_scheme, tvb, offset + cust_scheme_offset, -1, FALSE);
        proto_tree_add_item(dict_tree, hf_bundle_custodian_ssp, tvb, offset + cust_ssp_offset, -1, FALSE);

        /*
         * Add Source/Destination to INFO Field
         */

        /* Note: If we get this far, the offsets (and the strings) are at least within the TVB */
        dict_ptr = tvb_get_ptr(tvb, offset, bundle_header_dict_length);
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s:%s > %s:%s",
                     dict_ptr + source_scheme_offset, dict_ptr + source_ssp_offset,
                     dict_ptr + dest_scheme_offset, dict_ptr + dest_ssp_offset);
    }
    offset += bundle_header_dict_length;        /*Skip over dictionary*/

    /*
     * Do this only if Fragment Flag is set
     */

    if(pri_hdr_procflags & BUNDLE_PROCFLAGS_FRAG_MASK) {
        fragment_offset = evaluate_sdnv(tvb, offset, &sdnv_length);
        if(fragment_offset < 0) {
            return 0;
        }
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                                        "Fragment Offset: %d", fragment_offset);
        offset += sdnv_length;

        total_adu_length = evaluate_sdnv(tvb, offset, &sdnv_length);
        if(total_adu_length < 0) {
            return 0;
        }
        proto_tree_add_text(primary_tree, tvb, offset, sdnv_length,
                        "Total Application Data Unit Length: %d", fragment_offset);
        offset += sdnv_length;
    }
    return (offset);
}