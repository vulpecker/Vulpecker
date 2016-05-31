static void
dissect_oampdu_event_notification(tvbuff_t *tvb, proto_tree *tree)
{
    guint8    raw_octet;
    guint16   raw_word;
    guint32   dword;
    guint64   big;

    guint8    event_type;
    guint32   offset;
    guint16   bytes;

    proto_tree *event_tree;
    proto_item *event_item;

    offset = OAMPDU_HEADER_SIZE;

    /* Display the sequence number before displaying the TLVs */
    raw_word = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(tree, hf_oampdu_event_sequence,
            tvb, offset, 2, raw_word);

    offset += OAMPDU_EVENT_SEQUENCE_SZ;

    while (1)
    {
        bytes = tvb_length_remaining(tvb, offset);
        if (bytes < 1) break;

        event_type = tvb_get_guint8(tvb, offset);

        if (event_type == 0) break;

        event_item = proto_tree_add_uint(tree, hf_oampdu_event_type,
                            tvb, offset, 1, event_type);

        offset += OAMPDU_EVENT_TYPE_SZ;

        switch (event_type)
        {
            case OAMPDU_EVENT_TYPE_END:
                break;
            case OAMPDU_EVENT_TYPE_ESPE:
            {
                event_tree = proto_item_add_subtree(event_item,
                                    ett_oampdu_event_espe);

                raw_octet = tvb_get_guint8(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_length,
                        tvb, offset, 1, raw_octet);

                offset += OAMPDU_EVENT_LENGTH_SZ;

                raw_word = tvb_get_ntohs(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_timeStamp,
                        tvb, offset, 2, raw_word);

                offset += OAMPDU_EVENT_TIMESTAMP_SZ;

                big = tvb_get_ntoh64(tvb, offset);
                proto_tree_add_uint64(event_tree, hf_oampdu_event_espeWindow,
                        tvb, offset, 8, big);

                offset += OAMPDU_ESPE_WINDOW_SZ;

                big = tvb_get_ntoh64(tvb, offset);
                proto_tree_add_uint64(event_tree, hf_oampdu_event_espeThreshold,
                        tvb, offset, 8, big);

                offset += OAMPDU_ESPE_THRESHOLD_SZ;

                big = tvb_get_ntoh64(tvb, offset);
                proto_tree_add_uint64(event_tree, hf_oampdu_event_espeErrors,
                        tvb, offset, 8, big);

                offset += OAMPDU_ESPE_ERRORS_SZ;

                big = tvb_get_ntoh64(tvb, offset);
                proto_tree_add_uint64(event_tree, hf_oampdu_event_espeTotalErrors,
                        tvb, offset, 8, big);

                offset += OAMPDU_ESPE_ERR_TOTAL_SZ;

                dword = tvb_get_ntohl(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_espeTotalEvents,
                        tvb, offset, 4, dword);

                offset += OAMPDU_ESPE_TOTAL_SZ;
                break;
            }
            case OAMPDU_EVENT_TYPE_EFE:
            {
                event_tree = proto_item_add_subtree(event_item,
                                    ett_oampdu_event_efe);

                raw_octet = tvb_get_guint8(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_length,
                        tvb, offset, 1, raw_octet);

                offset += OAMPDU_EVENT_LENGTH_SZ;

                raw_word = tvb_get_ntohs(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_timeStamp,
                        tvb, offset, 2, raw_word);

                offset += OAMPDU_EVENT_TIMESTAMP_SZ;

                raw_word = tvb_get_ntohs(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_efeWindow,
                        tvb, offset, 2, raw_word);

                offset += OAMPDU_EFE_WINDOW_SZ;

                dword = tvb_get_ntohl(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_efeThreshold,
                        tvb, offset, 4, dword);

                offset += OAMPDU_EFE_THRESHOLD_SZ;

                dword = tvb_get_ntohl(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_efeErrors,
                        tvb, offset, 4, dword);

                offset += OAMPDU_EFE_ERRORS_SZ;

                big = tvb_get_ntoh64(tvb, offset);
                proto_tree_add_uint64(event_tree, hf_oampdu_event_efeTotalErrors,
                        tvb, offset, 8, big);

                offset += OAMPDU_EFE_ERR_TOTAL_SZ;

                dword = tvb_get_ntohl(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_efeTotalEvents,
                        tvb, offset, 4, dword);

                offset += OAMPDU_EFE_TOTAL_SZ;

                break;
            }
            case OAMPDU_EVENT_TYPE_EFPE:
            {
                event_tree = proto_item_add_subtree(event_item,
                                    ett_oampdu_event_efpe);

                raw_octet = tvb_get_guint8(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_length,
                        tvb, offset, 1, raw_octet);

                offset += OAMPDU_EVENT_LENGTH_SZ;

                raw_word = tvb_get_ntohs(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_timeStamp,
                        tvb, offset, 2, raw_word);

                offset += OAMPDU_EVENT_TIMESTAMP_SZ;

                raw_word = tvb_get_ntohl(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_efpeWindow,
                        tvb, offset, 4, raw_word);

                offset += OAMPDU_EFPE_WINDOW_SZ;

                dword = tvb_get_ntohl(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_efpeThreshold,
                        tvb, offset, 4, dword);

                offset += OAMPDU_EFPE_THRESHOLD_SZ;

                dword = tvb_get_ntohl(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_efpeErrors,
                        tvb, offset, 4, dword);

                offset += OAMPDU_EFPE_ERRORS_SZ;

                big = tvb_get_ntoh64(tvb, offset);
                proto_tree_add_uint64(event_tree, hf_oampdu_event_efpeTotalErrors,
                        tvb, offset, 8, big);

                offset += OAMPDU_EFPE_ERR_TOTAL_SZ;

                dword = tvb_get_ntohl(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_efpeTotalEvents,
                        tvb, offset, 4, dword);

                offset += OAMPDU_EFPE_TOTAL_SZ;

                break;
            }
            case OAMPDU_EVENT_TYPE_EFSSE:
            {
                event_tree = proto_item_add_subtree(event_item,
                                    ett_oampdu_event_efsse);

                raw_octet = tvb_get_guint8(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_length,
                        tvb, offset, 1, raw_octet);

                offset += OAMPDU_EVENT_LENGTH_SZ;

                raw_word = tvb_get_ntohs(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_timeStamp,
                        tvb, offset, 2, raw_word);

                offset += OAMPDU_EVENT_TIMESTAMP_SZ;

                raw_word = tvb_get_ntohs(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_efsseWindow,
                        tvb, offset, 2, raw_word);

                offset += OAMPDU_EFSSE_WINDOW_SZ;

                dword = tvb_get_ntohs(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_efsseThreshold,
                        tvb, offset, 2, dword);

                offset += OAMPDU_EFSSE_THRESHOLD_SZ;

                dword = tvb_get_ntohs(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_efsseErrors,
                        tvb, offset, 2, dword);

                offset += OAMPDU_EFSSE_ERRORS_SZ;

                dword = tvb_get_ntohl(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_efsseTotalErrors,
                        tvb, offset, 4, dword);

                offset += OAMPDU_EFSSE_ERR_TOTAL_SZ;

                dword = tvb_get_ntohl(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_efsseTotalEvents,
                        tvb, offset, 4, dword);

                offset += OAMPDU_EFSSE_TOTAL_SZ;

                break;
            }
            case OAMPDU_EVENT_TYPE_OSE:
            {
                event_tree = proto_item_add_subtree(event_item,
                                    ett_oampdu_event_ose);

                raw_octet = tvb_get_guint8(tvb, offset);
                proto_tree_add_uint(event_tree, hf_oampdu_event_length,
                        tvb, offset, 1, raw_octet);

                offset += OAMPDU_EVENT_LENGTH_SZ;

                offset += (raw_word-2);
                break;
            }
            default:
              break;
        }
    }
}