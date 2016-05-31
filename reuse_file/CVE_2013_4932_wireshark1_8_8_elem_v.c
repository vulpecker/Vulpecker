guint16 elem_v(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, gint pdu_type, int idx, guint32 offset, const gchar *name_add)
{
    guint16             consumed;
    guint32             curr_offset;
    proto_tree         *subtree;
    proto_item         *item;
    const value_string *elem_names;
    gint               *elem_ett;
    guint16 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string, int string_len);

    curr_offset = offset;
    consumed = 0;

    SET_ELEM_VARS(pdu_type, elem_names, elem_ett, elem_funcs);

    if (elem_funcs[idx] == NULL)
    {
        /* BAD THING, CANNOT DETERMINE LENGTH */

        proto_tree_add_text(tree,
            tvb, curr_offset, 1,
            "No element dissector, rest of dissection may be incorrect");

        consumed = 1;
    }
    else
    {
        gchar *a_add_string;

        item =
            proto_tree_add_text(tree,
                tvb, curr_offset, 0,
                "%s%s",
                elem_names[idx].strptr,
                (name_add == NULL) || (name_add[0] == '\0') ? "" : name_add);

        subtree = proto_item_add_subtree(item, elem_ett[idx]);

        a_add_string= (gchar*)ep_alloc(1024);
        a_add_string[0] = '\0';
        consumed = (*elem_funcs[idx])(tvb, subtree, pinfo, curr_offset, -1, a_add_string, 1024);
        if (a_add_string[0] != '\0')
        {
            proto_item_append_text(item, "%s", a_add_string);
        }
        proto_item_set_len(item, consumed);
    }

    return(consumed);
}