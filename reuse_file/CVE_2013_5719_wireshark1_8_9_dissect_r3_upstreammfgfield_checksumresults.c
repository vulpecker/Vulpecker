
static void dissect_r3_upstreammfgfield_checksumresults (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo, proto_tree *tree)
{
  proto_item *cksum_item = NULL;
  proto_tree *cksum_tree= NULL;
  guint32 l = tvb_length_remaining (tvb, start_offset);
  guint32 error = FALSE;
  guint32 i;

  if (l % 3 != 0)
    expert_add_info_format (pinfo, tree, PI_UNDECODED, PI_WARN, "Checksum results data length not modulo 3 == 0");
  else
  {
    for (i = start_offset; i < l; i += tvb_get_guint8 (tvb, start_offset + i))
      error |= tvb_get_guint8 (tvb, start_offset + i + 2);

    cksum_item = proto_tree_add_text (tree, tvb, start_offset, l, "Checksum Results (%s)", error ? "Error" : "No Errors");
    cksum_tree = proto_item_add_subtree (cksum_item, ett_r3checksumresults);

    for (i = 0; i < l; i += tvb_get_guint8 (tvb, start_offset + i))
    {
      proto_item *res_item = proto_tree_add_item (cksum_tree, hf_r3_checksumresults, tvb, start_offset + i, tvb_get_guint8 (tvb, start_offset + i), ENC_NA);
      proto_tree *res_tree = proto_item_add_subtree (res_item, ett_r3checksumresultsfield);
      const gchar *fn;

      fn = val_to_str_ext_const (tvb_get_guint8 (tvb, start_offset + i + 1), &r3_checksumresultnames_ext, "[Unknown Field Name]");

      proto_item_append_text (res_item, " %s (%s)", fn, tvb_get_guint8 (tvb, start_offset + i + 2) ? "Error" : "No Error");

      proto_tree_add_item (res_tree, hf_r3_checksumresults_length, tvb, start_offset + i + 0, 1, ENC_LITTLE_ENDIAN);
      proto_tree_add_item (res_tree, hf_r3_checksumresults_field, tvb, start_offset + i + 1, 1, ENC_LITTLE_ENDIAN);
      proto_tree_add_item (res_tree, hf_r3_checksumresults_state, tvb, start_offset + i + 2, 1, ENC_LITTLE_ENDIAN);
    }
  }
}