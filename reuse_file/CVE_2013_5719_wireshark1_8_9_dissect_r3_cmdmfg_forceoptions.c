
static void dissect_r3_cmdmfg_forceoptions (tvbuff_t *tvb, guint32 start_offset, guint32 length _U_, packet_info *pinfo _U_, proto_tree *tree)
{
  guint i = 0;
  guint l = 0;

  proto_tree_add_item (tree, hf_r3_commandmfglength, tvb, start_offset + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item (tree, hf_r3_commandmfg, tvb, start_offset + 1, 1, ENC_LITTLE_ENDIAN);

  start_offset += 2;
  l = tvb_length_remaining (tvb, start_offset);

  for (i = 0; i < l; i += tvb_get_guint8 (tvb, start_offset + i))
  {
    proto_item *force_item = proto_tree_add_text (tree, tvb, start_offset + i, tvb_get_guint8 (tvb, start_offset + i), "Force Option %s (%u)", val_to_str_ext_const (tvb_get_guint8 (tvb, start_offset + i + 1), &r3_forceitemnames_ext, "[Unknown]"), tvb_get_guint8 (tvb, start_offset + i + 1));
    proto_tree *force_tree = proto_item_add_subtree (force_item, ett_r3forceoptions);

    proto_tree_add_item (force_tree, hf_r3_forceoptions_length, tvb, start_offset + i + 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item (force_tree, hf_r3_forceoptions_item, tvb, start_offset + i + 1, 1, ENC_LITTLE_ENDIAN);

    switch (tvb_get_guint8 (tvb, start_offset + i) - 2)
    {
      case 1  : proto_tree_add_item (force_tree, hf_r3_forceoptions_state_8,  tvb, start_offset + i + 2, 1, ENC_LITTLE_ENDIAN); break;
      case 2  : proto_tree_add_item (force_tree, hf_r3_forceoptions_state_16, tvb, start_offset + i + 2, 2, ENC_LITTLE_ENDIAN); break;
      case 3  : proto_tree_add_item (force_tree, hf_r3_forceoptions_state_24, tvb, start_offset + i + 2, 3, ENC_LITTLE_ENDIAN); break;
      case 4  : proto_tree_add_item (force_tree, hf_r3_forceoptions_state_32, tvb, start_offset + i + 2, 4, ENC_LITTLE_ENDIAN); break;
      default : DISSECTOR_ASSERT (0);
    }
  }
}