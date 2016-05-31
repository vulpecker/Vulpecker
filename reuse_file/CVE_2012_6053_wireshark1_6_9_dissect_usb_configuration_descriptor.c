static int
dissect_usb_configuration_descriptor(packet_info *pinfo _U_, proto_tree *parent_tree, tvbuff_t *tvb, int offset, usb_trans_info_t *usb_trans_info, usb_conv_info_t *usb_conv_info)
{
    proto_item *item=NULL;
    proto_tree *tree=NULL;
    int old_offset=offset;
    guint16 len;
    proto_item *flags_item=NULL;
    proto_tree *flags_tree=NULL;
    guint8 flags;
    proto_item *power_item=NULL;
    guint8 power;

    if(parent_tree){
        item=proto_tree_add_text(parent_tree, tvb, offset, -1, "CONFIGURATION DESCRIPTOR");
        tree=proto_item_add_subtree(item, ett_descriptor_device);
    }

    /* bLength */
    proto_tree_add_item(tree, hf_usb_bLength, tvb, offset, 1, TRUE);
    offset++;

    /* bDescriptorType */
    proto_tree_add_item(tree, hf_usb_bDescriptorType, tvb, offset, 1, TRUE);
    offset++;

    /* wTotalLength */
    proto_tree_add_item(tree, hf_usb_wTotalLength, tvb, offset, 2, TRUE);
    len=tvb_get_letohs(tvb, offset);
    offset+=2;

    /* bNumInterfaces */
    proto_tree_add_item(tree, hf_usb_bNumInterfaces, tvb, offset, 1, TRUE);
    offset++;

    /* bConfigurationValue */
    proto_tree_add_item(tree, hf_usb_bConfigurationValue, tvb, offset, 1, TRUE);
    offset++;

    /* iConfiguration */
    proto_tree_add_item(tree, hf_usb_iConfiguration, tvb, offset, 1, TRUE);
    offset++;

    /* bmAttributes */
    if(tree){
        flags_item=proto_tree_add_item(tree, hf_usb_configuration_bmAttributes, tvb, offset, 1, TRUE);
        flags_tree=proto_item_add_subtree(flags_item, ett_configuration_bmAttributes);
    }
    flags=tvb_get_guint8(tvb, offset);
    proto_tree_add_item(flags_tree, hf_usb_configuration_legacy10buspowered, tvb, offset, 1, TRUE);
    proto_tree_add_item(flags_tree, hf_usb_configuration_selfpowered, tvb, offset, 1, TRUE);
    proto_item_append_text(flags_item, "  %sSELF-POWERED", (flags&0x40)?"":"NOT ");
    proto_tree_add_item(flags_tree, hf_usb_configuration_remotewakeup, tvb, offset, 1, TRUE);
    proto_item_append_text(flags_item, "  %sREMOTE-WAKEUP", (flags&0x20)?"":"NO ");
    offset++;

    /* bMaxPower */
    power_item=proto_tree_add_item(tree, hf_usb_bMaxPower, tvb, offset, 1, TRUE);
    power=tvb_get_guint8(tvb, offset);
    proto_item_append_text(power_item, "  (%dmA)", power*2);
    offset++;

    /* initialize interface_info to NULL */
    usb_trans_info->interface_info=NULL;

    /* decode any additional interface and endpoint descriptors */
    while(len>(old_offset-offset)){
        guint8 next_type;

        if(tvb_length_remaining(tvb, offset)<2){
            break;
        }
        next_type=tvb_get_guint8(tvb, offset+1);
        switch(next_type){
        case USB_DT_INTERFACE:
            offset=dissect_usb_interface_descriptor(pinfo, parent_tree, tvb, offset, usb_trans_info, usb_conv_info);
            break;
        case USB_DT_ENDPOINT:
            offset=dissect_usb_endpoint_descriptor(pinfo, parent_tree, tvb, offset, usb_trans_info, usb_conv_info);
            break;
        default:
            offset=dissect_usb_unknown_descriptor(pinfo, parent_tree, tvb, offset, usb_trans_info, usb_conv_info);
            break;
            /* was: return offset; */
        }
    }

    if(item){
        proto_item_set_len(item, offset-old_offset);
    }

    return offset;
}