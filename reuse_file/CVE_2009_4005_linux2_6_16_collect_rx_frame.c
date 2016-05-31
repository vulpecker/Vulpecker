static void
CVE_2009_4005_linux2_6_16_collect_rx_frame(usb_fifo * fifo, __u8 * data, int len, int finish)
{
	hfcusb_data *hfc = fifo->hfc;
	int transp_mode, fifon;
#ifdef CONFIG_HISAX_DEBUG
	int i;
#endif
	fifon = fifo->fifonum;
	transp_mode = 0;
	if (fifon < 4 && hfc->b_mode[fifon / 2] == L1_MODE_TRANS)
		transp_mode = TRUE;

	if (!fifo->skbuff) {
		fifo->skbuff = dev_alloc_skb(fifo->max_size + 3);
		if (!fifo->skbuff) {
			printk(KERN_INFO
			       "HFC-S USB: cannot allocate buffer (dev_alloc_skb) fifo:%d\n",
			       fifon);
			return;
		}
	}
	if (len) {
		if (fifo->skbuff->len + len < fifo->max_size) {
			memcpy(skb_put(fifo->skbuff, len), data, len);
		} else {
#ifdef CONFIG_HISAX_DEBUG
			printk(KERN_INFO "HFC-S USB: ");
			for (i = 0; i < 15; i++)
				printk("%.2x ",
				       fifo->skbuff->data[fifo->skbuff->
							  len - 15 + i]);
			printk("\n");
#endif
			printk(KERN_INFO
			       "HCF-USB: got frame exceeded fifo->max_size:%d on fifo:%d\n",
			       fifo->max_size, fifon);
		}
	}
	if (transp_mode && fifo->skbuff->len >= 128) {
		fifo->hif->l1l2(fifo->hif, PH_DATA | INDICATION,
				fifo->skbuff);
		fifo->skbuff = NULL;
		return;
	}
	/* we have a complete hdlc packet */
	if (finish) {
		if ((!fifo->skbuff->data[fifo->skbuff->len - 1])
		    && (fifo->skbuff->len > 3)) {
			/* remove CRC & status */
			skb_trim(fifo->skbuff, fifo->skbuff->len - 3);
			if (fifon == HFCUSB_PCM_RX) {
				fifo->hif->l1l2(fifo->hif,
						PH_DATA_E | INDICATION,
						fifo->skbuff);
			} else
				fifo->hif->l1l2(fifo->hif,
						PH_DATA | INDICATION,
						fifo->skbuff);
			fifo->skbuff = NULL;	/* buffer was freed from upper layer */
		} else {
			if (fifo->skbuff->len > 3) {
				printk(KERN_INFO
				       "HFC-S USB: got frame %d bytes but CRC ERROR on fifo:%d!!!\n",
				       fifo->skbuff->len, fifon);
#ifdef CONFIG_HISAX_DEBUG
				if (debug > 1) {
					printk(KERN_INFO "HFC-S USB: ");
					for (i = 0; i < 15; i++)
						printk("%.2x ",
						       fifo->skbuff->
						       data[fifo->skbuff->
							    len - 15 + i]);
					printk("\n");
				}
#endif
			}
#ifdef CONFIG_HISAX_DEBUG
			else {
				printk(KERN_INFO
				       "HFC-S USB: frame to small (%d bytes)!!!\n",
				       fifo->skbuff->len);
			}
#endif
			skb_trim(fifo->skbuff, 0);
		}
	}
}