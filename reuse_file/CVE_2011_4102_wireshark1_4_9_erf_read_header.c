
static int erf_read_header(FILE_T fh,
			   struct wtap_pkthdr *phdr,
			   union wtap_pseudo_header *pseudo_header,
			   erf_header_t *erf_header,
			   int *err,
			   gchar **err_info,
			   guint32 *bytes_read,
			   guint32 *packet_size)
{
  guint32 mc_hdr;
  guint8 erf_exhdr[8];
  guint64 erf_exhdr_sw;
  guint8 type = 0;
  guint16 eth_hdr;
  guint32 skiplen=0;
  int i = 0 , max = sizeof(pseudo_header->erf.ehdr_list)/sizeof(struct erf_ehdr);

  wtap_file_read_expected_bytes(erf_header, sizeof(*erf_header), fh, err);
  if (bytes_read != NULL) {
    *bytes_read = sizeof(*erf_header);
  }

  *packet_size =  g_ntohs(erf_header->rlen) - (guint32)sizeof(*erf_header);

  if (*packet_size > WTAP_MAX_PACKET_SIZE) {
    /*
     * Probably a corrupt capture file; don't blow up trying
     * to allocate space for an immensely-large packet.
     */
    *err = WTAP_ERR_BAD_RECORD;
    *err_info = g_strdup_printf("erf: File has %u-byte packet, bigger than maximum of %u",
				*packet_size, WTAP_MAX_PACKET_SIZE);
    return FALSE;
  }

  if (phdr != NULL) {
    guint64 ts = pletohll(&erf_header->ts);

    phdr->ts.secs = (long) (ts >> 32);
    ts = ((ts & 0xffffffff) * 1000 * 1000 * 1000);
    ts += (ts & 0x80000000) << 1; /* rounding */
    phdr->ts.nsecs = ((int) (ts >> 32));
    if (phdr->ts.nsecs >= 1000000000) {
      phdr->ts.nsecs -= 1000000000;
      phdr->ts.secs += 1;
    }
  }

  /* Copy the ERF pseudo header */
  memset(&pseudo_header->erf, 0, sizeof(pseudo_header->erf));
  pseudo_header->erf.phdr.ts = pletohll(&erf_header->ts);
  pseudo_header->erf.phdr.type = erf_header->type;
  pseudo_header->erf.phdr.flags = erf_header->flags;
  pseudo_header->erf.phdr.rlen = g_ntohs(erf_header->rlen);
  pseudo_header->erf.phdr.lctr = g_ntohs(erf_header->lctr);
  pseudo_header->erf.phdr.wlen = g_ntohs(erf_header->wlen);

  /* Copy the ERF extension header into the pseudo header */
  type = erf_header->type;
  while (type & 0x80){
	  wtap_file_read_expected_bytes(&erf_exhdr, sizeof(erf_exhdr), fh, err);
	  if (bytes_read != NULL)
		  *bytes_read += (guint32)sizeof(erf_exhdr);
	  *packet_size -=  (guint32)sizeof(erf_exhdr);
	  skiplen += (guint32)sizeof(erf_exhdr);
	  erf_exhdr_sw = pntohll((guint64*) &(erf_exhdr[0]));
	  if (i < max)
	    memcpy(&pseudo_header->erf.ehdr_list[i].ehdr, &erf_exhdr_sw, sizeof(erf_exhdr_sw));
	  type = erf_exhdr[0];
	  i++;
  }

  switch (erf_header->type & 0x7F) {
  case ERF_TYPE_IPV4:
  case ERF_TYPE_IPV6:
  case ERF_TYPE_RAW_LINK:
  case ERF_TYPE_INFINIBAND:
  case ERF_TYPE_INFINIBAND_LINK:
    /***
    if (phdr != NULL) {
      phdr->len =  g_htons(erf_header->wlen);
      phdr->caplen = g_htons(erf_header->wlen); 
    }  
    return TRUE;
    ***/
    break;
  case ERF_TYPE_PAD:
  case ERF_TYPE_HDLC_POS:
  case ERF_TYPE_COLOR_HDLC_POS:
  case ERF_TYPE_DSM_COLOR_HDLC_POS:
  case ERF_TYPE_ATM:
  case ERF_TYPE_AAL5:
    break;

  case ERF_TYPE_ETH:
  case ERF_TYPE_COLOR_ETH:
  case ERF_TYPE_DSM_COLOR_ETH:
    wtap_file_read_expected_bytes(&eth_hdr, sizeof(eth_hdr), fh, err);
    if (bytes_read != NULL)
      *bytes_read += (guint32)sizeof(eth_hdr);
    *packet_size -=  (guint32)sizeof(eth_hdr);
    skiplen += (guint32)sizeof(eth_hdr);
    pseudo_header->erf.subhdr.eth_hdr = g_htons(eth_hdr);
    break;

  case ERF_TYPE_MC_HDLC:
  case ERF_TYPE_MC_RAW:
  case ERF_TYPE_MC_ATM:
  case ERF_TYPE_MC_RAW_CHANNEL:
  case ERF_TYPE_MC_AAL5:
  case ERF_TYPE_MC_AAL2:
  case ERF_TYPE_COLOR_MC_HDLC_POS:
  case ERF_TYPE_AAL2: /* not an MC type but has a similar 'AAL2 ext' header */
    wtap_file_read_expected_bytes(&mc_hdr, sizeof(mc_hdr), fh, err);
    if (bytes_read != NULL)
      *bytes_read += (guint32)sizeof(mc_hdr);
    *packet_size -=  (guint32)sizeof(mc_hdr);
    skiplen += (guint32)sizeof(mc_hdr);
    pseudo_header->erf.subhdr.mc_hdr = g_htonl(mc_hdr);
    break;

  case ERF_TYPE_IP_COUNTER:
  case ERF_TYPE_TCP_FLOW_COUNTER:
    /* unsupported, continue with default: */
  default:
    *err = WTAP_ERR_UNSUPPORTED_ENCAP;
    *err_info = g_strdup_printf("erf: unknown record encapsulation %u",
				erf_header->type);
    return FALSE;
  }

  if (phdr != NULL) {
    phdr->len = g_htons(erf_header->wlen);
    phdr->caplen = min( g_htons(erf_header->wlen),
			g_htons(erf_header->rlen) - (guint32)sizeof(*erf_header) - skiplen );
  }
  return TRUE;
}