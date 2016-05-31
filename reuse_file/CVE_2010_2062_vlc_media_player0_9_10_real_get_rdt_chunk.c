
int CVE_2010_2062_vlc_media_player0_9_10_real_get_rdt_chunk(rtsp_client_t *rtsp_session, rmff_pheader_t *ph,
                       unsigned char **buffer) {

  int n;
  rmff_dump_pheader(ph, (char*)*buffer);
  if (ph->length<12) return 0;
  n=rtsp_read_data(rtsp_session, (uint8_t*)(*buffer + 12), ph->length - 12);
  return (n <= 0) ? 0 : n+12;
}