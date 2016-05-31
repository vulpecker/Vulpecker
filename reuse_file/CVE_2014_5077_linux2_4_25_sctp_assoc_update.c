void CVE_2014_5077_linux2_4_25_sctp_assoc_update(struct sctp_association *asoc, struct sctp_association *new)
{
	/* Copy in new parameters of peer. */
	asoc->c = new->c;
	asoc->peer.rwnd = new->peer.rwnd;
	asoc->peer.sack_needed = new->peer.sack_needed;
	asoc->peer.i = new->peer.i;
	sctp_tsnmap_init(&asoc->peer.tsn_map, SCTP_TSN_MAP_SIZE,
			 asoc->peer.i.initial_tsn);

	/* FIXME:
	 *    Do we need to copy primary_path etc?
	 *
	 *    More explicitly, addresses may have been removed and
	 *    this needs accounting for.
	 */

	/* If the case is A (association restart), use
	 * initial_tsn as next_tsn. If the case is B, use
	 * current next_tsn in case data sent to peer
	 * has been discarded and needs retransmission.
	 */
	if (SCTP_STATE_ESTABLISHED == asoc->state) {

		asoc->next_tsn = new->next_tsn;
		asoc->ctsn_ack_point = new->ctsn_ack_point;

		/* Reinitialize SSN for both local streams
		 * and peer's streams.
		 */
		sctp_ssnmap_clear(asoc->ssnmap);

	} else {
		asoc->ctsn_ack_point = asoc->next_tsn - 1;
		if (!asoc->ssnmap) {
			/* Move the ssnmap. */
			asoc->ssnmap = new->ssnmap;
			new->ssnmap = NULL;
		}
	}

}