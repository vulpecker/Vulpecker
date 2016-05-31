void CVE_2014_5077_linux2_6_23_sctp_assoc_update(struct sctp_association *asoc,
		       struct sctp_association *new)
{
	struct sctp_transport *trans;
	struct list_head *pos, *temp;

	/* Copy in new parameters of peer. */
	asoc->c = new->c;
	asoc->peer.rwnd = new->peer.rwnd;
	asoc->peer.sack_needed = new->peer.sack_needed;
	asoc->peer.i = new->peer.i;
	sctp_tsnmap_init(&asoc->peer.tsn_map, SCTP_TSN_MAP_SIZE,
			 asoc->peer.i.initial_tsn);

	/* Remove any peer addresses not present in the new association. */
	list_for_each_safe(pos, temp, &asoc->peer.transport_addr_list) {
		trans = list_entry(pos, struct sctp_transport, transports);
		if (!sctp_assoc_lookup_paddr(new, &trans->ipaddr))
			sctp_assoc_del_peer(asoc, &trans->ipaddr);

		if (asoc->state >= SCTP_STATE_ESTABLISHED)
			sctp_transport_reset(trans);
	}

	/* If the case is A (association restart), use
	 * initial_tsn as next_tsn. If the case is B, use
	 * current next_tsn in case data sent to peer
	 * has been discarded and needs retransmission.
	 */
	if (asoc->state >= SCTP_STATE_ESTABLISHED) {
		asoc->next_tsn = new->next_tsn;
		asoc->ctsn_ack_point = new->ctsn_ack_point;
		asoc->adv_peer_ack_point = new->adv_peer_ack_point;

		/* Reinitialize SSN for both local streams
		 * and peer's streams.
		 */
		sctp_ssnmap_clear(asoc->ssnmap);

		/* Flush the ULP reassembly and ordered queue.
		 * Any data there will now be stale and will
		 * cause problems.
		 */
		sctp_ulpq_flush(&asoc->ulpq);

		/* reset the overall association error count so
		 * that the restarted association doesn't get torn
		 * down on the next retransmission timer.
		 */
		asoc->overall_error_count = 0;

	} else {
		/* Add any peer addresses from the new association. */
		list_for_each(pos, &new->peer.transport_addr_list) {
			trans = list_entry(pos, struct sctp_transport,
					   transports);
			if (!sctp_assoc_lookup_paddr(asoc, &trans->ipaddr))
				sctp_assoc_add_peer(asoc, &trans->ipaddr,
						    GFP_ATOMIC, trans->state);
		}

		asoc->ctsn_ack_point = asoc->next_tsn - 1;
		asoc->adv_peer_ack_point = asoc->ctsn_ack_point;
		if (!asoc->ssnmap) {
			/* Move the ssnmap. */
			asoc->ssnmap = new->ssnmap;
			new->ssnmap = NULL;
		}

		if (!asoc->assoc_id) {
			/* get a new association id since we don't have one
			 * yet.
			 */
			sctp_assoc_set_id(asoc, GFP_ATOMIC);
		}
	}
}