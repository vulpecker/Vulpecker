static int CVE_2010_1173_linux2_4_25_sctp_process_unk_param(const struct sctp_association *asoc,
				  union sctp_params param,
				  sctp_chunk_t *chunk,
				  sctp_chunk_t **errp)
{
	int retval = 1;

	switch (param.p->type & SCTP_PARAM_ACTION_MASK) {
	case SCTP_PARAM_ACTION_DISCARD:
		retval =  0;
		break;
	case SCTP_PARAM_ACTION_DISCARD_ERR:
		retval =  0;
		/* Make an ERROR chunk, preparing enough room for
		 * returning multiple unknown parameters.
		 */
		if (NULL == *errp)
			*errp = sctp_make_op_error_space(asoc, chunk,
					ntohs(chunk->chunk_hdr->length));

		if (*errp)
			sctp_init_cause(*errp, SCTP_ERROR_UNKNOWN_PARAM,
					param.v,
					WORD_ROUND(ntohs(param.p->length)));

		break;
	case SCTP_PARAM_ACTION_SKIP:
		break;
	case SCTP_PARAM_ACTION_SKIP_ERR:
		/* Make an ERROR chunk, preparing enough room for
		 * returning multiple unknown parameters.
		 */
		if (NULL == *errp)
			*errp = sctp_make_op_error_space(asoc, chunk,
					ntohs(chunk->chunk_hdr->length));

		if (*errp) {
			sctp_init_cause(*errp, SCTP_ERROR_UNKNOWN_PARAM,
					param.v,
					WORD_ROUND(ntohs(param.p->length)));
		} else {
			/* If there is no memory for generating the ERROR
			 * report as specified, an ABORT will be triggered
			 * to the peer and the association won't be
			 * established.
			 */
			retval = 0;
		}

		break;
	default:
		break;
	}

	return retval;
}