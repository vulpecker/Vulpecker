static int CVE_2014_8415_asterisk12_0_0_update_connected_line_information(void *data)
{
	RAII_VAR(struct ast_sip_session *, session, data, ao2_cleanup);
	struct ast_party_id connected_id;

	if ((ast_channel_state(session->channel) != AST_STATE_UP) && (session->inv_session->role == PJSIP_UAS_ROLE)) {
		int response_code = 0;

		if (ast_channel_state(session->channel) == AST_STATE_RING) {
			response_code = !session->endpoint->inband_progress ? 180 : 183;
		} else if (ast_channel_state(session->channel) == AST_STATE_RINGING) {
			response_code = 183;
		}

		if (response_code) {
			struct pjsip_tx_data *packet = NULL;

			if (pjsip_inv_answer(session->inv_session, response_code, NULL, NULL, &packet) == PJ_SUCCESS) {
				ast_sip_session_send_response(session, packet);
			}
		}
	} else {
		enum ast_sip_session_refresh_method method = session->endpoint->id.refresh_method;

		if (session->inv_session->invite_tsx && (session->inv_session->options & PJSIP_INV_SUPPORT_UPDATE)) {
			method = AST_SIP_SESSION_REFRESH_METHOD_UPDATE;
		}

		connected_id = ast_channel_connected_effective_id(session->channel);
		if ((session->endpoint->id.send_pai || session->endpoint->id.send_rpid) &&
		    (session->endpoint->id.trust_outbound ||
		     ((connected_id.name.presentation & AST_PRES_RESTRICTION) == AST_PRES_ALLOWED &&
		      (connected_id.number.presentation & AST_PRES_RESTRICTION) == AST_PRES_ALLOWED))) {
			ast_sip_session_refresh(session, NULL, NULL, NULL, method, 1);
		}
	}

	return 0;
}