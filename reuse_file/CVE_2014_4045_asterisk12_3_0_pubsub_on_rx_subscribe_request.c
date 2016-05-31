
static pj_bool_t CVE_2014_4045_asterisk12_3_0_pubsub_on_rx_subscribe_request(pjsip_rx_data *rdata)
{
	char event[32];
	char accept[AST_SIP_MAX_ACCEPT][64];
	pjsip_accept_hdr *accept_header;
	pjsip_event_hdr *event_header;
	pjsip_expires_hdr *expires_header;
	struct ast_sip_subscription_handler *handler;
	RAII_VAR(struct ast_sip_endpoint *, endpoint, NULL, ao2_cleanup);
	struct ast_sip_subscription *sub;
	size_t num_accept_headers;
	struct ast_sip_pubsub_body_generator *generator;

	endpoint = ast_pjsip_rdata_get_endpoint(rdata);
	ast_assert(endpoint != NULL);

	if (!endpoint->subscription.allow) {
		ast_log(LOG_WARNING, "Subscriptions not permitted for endpoint %s.\n", ast_sorcery_object_get_id(endpoint));
		pjsip_endpt_respond_stateless(ast_sip_get_pjsip_endpoint(), rdata, 603, NULL, NULL, NULL);
		return PJ_TRUE;
	}

	expires_header = pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_EXPIRES, rdata->msg_info.msg->hdr.next);

	if (expires_header && expires_header->ivalue < endpoint->subscription.minexpiry) {
		ast_log(LOG_WARNING, "Subscription expiration %d is too brief for endpoint %s. Minimum is %u\n",
				expires_header->ivalue, ast_sorcery_object_get_id(endpoint), endpoint->subscription.minexpiry);
		pjsip_endpt_respond_stateless(ast_sip_get_pjsip_endpoint(), rdata, 423, NULL, NULL, NULL);
		return PJ_TRUE;
	}

	event_header = pjsip_msg_find_hdr_by_name(rdata->msg_info.msg, &str_event_name, rdata->msg_info.msg->hdr.next);
	if (!event_header) {
		ast_log(LOG_WARNING, "Incoming SUBSCRIBE request with no Event header\n");
		pjsip_endpt_respond_stateless(ast_sip_get_pjsip_endpoint(), rdata, 489, NULL, NULL, NULL);
		return PJ_TRUE;
	}
	ast_copy_pj_str(event, &event_header->event_type, sizeof(event));

	handler = find_sub_handler_for_event_name(event);
	if (!handler) {
		ast_log(LOG_WARNING, "No registered subscribe handler for event %s\n", event);
		pjsip_endpt_respond_stateless(ast_sip_get_pjsip_endpoint(), rdata, 489, NULL, NULL, NULL);
		return PJ_TRUE;
	}

	accept_header = pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_ACCEPT, rdata->msg_info.msg->hdr.next);
	if (accept_header) {
		int i;

		for (i = 0; i < accept_header->count; ++i) {
			ast_copy_pj_str(accept[i], &accept_header->values[i], sizeof(accept[i]));
		}
		num_accept_headers = accept_header->count;
	} else {
		/* If a SUBSCRIBE contains no Accept headers, then we must assume that
		 * the default accept type for the event package is to be used.
		 */
		ast_copy_string(accept[0], handler->default_accept, sizeof(accept[0]));
		num_accept_headers = 1;
	}

	generator = find_body_generator(accept, num_accept_headers);
	if (!generator) {
		pjsip_endpt_respond_stateless(ast_sip_get_pjsip_endpoint(), rdata, 489, NULL, NULL, NULL);
		return PJ_TRUE;
	}

	ast_sip_mod_data_set(rdata->tp_info.pool, rdata->endpt_info.mod_data,
			pubsub_module.id, MOD_DATA_BODY_GENERATOR, generator);

	sub = handler->new_subscribe(endpoint, rdata);
	if (!sub) {
		pjsip_transaction *trans = pjsip_rdata_get_tsx(rdata);

		if (trans) {
			pjsip_dialog *dlg = pjsip_rdata_get_dlg(rdata);
			pjsip_tx_data *tdata;

			if (pjsip_endpt_create_response(ast_sip_get_pjsip_endpoint(), rdata, 500, NULL, &tdata) != PJ_SUCCESS) {
				return PJ_TRUE;
			}
			pjsip_dlg_send_response(dlg, trans, tdata);
		} else {
			pjsip_endpt_respond_stateless(ast_sip_get_pjsip_endpoint(), rdata, 500, NULL, NULL, NULL);
		}
	}
	return PJ_TRUE;
}