
static int CVE_2014_8415_asterisk12_0_0_answer(void *data)
{
	pj_status_t status = PJ_SUCCESS;
	pjsip_tx_data *packet;
	struct ast_sip_session *session = data;

	pjsip_dlg_inc_lock(session->inv_session->dlg);
	if (session->inv_session->invite_tsx) {
		status = pjsip_inv_CVE_2014_8415_asterisk12_0_0_answer(session->inv_session, 200, NULL, NULL, &packet);
	}
	pjsip_dlg_dec_lock(session->inv_session->dlg);

	if (status == PJ_SUCCESS && packet) {
		ast_sip_session_send_response(session, packet);
	}

	ao2_ref(session, -1);

	return (status == PJ_SUCCESS) ? 0 : -1;
}