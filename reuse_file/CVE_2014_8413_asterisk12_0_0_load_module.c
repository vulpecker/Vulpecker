
static int CVE_2014_8413_asterisk12_0_0_load_module(void)
{
	ast_sorcery_apply_default(ast_sip_get_sorcery(), SIP_SORCERY_ACL_TYPE,
				  "config", "pjsip.conf,criteria=type=acl");

	if (ast_sorcery_object_register(ast_sip_get_sorcery(), SIP_SORCERY_ACL_TYPE,
					acl_alloc, NULL, NULL)) {

		ast_log(LOG_ERROR, "Failed to register SIP %s object with sorcery\n",
			SIP_SORCERY_ACL_TYPE);
		return AST_MODULE_LOAD_DECLINE;
	}

	ast_sorcery_object_field_register(ast_sip_get_sorcery(), SIP_SORCERY_ACL_TYPE, "type", "", OPT_NOOP_T, 0, 0);
	ast_sorcery_object_field_register_custom(ast_sip_get_sorcery(), SIP_SORCERY_ACL_TYPE, "permit", "", acl_handler, NULL, 0, 0);
	ast_sorcery_object_field_register_custom(ast_sip_get_sorcery(), SIP_SORCERY_ACL_TYPE, "deny", "", acl_handler, NULL, 0, 0);
	ast_sorcery_object_field_register_custom(ast_sip_get_sorcery(), SIP_SORCERY_ACL_TYPE, "acl", "", acl_handler, NULL, 0, 0);
	ast_sorcery_object_field_register_custom(ast_sip_get_sorcery(), SIP_SORCERY_ACL_TYPE, "contact_permit", "", acl_handler, NULL, 0, 0);
	ast_sorcery_object_field_register_custom(ast_sip_get_sorcery(), SIP_SORCERY_ACL_TYPE, "contact_deny", "", acl_handler, NULL, 0, 0);
	ast_sorcery_object_field_register_custom(ast_sip_get_sorcery(), SIP_SORCERY_ACL_TYPE, "contact_acl", "", acl_handler, NULL, 0, 0);

	ast_sip_register_service(&acl_module);
	return AST_MODULE_LOAD_SUCCESS;
}