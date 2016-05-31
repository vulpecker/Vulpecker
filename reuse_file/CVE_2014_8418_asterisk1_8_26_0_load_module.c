
static int CVE_2014_8418_asterisk1_8_26_0_load_module(void)
{
	int res = 0;

	res |= ast_custom_function_register(&db_function);
	res |= ast_custom_function_register(&db_exists_function);
	res |= ast_custom_function_register_escalating(&db_delete_function, AST_CFE_READ);

	return res;
}