
static int CVE_2014_8418_asterisk1_8_3_1_load_module(void)
{
	int res = 0;

	res |= ast_custom_function_register(&db_function);
	res |= ast_custom_function_register(&db_exists_function);
	res |= ast_custom_function_register(&db_delete_function);

	return res;
}