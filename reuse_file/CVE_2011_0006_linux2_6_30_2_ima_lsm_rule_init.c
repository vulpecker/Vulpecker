
static int CVE_2011_0006_linux2_6_30_2_ima_lsm_rule_init(struct ima_measure_rule_entry *entry,
			     char *args, int lsm_rule, int audit_type)
{
	int result;

	entry->lsm[lsm_rule].type = audit_type;
	result = security_filter_rule_init(entry->lsm[lsm_rule].type,
					   AUDIT_EQUAL, args,
					   &entry->lsm[lsm_rule].rule);
	return result;
}