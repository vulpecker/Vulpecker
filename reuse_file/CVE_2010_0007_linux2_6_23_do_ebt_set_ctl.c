
static int CVE_2010_0007_linux2_6_23_do_ebt_set_ctl(struct sock *sk,
	int cmd, void __user *user, unsigned int len)
{
	int ret;

	switch(cmd) {
	case EBT_SO_SET_ENTRIES:
		ret = do_replace(user, len);
		break;
	case EBT_SO_SET_COUNTERS:
		ret = update_counters(user, len);
		break;
	default:
		ret = -EINVAL;
  }
	return ret;
}