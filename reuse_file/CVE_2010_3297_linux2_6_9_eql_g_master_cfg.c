
static int CVE_2010_3297_linux2_6_9_eql_g_master_cfg(struct net_device *dev, master_config_t __user *mcp)
{
	equalizer_t *eql;
	master_config_t mc;

	if (eql_is_master(dev)) {
		eql = dev->priv;
		mc.max_slaves = eql->max_slaves;
		mc.min_slaves = eql->min_slaves;
		if (copy_to_user(mcp, &mc, sizeof (master_config_t)))
			return -EFAULT;
		return 0;
	}
	return -EINVAL;
}