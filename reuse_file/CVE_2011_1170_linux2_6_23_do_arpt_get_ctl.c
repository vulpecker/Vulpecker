
static int CVE_2011_1170_linux2_6_23_do_arpt_get_ctl(struct sock *sk, int cmd, void __user *user, int *len)
{
	int ret;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	switch (cmd) {
	case ARPT_SO_GET_INFO: {
		char name[ARPT_TABLE_MAXNAMELEN];
		struct arpt_table *t;

		if (*len != sizeof(struct arpt_getinfo)) {
			duprintf("length %u != %Zu\n", *len,
				 sizeof(struct arpt_getinfo));
			ret = -EINVAL;
			break;
		}

		if (copy_from_user(name, user, sizeof(name)) != 0) {
			ret = -EFAULT;
			break;
		}
		name[ARPT_TABLE_MAXNAMELEN-1] = '\0';

		t = try_then_request_module(xt_find_table_lock(NF_ARP, name),
					    "arptable_%s", name);
		if (t && !IS_ERR(t)) {
			struct arpt_getinfo info;
			struct xt_table_info *private = t->private;

			info.valid_hooks = t->valid_hooks;
			memcpy(info.hook_entry, private->hook_entry,
			       sizeof(info.hook_entry));
			memcpy(info.underflow, private->underflow,
			       sizeof(info.underflow));
			info.num_entries = private->number;
			info.size = private->size;
			strcpy(info.name, name);

			if (copy_to_user(user, &info, *len) != 0)
				ret = -EFAULT;
			else
				ret = 0;
			xt_table_unlock(t);
			module_put(t->me);
		} else
			ret = t ? PTR_ERR(t) : -ENOENT;
	}
	break;

	case ARPT_SO_GET_ENTRIES: {
		struct arpt_get_entries get;

		if (*len < sizeof(get)) {
			duprintf("get_entries: %u < %Zu\n", *len, sizeof(get));
			ret = -EINVAL;
		} else if (copy_from_user(&get, user, sizeof(get)) != 0) {
			ret = -EFAULT;
		} else if (*len != sizeof(struct arpt_get_entries) + get.size) {
			duprintf("get_entries: %u != %Zu\n", *len,
				 sizeof(struct arpt_get_entries) + get.size);
			ret = -EINVAL;
		} else
			ret = get_entries(&get, user);
		break;
	}

	case ARPT_SO_GET_REVISION_TARGET: {
		struct xt_get_revision rev;

		if (*len != sizeof(rev)) {
			ret = -EINVAL;
			break;
		}
		if (copy_from_user(&rev, user, sizeof(rev)) != 0) {
			ret = -EFAULT;
			break;
		}

		try_then_request_module(xt_find_revision(NF_ARP, rev.name,
							 rev.revision, 1, &ret),
					"arpt_%s", rev.name);
		break;
	}

	default:
		duprintf("CVE_2011_1170_linux2_6_23_do_arpt_get_ctl: unknown request %i\n", cmd);
		ret = -EINVAL;
	}

	return ret;
}