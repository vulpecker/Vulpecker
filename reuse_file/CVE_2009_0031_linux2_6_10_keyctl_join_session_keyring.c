long CVE_2009_0031_linux2_6_10_keyctl_join_session_keyring(const char __user *_name)
{
	char *name;
	long nlen, ret;

	/* fetch the name from userspace */
	name = NULL;
	if (_name) {
		ret = -EFAULT;
		nlen = strnlen_user(_name, PAGE_SIZE - 1);
		if (nlen <= 0)
			goto error;

		ret = -EINVAL;
		if (nlen > PAGE_SIZE - 1)
			goto error;

		ret = -ENOMEM;
		name = kmalloc(nlen + 1, GFP_KERNEL);
		if (!name)
			goto error;

		ret = -EFAULT;
		if (copy_from_user(name, _name, nlen + 1) != 0)
			goto error2;
	}

	/* join the session */
	ret = join_session_keyring(name);

 error2:
	kfree(name);
 error:
	return ret;

}