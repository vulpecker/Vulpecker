static int CVE_2012_0957_linux3_0_4_override_release(char __user *release, int len)
{
	int ret = 0;
	char buf[len];

	if (current->personality & UNAME26) {
		char *rest = UTS_RELEASE;
		int ndots = 0;
		unsigned v;

		while (*rest) {
			if (*rest == '.' && ++ndots >= 3)
				break;
			if (!isdigit(*rest) && *rest != '.')
				break;
			rest++;
		}
		v = ((LINUX_VERSION_CODE >> 8) & 0xff) + 40;
		snprintf(buf, len, "2.6.%u%s", v, rest);
		ret = copy_to_user(release, buf, len);
	}
	return ret;
}