unsigned int CVE_2009_3238_linux2_6_16_get_random_int(void)
{
	/*
	 * Use IP's RNG. It suits our purpose perfectly: it re-keys itself
	 * every second, from the entropy pool (and thus creates a limited
	 * drain on it), and uses halfMD4Transform within the second. We
	 * also mix it with jiffies and the PID:
	 */
	return secure_ip_id(current->pid + jiffies);
}