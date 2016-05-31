static int CVE_2006_0557_linux2_6_10_get_nodes(unsigned long *nodes, unsigned long __user *nmask,
		     unsigned long maxnode, int mode)
{
	unsigned long k;
	unsigned long nlongs;
	unsigned long endmask;

	--maxnode;
	bitmap_zero(nodes, MAX_NUMNODES);
	if (maxnode == 0 || !nmask)
		return 0;

	nlongs = BITS_TO_LONGS(maxnode);
	if ((maxnode % BITS_PER_LONG) == 0)
		endmask = ~0UL;
	else
		endmask = (1UL << (maxnode % BITS_PER_LONG)) - 1;

	/* When the user specified more nodes than supported just check
	   if the non supported part is all zero. */
	if (nlongs > BITS_TO_LONGS(MAX_NUMNODES)) {
		if (nlongs > PAGE_SIZE/sizeof(long))
			return -EINVAL;
		for (k = BITS_TO_LONGS(MAX_NUMNODES); k < nlongs; k++) {
			unsigned long t;
			if (get_user(t,  nmask + k))
				return -EFAULT;
			if (k == nlongs - 1) {
				if (t & endmask)
					return -EINVAL;
			} else if (t)
				return -EINVAL;
		}
		nlongs = BITS_TO_LONGS(MAX_NUMNODES);
		endmask = ~0UL;
	}

	if (copy_from_user(nodes, nmask, nlongs*sizeof(unsigned long)))
		return -EFAULT;
	nodes[nlongs-1] &= endmask;
	return mpol_check_policy(mode, nodes);
}