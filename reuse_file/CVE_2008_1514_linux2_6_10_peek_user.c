static int
CVE_2008_1514_linux2_6_10_peek_user(struct task_struct *child, addr_t addr, addr_t data)
{
	struct user *dummy = NULL;
	addr_t offset, tmp;

	/*
	 * Stupid gdb peeks/pokes the access registers in 64 bit with
	 * an alignment of 4. Programmers from hell...
	 */
	if ((addr & 3) || addr > sizeof(struct user) - __ADDR_MASK)
		return -EIO;

	if (addr < (addr_t) &dummy->regs.acrs) {
		/*
		 * psw and gprs are stored on the stack
		 */
		tmp = *(addr_t *)((addr_t) &__KSTK_PTREGS(child)->psw + addr);
		if (addr == (addr_t) &dummy->regs.psw.mask)
			/* Remove per bit from user psw. */
			tmp &= ~PSW_MASK_PER;

	} else if (addr < (addr_t) &dummy->regs.orig_gpr2) {
		/*
		 * access registers are stored in the thread structure
		 */
		offset = addr - (addr_t) &dummy->regs.acrs;
		tmp = *(addr_t *)((addr_t) &child->thread.acrs + offset);

	} else if (addr == (addr_t) &dummy->regs.orig_gpr2) {
		/*
		 * orig_gpr2 is stored on the kernel stack
		 */
		tmp = (addr_t) __KSTK_PTREGS(child)->orig_gpr2;

	} else if (addr < (addr_t) (&dummy->regs.fp_regs + 1)) {
		/* 
		 * floating point regs. are stored in the thread structure
		 */
		offset = addr - (addr_t) &dummy->regs.fp_regs;
		tmp = *(addr_t *)((addr_t) &child->thread.fp_regs + offset);

	} else if (addr < (addr_t) (&dummy->regs.per_info + 1)) {
		/*
		 * per_info is found in the thread structure
		 */
		offset = addr - (addr_t) &dummy->regs.per_info;
		tmp = *(addr_t *)((addr_t) &child->thread.per_info + offset);

	} else
		tmp = 0;

	return put_user(tmp, (addr_t __user *) data);
}