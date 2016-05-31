static int
CVE_2008_1514_linux2_6_10_poke_user(struct task_struct *child, addr_t addr, addr_t data)
{
	struct user *dummy = NULL;
	addr_t offset;

	/*
	 * Stupid gdb peeks/pokes the access registers in 64 bit with
	 * an alignment of 4. Programmers from hell indeed...
	 */
	if ((addr & 3) || addr > sizeof(struct user) - __ADDR_MASK)
		return -EIO;

	if (addr < (addr_t) &dummy->regs.acrs) {
		/*
		 * psw and gprs are stored on the stack
		 */
		if (addr == (addr_t) &dummy->regs.psw.mask &&
#ifdef CONFIG_S390_SUPPORT
		    data != PSW_MASK_MERGE(PSW_USER32_BITS, data) &&
#endif
		    data != PSW_MASK_MERGE(PSW_USER_BITS, data))
			/* Invalid psw mask. */
			return -EINVAL;
#ifndef CONFIG_ARCH_S390X
		if (addr == (addr_t) &dummy->regs.psw.addr)
			/* I'd like to reject addresses without the
			   high order bit but older gdb's rely on it */
			data |= PSW_ADDR_AMODE;
#endif
		*(addr_t *)((addr_t) &__KSTK_PTREGS(child)->psw + addr) = data;

	} else if (addr < (addr_t) (&dummy->regs.orig_gpr2)) {
		/*
		 * access registers are stored in the thread structure
		 */
		offset = addr - (addr_t) &dummy->regs.acrs;
		*(addr_t *)((addr_t) &child->thread.acrs + offset) = data;

	} else if (addr == (addr_t) &dummy->regs.orig_gpr2) {
		/*
		 * orig_gpr2 is stored on the kernel stack
		 */
		__KSTK_PTREGS(child)->orig_gpr2 = data;

	} else if (addr < (addr_t) (&dummy->regs.fp_regs + 1)) {
		/*
		 * floating point regs. are stored in the thread structure
		 */
		if (addr == (addr_t) &dummy->regs.fp_regs.fpc &&
		    (data & ~FPC_VALID_MASK) != 0)
			return -EINVAL;
		offset = addr - (addr_t) &dummy->regs.fp_regs;
		*(addr_t *)((addr_t) &child->thread.fp_regs + offset) = data;

	} else if (addr < (addr_t) (&dummy->regs.per_info + 1)) {
		/*
		 * per_info is found in the thread structure 
		 */
		offset = addr - (addr_t) &dummy->regs.per_info;
		*(addr_t *)((addr_t) &child->thread.per_info + offset) = data;

	}

	FixPerRegisters(child);
	return 0;
}