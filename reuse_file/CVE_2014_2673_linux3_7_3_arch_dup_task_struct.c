int CVE_2014_2673_linux3_7_3_arch_dup_task_struct(struct task_struct *dst, struct task_struct *src)
{
	flush_fp_to_thread(src);
	flush_altivec_to_thread(src);
	flush_vsx_to_thread(src);
	flush_spe_to_thread(src);
#ifdef CONFIG_HAVE_HW_BREAKPOINT
	flush_ptrace_hw_breakpoint(src);
#endif /* CONFIG_HAVE_HW_BREAKPOINT */

	*dst = *src;
	return 0;
}