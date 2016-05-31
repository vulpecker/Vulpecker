
void
CVE_2013_0914_linux2_4_25_flush_signal_handlers(struct task_struct *t)
{
	int i;
	struct k_sigaction *ka = &t->sig->action[0];
	for (i = _NSIG ; i != 0 ; i--) {
		if (ka->sa.sa_handler != SIG_IGN)
			ka->sa.sa_handler = SIG_DFL;
		ka->sa.sa_flags = 0;
		sigemptyset(&ka->sa.sa_mask);
		ka++;
	}
}