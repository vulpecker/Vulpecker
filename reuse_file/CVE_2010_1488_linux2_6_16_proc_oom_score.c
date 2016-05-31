static int CVE_2010_1488_linux2_6_16_proc_oom_score(struct task_struct *task, char *buffer)
{
	unsigned long points;
	struct timespec uptime;

	do_posix_clock_monotonic_gettime(&uptime);
	points = badness(task, uptime.tv_sec);
	return sprintf(buffer, "%lu\n", points);
}