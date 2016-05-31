static int CVE_2010_1488_linux2_6_23_proc_oom_score(struct task_struct *task, char *buffer)
{
	unsigned long points;
	struct timespec uptime;

	do_posix_clock_monotonic_gettime(&uptime);
	read_lock(&tasklist_lock);
	points = badness(task, uptime.tv_sec);
	read_unlock(&tasklist_lock);
	return sprintf(buffer, "%lu\n", points);
}