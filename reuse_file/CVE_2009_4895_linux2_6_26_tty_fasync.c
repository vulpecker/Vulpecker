
static int CVE_2009_4895_linux2_6_26_tty_fasync(int fd, struct file *filp, int on)
{
	struct tty_struct *tty;
	unsigned long flags;
	int retval;

	tty = (struct tty_struct *)filp->private_data;
	if (tty_paranoia_check(tty, filp->f_path.dentry->d_inode, "CVE_2009_4895_linux2_6_26_tty_fasync"))
		return 0;

	retval = fasync_helper(fd, filp, on, &tty->fasync);
	if (retval <= 0)
		return retval;

	if (on) {
		enum pid_type type;
		struct pid *pid;
		if (!waitqueue_active(&tty->read_wait))
			tty->minimum_to_wake = 1;
		spin_lock_irqsave(&tty->ctrl_lock, flags);
		if (tty->pgrp) {
			pid = tty->pgrp;
			type = PIDTYPE_PGID;
		} else {
			pid = task_pid(current);
			type = PIDTYPE_PID;
		}
		spin_unlock_irqrestore(&tty->ctrl_lock, flags);
		retval = __f_setown(filp, pid, type, 0);
		if (retval)
			return retval;
	} else {
		if (!tty->fasync && !waitqueue_active(&tty->read_wait))
			tty->minimum_to_wake = N_TTY_BUF_SIZE;
	}
	return 0;
}