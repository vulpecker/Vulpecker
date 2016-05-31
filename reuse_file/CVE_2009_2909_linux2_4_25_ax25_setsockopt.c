
static int CVE_2009_2909_linux2_4_25_ax25_setsockopt(struct socket *sock, int level, int optname, char *optval, int optlen)
{
	struct sock *sk = sock->sk;
	struct net_device *dev;
	char devname[IFNAMSIZ];
	int opt;

	if (level != SOL_AX25)
		return -ENOPROTOOPT;

	if (optlen < sizeof(int))
		return -EINVAL;

	if (get_user(opt, (int *)optval))
		return -EFAULT;

	switch (optname) {
		case AX25_WINDOW:
			if (sk->protinfo.ax25->modulus == AX25_MODULUS) {
				if (opt < 1 || opt > 7)
					return -EINVAL;
			} else {
				if (opt < 1 || opt > 63)
					return -EINVAL;
			}
			sk->protinfo.ax25->window = opt;
			return 0;

		case AX25_T1:
			if (opt < 1)
				return -EINVAL;
			sk->protinfo.ax25->rtt = (opt * HZ) / 2;
			sk->protinfo.ax25->t1  = opt * HZ;
			return 0;

		case AX25_T2:
			if (opt < 1)
				return -EINVAL;
			sk->protinfo.ax25->t2 = opt * HZ;
			return 0;

		case AX25_N2:
			if (opt < 1 || opt > 31)
				return -EINVAL;
			sk->protinfo.ax25->n2 = opt;
			return 0;

		case AX25_T3:
			if (opt < 1)
				return -EINVAL;
			sk->protinfo.ax25->t3 = opt * HZ;
			return 0;

		case AX25_IDLE:
			if (opt < 0)
				return -EINVAL;
			sk->protinfo.ax25->idle = opt * 60 * HZ;
			return 0;

		case AX25_BACKOFF:
			if (opt < 0 || opt > 2)
				return -EINVAL;
			sk->protinfo.ax25->backoff = opt;
			return 0;

		case AX25_EXTSEQ:
			sk->protinfo.ax25->modulus = opt ? AX25_EMODULUS : AX25_MODULUS;
			return 0;

		case AX25_PIDINCL:
			sk->protinfo.ax25->pidincl = opt ? 1 : 0;
			return 0;

		case AX25_IAMDIGI:
			sk->protinfo.ax25->iamdigi = opt ? 1 : 0;
			return 0;

		case AX25_PACLEN:
			if (opt < 16 || opt > 65535)
				return -EINVAL;
			sk->protinfo.ax25->paclen = opt;
			return 0;

		case SO_BINDTODEVICE:
			if (optlen > IFNAMSIZ) optlen=IFNAMSIZ;
			if (copy_from_user(devname, optval, optlen))
				return -EFAULT;

			dev = dev_get_by_name(devname);
			if (dev == NULL) return -ENODEV;

			if (sk->type == SOCK_SEQPACKET && 
			   (sock->state != SS_UNCONNECTED || sk->state == TCP_LISTEN))
				return -EADDRNOTAVAIL;
		
			sk->protinfo.ax25->ax25_dev = ax25_dev_ax25dev(dev);
			ax25_fillin_cb(sk->protinfo.ax25, sk->protinfo.ax25->ax25_dev);
			return 0;

		default:
			return -ENOPROTOOPT;
	}
}