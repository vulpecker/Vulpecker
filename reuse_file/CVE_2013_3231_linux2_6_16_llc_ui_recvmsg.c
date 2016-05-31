static int CVE_2013_3231_linux2_6_16_llc_ui_recvmsg(struct kiocb *iocb, struct socket *sock,
			  struct msghdr *msg, size_t len, int flags)
{
	struct sockaddr_llc *uaddr = (struct sockaddr_llc *)msg->msg_name;
	const int nonblock = flags & MSG_DONTWAIT;
	struct sk_buff *skb = NULL;
	struct sock *sk = sock->sk;
	struct llc_sock *llc = llc_sk(sk);
	size_t copied = 0;
	u32 peek_seq = 0;
	u32 *seq;
	unsigned long used;
	int target;	/* Read at least this many bytes */
	long timeo;

	lock_sock(sk);
	copied = -ENOTCONN;
	if (sk->sk_state == TCP_LISTEN)
		goto out;

	timeo = sock_rcvtimeo(sk, nonblock);

	seq = &llc->copied_seq;
	if (flags & MSG_PEEK) {
		peek_seq = llc->copied_seq;
		seq = &peek_seq;
 	}

	target = sock_rcvlowat(sk, flags & MSG_WAITALL, len);
	copied = 0;

	do {
		u32 offset;

		/*
		 * We need to check signals first, to get correct SIGURG
		 * handling. FIXME: Need to check this doesn't impact 1003.1g
		 * and move it down to the bottom of the loop
		 */
		if (signal_pending(current)) {
			if (copied)
				break;
			copied = timeo ? sock_intr_errno(timeo) : -EAGAIN;
			break;
		}

		/* Next get a buffer. */

		skb = skb_peek(&sk->sk_receive_queue);
		if (skb) {
			offset = *seq;
			goto found_ok_skb;
		}
		/* Well, if we have backlog, try to process it now yet. */

		if (copied >= target && !sk->sk_backlog.tail)
			break;

		if (copied) {
			if (sk->sk_err ||
			    sk->sk_state == TCP_CLOSE ||
			    (sk->sk_shutdown & RCV_SHUTDOWN) ||
			    !timeo ||
			    (flags & MSG_PEEK))
				break;
		} else {
			if (sock_flag(sk, SOCK_DONE))
				break;

			if (sk->sk_err) {
				copied = sock_error(sk);
				break;
			}
			if (sk->sk_shutdown & RCV_SHUTDOWN)
				break;

			if (sk->sk_state == TCP_CLOSE) {
				if (!sock_flag(sk, SOCK_DONE)) {
					/*
					 * This occurs when user tries to read
					 * from never connected socket.
					 */
					copied = -ENOTCONN;
					break;
				}
				break;
			}
			if (!timeo) {
				copied = -EAGAIN;
				break;
			}
		}

		if (copied >= target) { /* Do not sleep, just process backlog. */
			release_sock(sk);
			lock_sock(sk);
		} else
			sk_wait_data(sk, &timeo);

		if ((flags & MSG_PEEK) && peek_seq != llc->copied_seq) {
			if (net_ratelimit())
				printk(KERN_DEBUG "LLC(%s:%d): Application "
						  "bug, race in MSG_PEEK.\n",
				       current->comm, current->pid);
			peek_seq = llc->copied_seq;
		}
		continue;
	found_ok_skb:
		/* Ok so how much can we use? */
		used = skb->len - offset;
		if (len < used)
			used = len;

		if (!(flags & MSG_TRUNC)) {
			int rc = skb_copy_datagram_iovec(skb, offset,
							 msg->msg_iov, used);
			if (rc) {
				/* Exception. Bailout! */
				if (!copied)
					copied = -EFAULT;
				break;
			}
		}

		*seq += used;
		copied += used;
		len -= used;

		if (used + offset < skb->len)
			continue;

		if (!(flags & MSG_PEEK)) {
			sk_eat_skb(sk, skb);
			*seq = 0;
		}
	} while (len > 0);

	/* 
	 * According to UNIX98, msg_name/msg_namelen are ignored
	 * on connected socket. -ANK
	 * But... af_llc still doesn't have separate sets of methods for
	 * SOCK_DGRAM and SOCK_STREAM :-( So we have to do this test, will
	 * eventually fix this tho :-) -acme
	 */
	if (sk->sk_type == SOCK_DGRAM)
		goto copy_uaddr;
out:
	release_sock(sk);
	return copied;
copy_uaddr:
	if (uaddr != NULL && skb != NULL) {
		memcpy(uaddr, llc_ui_skb_cb(skb), sizeof(*uaddr));
		msg->msg_namelen = sizeof(*uaddr);
	}
	goto out;
}