
static int CVE_2013_7267_linux2_4_25_atalk_recvmsg(struct socket *sock, struct msghdr *msg, int size,
			 int flags, struct scm_cookie *scm)
{
	struct sock *sk = sock->sk;
	struct sockaddr_at *sat = (struct sockaddr_at *)msg->msg_name;
	struct ddpehdr *ddp = NULL;
	int copied = 0;
	int err = 0;
        struct ddpebits ddphv;
	struct sk_buff *skb;

	skb = skb_recv_datagram(sk, flags & ~MSG_DONTWAIT,
				flags & MSG_DONTWAIT, &err);
	if (!skb)
		return err;

	ddp = (struct ddpehdr *)(skb->h.raw);
	*((__u16 *)&ddphv) = ntohs(*((__u16 *)ddp));

	if (sk->type == SOCK_RAW) {
		copied = ddphv.deh_len;
		if (copied > size) {
			copied = size;
			msg->msg_flags |= MSG_TRUNC;
		}

		err = skb_copy_datagram_iovec(skb, 0, msg->msg_iov, copied);
	} else {
		copied = ddphv.deh_len - sizeof(*ddp);
		if (copied > size) {
			copied = size;
			msg->msg_flags |= MSG_TRUNC;
		}
		err = skb_copy_datagram_iovec(skb, sizeof(*ddp),
						msg->msg_iov, copied);
	}

	if (!err) {
		if (sat) {
			sat->sat_family      = AF_APPLETALK;
			sat->sat_port        = ddp->deh_sport;
			sat->sat_addr.s_node = ddp->deh_snode;
			sat->sat_addr.s_net  = ddp->deh_snet;
		}
		msg->msg_namelen = sizeof(*sat);
	}

	skb_free_datagram(sk, skb);	/* Free the datagram. */
	return err ? err : copied;
}