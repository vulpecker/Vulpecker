
static int CVE_2013_7267_linux2_6_10_atalk_recvmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg,
			 size_t size, int flags)
{
	struct sock *sk = sock->sk;
	struct sockaddr_at *sat = (struct sockaddr_at *)msg->msg_name;
	struct ddpehdr *ddp;
	int copied = 0;
	int err = 0;
        struct ddpebits ddphv;
	struct sk_buff *skb = skb_recv_datagram(sk, flags & ~MSG_DONTWAIT,
						flags & MSG_DONTWAIT, &err);
	if (!skb)
		return err;

	/* FIXME: use skb->cb to be able to use shared skbs */
	ddp = ddp_hdr(skb);
	*((__u16 *)&ddphv) = ntohs(*((__u16 *)ddp));

	if (sk->sk_type == SOCK_RAW) {
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
	return err ? : copied;
}