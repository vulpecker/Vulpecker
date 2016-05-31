
static int CVE_2013_7269_linux2_4_25_nr_recvmsg(struct socket *sock, struct msghdr *msg, int size, 
	int flags, struct scm_cookie *scm)
{
	struct sock *sk = sock->sk;
	struct sockaddr_ax25 *sax = (struct sockaddr_ax25 *)msg->msg_name;
	int copied;
	struct sk_buff *skb;
	int er;

	/*
	 * This works for seqpacket too. The receiver has ordered the queue for
	 * us! We do one quick check first though
	 */

	if (sk->state != TCP_ESTABLISHED)
		return -ENOTCONN;

	/* Now we can treat all alike */
	if ((skb = skb_recv_datagram(sk, flags & ~MSG_DONTWAIT, flags & MSG_DONTWAIT, &er)) == NULL)
		return er;

	skb->h.raw = skb->data;
	copied     = skb->len;

	if (copied > size) {
		copied = size;
		msg->msg_flags |= MSG_TRUNC;
	}

	skb_copy_datagram_iovec(skb, 0, msg->msg_iov, copied);

	if (sax != NULL) {
		sax->sax25_family = AF_NETROM;
		memcpy(sax->sax25_call.ax25_call, skb->data + 7, AX25_ADDR_LEN);
	}

	msg->msg_namelen = sizeof(*sax);

	skb_free_datagram(sk, skb);

	return copied;
}