static int CVE_2013_3228_linux2_4_25_irda_recvmsg_dgram(struct socket *sock, struct msghdr *msg, 
			      int size, int flags, struct scm_cookie *scm)
{
	struct irda_sock *self;
	struct sock *sk = sock->sk;
	struct sk_buff *skb;
	int copied, err;

	IRDA_DEBUG(4, "%s()\n", __FUNCTION__);

	self = sk->protinfo.irda;
	ASSERT(self != NULL, return -1;);

	skb = skb_recv_datagram(sk, flags & ~MSG_DONTWAIT, 
				flags & MSG_DONTWAIT, &err);
	if (!skb)
		return err;

	skb->h.raw = skb->data;
	copied     = skb->len;
	
	if (copied > size) {
		IRDA_DEBUG(2, "%s(), Received truncated frame (%d < %d)!\n", __FUNCTION__,
			   copied, size);
		copied = size;
		msg->msg_flags |= MSG_TRUNC;
	}
	skb_copy_datagram_iovec(skb, 0, msg->msg_iov, copied);

	skb_free_datagram(sk, skb);

	/*
	 *  Check if we have previously stopped IrTTP and we know
	 *  have more free space in our rx_queue. If so tell IrTTP
	 *  to start delivering frames again before our rx_queue gets
	 *  empty
	 */
	if (self->rx_flow == FLOW_STOP) {
		if ((atomic_read(&sk->rmem_alloc) << 2) <= sk->rcvbuf) {
			IRDA_DEBUG(2, "%s(), Starting IrTTP\n", __FUNCTION__);
			self->rx_flow = FLOW_START;
			irttp_flow_request(self->tsap, FLOW_START);
		}
	}

	return copied;
}