int CVE_2013_2128_linux2_4_25_tcp_read_sock(struct sock *sk, read_descriptor_t *desc,
		  sk_read_actor_t recv_actor)
{
	struct sk_buff *skb;
	struct tcp_opt *tp = &(sk->tp_pinfo.af_tcp);
	u32 seq = tp->copied_seq;
	u32 offset;
	int copied = 0;

	if (sk->state == TCP_LISTEN)
		return -ENOTCONN;
	while ((skb = tcp_recv_skb(sk, seq, &offset)) != NULL) {
		if (offset < skb->len) {
			size_t used, len;

			len = skb->len - offset;
			/* Stop reading if we hit a patch of urgent data */
			if (tp->urg_data) {
				u32 urg_offset = tp->urg_seq - seq;
				if (urg_offset < len)
					len = urg_offset;
				if (!len)
					break;
			}
			used = recv_actor(desc, skb, offset, len);
			if (used <= len) {
				seq += used;
				copied += used;
				offset += used;
			}
			if (offset != skb->len)
				break;
		}
		if (skb->h.th->fin) {
			tcp_eat_skb(sk, skb);
			++seq;
			break;
		}
		tcp_eat_skb(sk, skb);
		if (!desc->count)
			break;
	}
	tp->copied_seq = seq;
	/* Clean up data we have read: This will do ACK frames. */
	if (copied)
		cleanup_rbuf(sk, copied);
	return copied;
}