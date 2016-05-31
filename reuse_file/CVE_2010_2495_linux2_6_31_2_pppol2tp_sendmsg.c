static int CVE_2010_2495_linux2_6_31_2_pppol2tp_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *m,
			    size_t total_len)
{
	static const unsigned char ppph[2] = { 0xff, 0x03 };
	struct sock *sk = sock->sk;
	struct inet_sock *inet;
	__wsum csum;
	struct sk_buff *skb;
	int error;
	int hdr_len;
	struct pppol2tp_session *session;
	struct pppol2tp_tunnel *tunnel;
	struct udphdr *uh;
	unsigned int len;
	struct sock *sk_tun;
	u16 udp_len;

	error = -ENOTCONN;
	if (sock_flag(sk, SOCK_DEAD) || !(sk->sk_state & PPPOX_CONNECTED))
		goto error;

	/* Get session and tunnel contexts */
	error = -EBADF;
	session = pppol2tp_sock_to_session(sk);
	if (session == NULL)
		goto error;

	sk_tun = session->tunnel_sock;
	tunnel = pppol2tp_sock_to_tunnel(sk_tun);
	if (tunnel == NULL)
		goto error_put_sess;

	/* What header length is configured for this session? */
	hdr_len = pppol2tp_l2tp_header_len(session);

	/* Allocate a socket buffer */
	error = -ENOMEM;
	skb = sock_wmalloc(sk, NET_SKB_PAD + sizeof(struct iphdr) +
			   sizeof(struct udphdr) + hdr_len +
			   sizeof(ppph) + total_len,
			   0, GFP_KERNEL);
	if (!skb)
		goto error_put_sess_tun;

	/* Reserve space for headers. */
	skb_reserve(skb, NET_SKB_PAD);
	skb_reset_network_header(skb);
	skb_reserve(skb, sizeof(struct iphdr));
	skb_reset_transport_header(skb);

	/* Build UDP header */
	inet = inet_sk(sk_tun);
	udp_len = hdr_len + sizeof(ppph) + total_len;
	uh = (struct udphdr *) skb->data;
	uh->source = inet->sport;
	uh->dest = inet->dport;
	uh->len = htons(udp_len);
	uh->check = 0;
	skb_put(skb, sizeof(struct udphdr));

	/* Build L2TP header */
	pppol2tp_build_l2tp_header(session, skb->data);
	skb_put(skb, hdr_len);

	/* Add PPP header */
	skb->data[0] = ppph[0];
	skb->data[1] = ppph[1];
	skb_put(skb, 2);

	/* Copy user data into skb */
	error = memcpy_fromiovec(skb->data, m->msg_iov, total_len);
	if (error < 0) {
		kfree_skb(skb);
		goto error_put_sess_tun;
	}
	skb_put(skb, total_len);

	/* Calculate UDP checksum if configured to do so */
	if (sk_tun->sk_no_check == UDP_CSUM_NOXMIT)
		skb->ip_summed = CHECKSUM_NONE;
	else if (!(skb_dst(skb)->dev->features & NETIF_F_V4_CSUM)) {
		skb->ip_summed = CHECKSUM_COMPLETE;
		csum = skb_checksum(skb, 0, udp_len, 0);
		uh->check = csum_tcpudp_magic(inet->saddr, inet->daddr,
					      udp_len, IPPROTO_UDP, csum);
		if (uh->check == 0)
			uh->check = CSUM_MANGLED_0;
	} else {
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct udphdr, check);
		uh->check = ~csum_tcpudp_magic(inet->saddr, inet->daddr,
					       udp_len, IPPROTO_UDP, 0);
	}

	/* Debug */
	if (session->send_seq)
		PRINTK(session->debug, PPPOL2TP_MSG_DATA, KERN_DEBUG,
		       "%s: send %Zd bytes, ns=%hu\n", session->name,
		       total_len, session->ns - 1);
	else
		PRINTK(session->debug, PPPOL2TP_MSG_DATA, KERN_DEBUG,
		       "%s: send %Zd bytes\n", session->name, total_len);

	if (session->debug & PPPOL2TP_MSG_DATA) {
		int i;
		unsigned char *datap = skb->data;

		printk(KERN_DEBUG "%s: xmit:", session->name);
		for (i = 0; i < total_len; i++) {
			printk(" %02X", *datap++);
			if (i == 15) {
				printk(" ...");
				break;
			}
		}
		printk("\n");
	}

	/* Queue the packet to IP for output */
	len = skb->len;
	error = ip_queue_xmit(skb, 1);

	/* Update stats */
	if (error >= 0) {
		tunnel->stats.tx_packets++;
		tunnel->stats.tx_bytes += len;
		session->stats.tx_packets++;
		session->stats.tx_bytes += len;
	} else {
		tunnel->stats.tx_errors++;
		session->stats.tx_errors++;
	}

	return error;

error_put_sess_tun:
	sock_put(session->tunnel_sock);
error_put_sess:
	sock_put(sk);
error:
	return error;
}