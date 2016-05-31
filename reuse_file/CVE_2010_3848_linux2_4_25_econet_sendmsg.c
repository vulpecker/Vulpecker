
static int CVE_2010_3848_linux2_4_25_econet_sendmsg(struct socket *sock, struct msghdr *msg, int len,
			  struct scm_cookie *scm)
{
	struct sock *sk = sock->sk;
	struct sockaddr_ec *saddr=(struct sockaddr_ec *)msg->msg_name;
	struct net_device *dev;
	struct ec_addr addr;
	int err;
	unsigned char port, cb;
	struct sk_buff *skb;
	struct ec_cb *eb;
#ifdef CONFIG_ECONET_NATIVE
	unsigned short proto = 0;
#endif
#ifdef CONFIG_ECONET_AUNUDP
	struct msghdr udpmsg;
	struct iovec iov[msg->msg_iovlen+1];
	struct aunhdr ah;
	struct sockaddr_in udpdest;
	__kernel_size_t size;
	int i;
	mm_segment_t oldfs;
#endif
		
	/*
	 *	Check the flags. 
	 */

	if (msg->msg_flags&~MSG_DONTWAIT) 
		return(-EINVAL);

	/*
	 *	Get and verify the address. 
	 */
	 
	if (saddr == NULL) {
		addr.station = sk->protinfo.af_econet->station;
		addr.net = sk->protinfo.af_econet->net;
		port = sk->protinfo.af_econet->port;
		cb = sk->protinfo.af_econet->cb;
	} else {
		if (msg->msg_namelen < sizeof(struct sockaddr_ec)) 
			return -EINVAL;
		addr.station = saddr->addr.station;
		addr.net = saddr->addr.net;
		port = saddr->port;
		cb = saddr->cb;
	}

	/* Look for a device with the right network number. */
	dev = net2dev_map[addr.net];

	/* If not directly reachable, use some default */
	if (dev == NULL)
	{
		dev = net2dev_map[0];
		/* No interfaces at all? */
		if (dev == NULL)
			return -ENETDOWN;
	}

	if (dev->type == ARPHRD_ECONET)
	{
		/* Real hardware Econet.  We're not worthy etc. */
#ifdef CONFIG_ECONET_NATIVE
		atomic_inc(&dev->refcnt);
		
		skb = sock_alloc_send_skb(sk, len+dev->hard_header_len+15, 
					  msg->msg_flags & MSG_DONTWAIT, &err);
		if (skb==NULL)
			goto out_unlock;
		
		skb_reserve(skb, (dev->hard_header_len+15)&~15);
		skb->nh.raw = skb->data;
		
		eb = (struct ec_cb *)&skb->cb;
		
		/* BUG: saddr may be NULL */
		eb->cookie = saddr->cookie;
		eb->sec = *saddr;
		eb->sent = ec_tx_done;

		if (dev->hard_header) {
			int res;
			struct ec_framehdr *fh;
			err = -EINVAL;
			res = dev->hard_header(skb, dev, ntohs(proto), 
					       &addr, NULL, len);
			/* Poke in our control byte and
			   port number.  Hack, hack.  */
			fh = (struct ec_framehdr *)(skb->data);
			fh->cb = cb;
			fh->port = port;
			if (sock->type != SOCK_DGRAM) {
				skb->tail = skb->data;
				skb->len = 0;
			} else if (res < 0)
				goto out_free;
		}
		
		/* Copy the data. Returns -EFAULT on error */
		err = memcpy_fromiovec(skb_put(skb,len), msg->msg_iov, len);
		skb->protocol = proto;
		skb->dev = dev;
		skb->priority = sk->priority;
		if (err)
			goto out_free;
		
		err = -ENETDOWN;
		if (!(dev->flags & IFF_UP))
			goto out_free;
		
		/*
		 *	Now send it
		 */
		
		dev_queue_xmit(skb);
		dev_put(dev);
		return(len);

	out_free:
		kfree_skb(skb);
	out_unlock:
		if (dev)
			dev_put(dev);
#else
		err = -EPROTOTYPE;
#endif
		return err;
	}

#ifdef CONFIG_ECONET_AUNUDP
	/* AUN virtual Econet. */

	if (udpsock == NULL)
		return -ENETDOWN;		/* No socket - can't send */
	
	/* Make up a UDP datagram and hand it off to some higher intellect. */

	memset(&udpdest, 0, sizeof(udpdest));
	udpdest.sin_family = AF_INET;
	udpdest.sin_port = htons(AUN_PORT);

	/* At the moment we use the stupid Acorn scheme of Econet address
	   y.x maps to IP a.b.c.x.  This should be replaced with something
	   more flexible and more aware of subnet masks.  */
	{
		struct in_device *idev = in_dev_get(dev);
		unsigned long network = 0;
		if (idev) {
			read_lock(&idev->lock);
			if (idev->ifa_list)
				network = ntohl(idev->ifa_list->ifa_address) & 
					0xffffff00;		/* !!! */
			read_unlock(&idev->lock);
			in_dev_put(idev);
		}
		udpdest.sin_addr.s_addr = htonl(network | addr.station);
	}

	ah.port = port;
	ah.cb = cb & 0x7f;
	ah.code = 2;		/* magic */
	ah.pad = 0;

	/* tack our header on the front of the iovec */
	size = sizeof(struct aunhdr);
	iov[0].iov_base = (void *)&ah;
	iov[0].iov_len = size;
	for (i = 0; i < msg->msg_iovlen; i++) {
		void *base = msg->msg_iov[i].iov_base;
		size_t len = msg->msg_iov[i].iov_len;
		/* Check it now since we switch to KERNEL_DS later. */
		if ((err = verify_area(VERIFY_READ, base, len)) < 0)
			return err;
		iov[i+1].iov_base = base;
		iov[i+1].iov_len = len;
		size += len;
	}

	/* Get a skbuff (no data, just holds our cb information) */
	if ((skb = sock_alloc_send_skb(sk, 0, 
			     msg->msg_flags & MSG_DONTWAIT, &err)) == NULL)
		return err;

	eb = (struct ec_cb *)&skb->cb;

	eb->cookie = saddr->cookie;
	eb->timeout = (5*HZ);
	eb->start = jiffies;
	ah.handle = aun_seq;
	eb->seq = (aun_seq++);
	eb->sec = *saddr;

	skb_queue_tail(&aun_queue, skb);

	udpmsg.msg_name = (void *)&udpdest;
	udpmsg.msg_namelen = sizeof(udpdest);
	udpmsg.msg_iov = &iov[0];
	udpmsg.msg_iovlen = msg->msg_iovlen + 1;
	udpmsg.msg_control = NULL;
	udpmsg.msg_controllen = 0;
	udpmsg.msg_flags=0;

	oldfs = get_fs(); set_fs(KERNEL_DS);	/* More privs :-) */
	err = sock_sendmsg(udpsock, &udpmsg, size);
	set_fs(oldfs);
#else
	err = -EPROTOTYPE;
#endif
	return err;
}