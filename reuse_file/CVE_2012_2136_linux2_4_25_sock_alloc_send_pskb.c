
struct sk_buff *CVE_2012_2136_linux2_4_25_sock_alloc_send_pskb(struct sock *sk, unsigned long header_len,
				     unsigned long data_len, int noblock, int *errcode)
{
	struct sk_buff *skb;
	long timeo;
	int err;

	timeo = sock_sndtimeo(sk, noblock);
	while (1) {
		err = sock_error(sk);
		if (err != 0)
			goto failure;

		err = -EPIPE;
		if (sk->shutdown & SEND_SHUTDOWN)
			goto failure;

		if (atomic_read(&sk->wmem_alloc) < sk->sndbuf) {
			skb = alloc_skb(header_len, sk->allocation);
			if (skb) {
				int npages;
				int i;

				/* No pages, we're done... */
				if (!data_len)
					break;

				npages = (data_len + (PAGE_SIZE - 1)) >> PAGE_SHIFT;
				skb->truesize += data_len;
				skb_shinfo(skb)->nr_frags = npages;
				for (i = 0; i < npages; i++) {
					struct page *page;
					skb_frag_t *frag;

					page = alloc_pages(sk->allocation, 0);
					if (!page) {
						err = -ENOBUFS;
						skb_shinfo(skb)->nr_frags = i;
						kfree_skb(skb);
						goto failure;
					}

					frag = &skb_shinfo(skb)->frags[i];
					frag->page = page;
					frag->page_offset = 0;
					frag->size = (data_len >= PAGE_SIZE ?
						      PAGE_SIZE :
						      data_len);
					data_len -= PAGE_SIZE;
				}

				/* Full success... */
				break;
			}
			err = -ENOBUFS;
			goto failure;
		}
		set_bit(SOCK_ASYNC_NOSPACE, &sk->socket->flags);
		set_bit(SOCK_NOSPACE, &sk->socket->flags);
		err = -EAGAIN;
		if (!timeo)
			goto failure;
		if (signal_pending(current))
			goto interrupted;
		timeo = sock_wait_for_wmem(sk, timeo);
	}

	skb_set_owner_w(skb, sk);
	return skb;

interrupted:
	err = sock_intr_errno(timeo);
failure:
	*errcode = err;
	return NULL;
}