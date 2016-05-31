static int CVE_2008_2826_linux2_6_16_sctp_getsockopt_local_addrs_old(struct sock *sk, int len,
					   char __user *optval, int __user *optlen)
{
	struct sctp_bind_addr *bp;
	struct sctp_association *asoc;
	struct list_head *pos;
	int cnt = 0;
	struct sctp_getaddrs_old getaddrs;
	struct sctp_sockaddr_entry *addr;
	void __user *to;
	union sctp_addr temp;
	struct sctp_sock *sp = sctp_sk(sk);
	int addrlen;
	rwlock_t *addr_lock;
	int err = 0;

	if (len != sizeof(struct sctp_getaddrs_old))
		return -EINVAL;

	if (copy_from_user(&getaddrs, optval, sizeof(struct sctp_getaddrs_old)))
		return -EFAULT;

	if (getaddrs.addr_num <= 0) return -EINVAL;
	/*
	 *  For UDP-style sockets, id specifies the association to query.
	 *  If the id field is set to the value '0' then the locally bound
	 *  addresses are returned without regard to any particular
	 *  association.
	 */
	if (0 == getaddrs.assoc_id) {
		bp = &sctp_sk(sk)->ep->base.bind_addr;
		addr_lock = &sctp_sk(sk)->ep->base.addr_lock;
	} else {
		asoc = sctp_id2assoc(sk, getaddrs.assoc_id);
		if (!asoc)
			return -EINVAL;
		bp = &asoc->base.bind_addr;
		addr_lock = &asoc->base.addr_lock;
	}

	to = getaddrs.addrs;

	sctp_read_lock(addr_lock);

	/* If the endpoint is bound to 0.0.0.0 or ::0, get the valid
	 * addresses from the global local address list.
	 */
	if (sctp_list_single_entry(&bp->address_list)) {
		addr = list_entry(bp->address_list.next,
				  struct sctp_sockaddr_entry, list);
		if (sctp_is_any(&addr->a)) {
			cnt = sctp_copy_laddrs_to_user_old(sk, bp->port,
							   getaddrs.addr_num,
							   to);
			if (cnt < 0) {
				err = cnt;
				goto unlock;
			}
			goto copy_getaddrs;		
		}
	}

	list_for_each(pos, &bp->address_list) {
		addr = list_entry(pos, struct sctp_sockaddr_entry, list);
		memcpy(&temp, &addr->a, sizeof(temp));
		sctp_get_pf_specific(sk->sk_family)->addr_v4map(sp, &temp);
		addrlen = sctp_get_af_specific(temp.sa.sa_family)->sockaddr_len;
		temp.v4.sin_port = htons(temp.v4.sin_port);
		if (copy_to_user(to, &temp, addrlen)) {
			err = -EFAULT;
			goto unlock;
		}
		to += addrlen;
		cnt ++;
		if (cnt >= getaddrs.addr_num) break;
	}

copy_getaddrs:
	getaddrs.addr_num = cnt;
	if (copy_to_user(optval, &getaddrs, sizeof(struct sctp_getaddrs_old)))
		err = -EFAULT;

unlock:
	sctp_read_unlock(addr_lock);
	return err;
}