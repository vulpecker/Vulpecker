
static void CVE_2015_2922_linux3_3_6_ndisc_router_discovery(struct sk_buff *skb)
{
	struct ra_msg *ra_msg = (struct ra_msg *)skb_transport_header(skb);
	struct neighbour *neigh = NULL;
	struct inet6_dev *in6_dev;
	struct rt6_info *rt = NULL;
	int lifetime;
	struct ndisc_options ndopts;
	int optlen;
	unsigned int pref = 0;

	__u8 * opt = (__u8 *)(ra_msg + 1);

	optlen = (skb->tail - skb->transport_header) - sizeof(struct ra_msg);

	if (!(ipv6_addr_type(&ipv6_hdr(skb)->saddr) & IPV6_ADDR_LINKLOCAL)) {
		ND_PRINTK2(KERN_WARNING
			   "ICMPv6 RA: source address is not link-local.\n");
		return;
	}
	if (optlen < 0) {
		ND_PRINTK2(KERN_WARNING
			   "ICMPv6 RA: packet too short\n");
		return;
	}

#ifdef CONFIG_IPV6_NDISC_NODETYPE
	if (skb->ndisc_nodetype == NDISC_NODETYPE_HOST) {
		ND_PRINTK2(KERN_WARNING
			   "ICMPv6 RA: from host or unauthorized router\n");
		return;
	}
#endif

	/*
	 *	set the RA_RECV flag in the interface
	 */

	in6_dev = __in6_dev_get(skb->dev);
	if (in6_dev == NULL) {
		ND_PRINTK0(KERN_ERR
			   "ICMPv6 RA: can't find inet6 device for %s.\n",
			   skb->dev->name);
		return;
	}

	if (!ndisc_parse_options(opt, optlen, &ndopts)) {
		ND_PRINTK2(KERN_WARNING
			   "ICMP6 RA: invalid ND options\n");
		return;
	}

	if (!accept_ra(in6_dev))
		goto skip_linkparms;

#ifdef CONFIG_IPV6_NDISC_NODETYPE
	/* skip link-specific parameters from interior routers */
	if (skb->ndisc_nodetype == NDISC_NODETYPE_NODEFAULT)
		goto skip_linkparms;
#endif

	if (in6_dev->if_flags & IF_RS_SENT) {
		/*
		 *	flag that an RA was received after an RS was sent
		 *	out on this interface.
		 */
		in6_dev->if_flags |= IF_RA_RCVD;
	}

	/*
	 * Remember the managed/otherconf flags from most recently
	 * received RA message (RFC 2462) -- yoshfuji
	 */
	in6_dev->if_flags = (in6_dev->if_flags & ~(IF_RA_MANAGED |
				IF_RA_OTHERCONF)) |
				(ra_msg->icmph.icmp6_addrconf_managed ?
					IF_RA_MANAGED : 0) |
				(ra_msg->icmph.icmp6_addrconf_other ?
					IF_RA_OTHERCONF : 0);

	if (!in6_dev->cnf.accept_ra_defrtr)
		goto skip_defrtr;

	if (ipv6_chk_addr(dev_net(in6_dev->dev), &ipv6_hdr(skb)->saddr, NULL, 0))
		goto skip_defrtr;

	lifetime = ntohs(ra_msg->icmph.icmp6_rt_lifetime);

#ifdef CONFIG_IPV6_ROUTER_PREF
	pref = ra_msg->icmph.icmp6_router_pref;
	/* 10b is handled as if it were 00b (medium) */
	if (pref == ICMPV6_ROUTER_PREF_INVALID ||
	    !in6_dev->cnf.accept_ra_rtr_pref)
		pref = ICMPV6_ROUTER_PREF_MEDIUM;
#endif

	rt = rt6_get_dflt_router(&ipv6_hdr(skb)->saddr, skb->dev);

	if (rt)
		neigh = dst_get_neighbour_noref(&rt->dst);

	if (rt && lifetime == 0) {
		neigh_clone(neigh);
		ip6_del_rt(rt);
		rt = NULL;
	}

	if (rt == NULL && lifetime) {
		ND_PRINTK3(KERN_DEBUG
			   "ICMPv6 RA: adding default router.\n");

		rt = rt6_add_dflt_router(&ipv6_hdr(skb)->saddr, skb->dev, pref);
		if (rt == NULL) {
			ND_PRINTK0(KERN_ERR
				   "ICMPv6 RA: %s() failed to add default route.\n",
				   __func__);
			return;
		}

		neigh = dst_get_neighbour_noref(&rt->dst);
		if (neigh == NULL) {
			ND_PRINTK0(KERN_ERR
				   "ICMPv6 RA: %s() got default router without neighbour.\n",
				   __func__);
			dst_release(&rt->dst);
			return;
		}
		neigh->flags |= NTF_ROUTER;
	} else if (rt) {
		rt->rt6i_flags = (rt->rt6i_flags & ~RTF_PREF_MASK) | RTF_PREF(pref);
	}

	if (rt)
		rt->dst.expires = jiffies + (HZ * lifetime);

	if (ra_msg->icmph.icmp6_hop_limit) {
		in6_dev->cnf.hop_limit = ra_msg->icmph.icmp6_hop_limit;
		if (rt)
			dst_metric_set(&rt->dst, RTAX_HOPLIMIT,
				       ra_msg->icmph.icmp6_hop_limit);
	}

skip_defrtr:

	/*
	 *	Update Reachable Time and Retrans Timer
	 */

	if (in6_dev->nd_parms) {
		unsigned long rtime = ntohl(ra_msg->retrans_timer);

		if (rtime && rtime/1000 < MAX_SCHEDULE_TIMEOUT/HZ) {
			rtime = (rtime*HZ)/1000;
			if (rtime < HZ/10)
				rtime = HZ/10;
			in6_dev->nd_parms->retrans_time = rtime;
			in6_dev->tstamp = jiffies;
			inet6_ifinfo_notify(RTM_NEWLINK, in6_dev);
		}

		rtime = ntohl(ra_msg->reachable_time);
		if (rtime && rtime/1000 < MAX_SCHEDULE_TIMEOUT/(3*HZ)) {
			rtime = (rtime*HZ)/1000;

			if (rtime < HZ/10)
				rtime = HZ/10;

			if (rtime != in6_dev->nd_parms->base_reachable_time) {
				in6_dev->nd_parms->base_reachable_time = rtime;
				in6_dev->nd_parms->gc_staletime = 3 * rtime;
				in6_dev->nd_parms->reachable_time = neigh_rand_reach_time(rtime);
				in6_dev->tstamp = jiffies;
				inet6_ifinfo_notify(RTM_NEWLINK, in6_dev);
			}
		}
	}

skip_linkparms:

	/*
	 *	Process options.
	 */

	if (!neigh)
		neigh = __neigh_lookup(&nd_tbl, &ipv6_hdr(skb)->saddr,
				       skb->dev, 1);
	if (neigh) {
		u8 *lladdr = NULL;
		if (ndopts.nd_opts_src_lladdr) {
			lladdr = ndisc_opt_addr_data(ndopts.nd_opts_src_lladdr,
						     skb->dev);
			if (!lladdr) {
				ND_PRINTK2(KERN_WARNING
					   "ICMPv6 RA: invalid link-layer address length\n");
				goto out;
			}
		}
		neigh_update(neigh, lladdr, NUD_STALE,
			     NEIGH_UPDATE_F_WEAK_OVERRIDE|
			     NEIGH_UPDATE_F_OVERRIDE|
			     NEIGH_UPDATE_F_OVERRIDE_ISROUTER|
			     NEIGH_UPDATE_F_ISROUTER);
	}

	if (!accept_ra(in6_dev))
		goto out;

#ifdef CONFIG_IPV6_ROUTE_INFO
	if (ipv6_chk_addr(dev_net(in6_dev->dev), &ipv6_hdr(skb)->saddr, NULL, 0))
		goto skip_routeinfo;

	if (in6_dev->cnf.accept_ra_rtr_pref && ndopts.nd_opts_ri) {
		struct nd_opt_hdr *p;
		for (p = ndopts.nd_opts_ri;
		     p;
		     p = ndisc_next_option(p, ndopts.nd_opts_ri_end)) {
			struct route_info *ri = (struct route_info *)p;
#ifdef CONFIG_IPV6_NDISC_NODETYPE
			if (skb->ndisc_nodetype == NDISC_NODETYPE_NODEFAULT &&
			    ri->prefix_len == 0)
				continue;
#endif
			if (ri->prefix_len > in6_dev->cnf.accept_ra_rt_info_max_plen)
				continue;
			rt6_route_rcv(skb->dev, (u8*)p, (p->nd_opt_len) << 3,
				      &ipv6_hdr(skb)->saddr);
		}
	}

skip_routeinfo:
#endif

#ifdef CONFIG_IPV6_NDISC_NODETYPE
	/* skip link-specific ndopts from interior routers */
	if (skb->ndisc_nodetype == NDISC_NODETYPE_NODEFAULT)
		goto out;
#endif

	if (in6_dev->cnf.accept_ra_pinfo && ndopts.nd_opts_pi) {
		struct nd_opt_hdr *p;
		for (p = ndopts.nd_opts_pi;
		     p;
		     p = ndisc_next_option(p, ndopts.nd_opts_pi_end)) {
			addrconf_prefix_rcv(skb->dev, (u8 *)p,
					    (p->nd_opt_len) << 3,
					    ndopts.nd_opts_src_lladdr != NULL);
		}
	}

	if (ndopts.nd_opts_mtu) {
		__be32 n;
		u32 mtu;

		memcpy(&n, ((u8*)(ndopts.nd_opts_mtu+1))+2, sizeof(mtu));
		mtu = ntohl(n);

		if (mtu < IPV6_MIN_MTU || mtu > skb->dev->mtu) {
			ND_PRINTK2(KERN_WARNING
				   "ICMPv6 RA: invalid mtu: %d\n",
				   mtu);
		} else if (in6_dev->cnf.mtu6 != mtu) {
			in6_dev->cnf.mtu6 = mtu;

			if (rt)
				dst_metric_set(&rt->dst, RTAX_MTU, mtu);

			rt6_mtu_change(skb->dev, mtu);
		}
	}

	if (ndopts.nd_useropts) {
		struct nd_opt_hdr *p;
		for (p = ndopts.nd_useropts;
		     p;
		     p = ndisc_next_useropt(p, ndopts.nd_useropts_end)) {
			ndisc_ra_useropt(skb, p);
		}
	}

	if (ndopts.nd_opts_tgt_lladdr || ndopts.nd_opts_rh) {
		ND_PRINTK2(KERN_WARNING
			   "ICMPv6 RA: invalid RA options");
	}
out:
	if (rt)
		dst_release(&rt->dst);
	else if (neigh)
		neigh_release(neigh);
}