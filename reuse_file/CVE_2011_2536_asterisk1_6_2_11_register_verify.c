static enum check_auth_result CVE_2011_2536_asterisk1_6_2_11_register_verify(struct sip_pvt *p, struct sockaddr_in *sin,
					      struct sip_request *req, char *uri)
{
	enum check_auth_result res = AUTH_NOT_FOUND;
	struct sip_peer *peer;
	char tmp[256];
	char *name, *c;
	char *domain;

	terminate_uri(uri);	/* warning, overwrite the string */

	ast_copy_string(tmp, get_header(req, "To"), sizeof(tmp));
	if (sip_cfg.pedanticsipchecking)
		ast_uri_decode(tmp);

	c = get_in_brackets(tmp);
	c = remove_uri_parameters(c);

	if (!strncasecmp(c, "sip:", 4)) {
		name = c + 4;
	} else if (!strncasecmp(c, "sips:", 5)) {
		name = c + 5;
	} else {
		name = c;
		ast_log(LOG_NOTICE, "Invalid to address: '%s' from %s (missing sip:) trying to use anyway...\n", c, ast_inet_ntoa(sin->sin_addr));
	}

	/*! \todo XXX here too we interpret a missing @domain as a name-only
	 * URI, whereas the RFC says this is a domain-only uri.
	 */
	/* Strip off the domain name */
	if ((c = strchr(name, '@'))) {
		*c++ = '\0';
		domain = c;
		if ((c = strchr(domain, ':')))	/* Remove :port */
			*c = '\0';
		if (!AST_LIST_EMPTY(&domain_list)) {
			if (!check_sip_domain(domain, NULL, 0)) {
				transmit_response(p, "404 Not found (unknown domain)", &p->initreq);
				return AUTH_UNKNOWN_DOMAIN;
			}
		}
	}
	c = strchr(name, ';');	/* Remove any Username parameters */
	if (c)
		*c = '\0';

	ast_string_field_set(p, exten, name);
	build_contact(p);
	if (req->ignore) {
		/* Expires is a special case, where we only want to load the peer if this isn't a deregistration attempt */
		const char *expires = get_header(req, "Expires");
		int expire = atoi(expires);

		if (ast_strlen_zero(expires)) { /* No expires header; look in Contact */
			if ((expires = strcasestr(get_header(req, "Contact"), ";expires="))) {
				expire = atoi(expires + 9);
			}
		}
		if (!ast_strlen_zero(expires) && expire == 0) {
			transmit_response_with_date(p, "200 OK", req);
			return 0;
		}
	}
	peer = find_peer(name, NULL, TRUE, FINDPEERS, FALSE, 0);
	if (!(peer && ast_apply_ha(peer->ha, sin))) {
		/* Peer fails ACL check */
		if (peer) {
			unref_peer(peer, "CVE_2011_2536_asterisk1_6_2_11_register_verify: unref_peer: from find_peer operation");
			peer = NULL;
			res = AUTH_ACL_FAILED;
		} else
			res = AUTH_NOT_FOUND;
	}

	if (peer) {
		/*! \todo OEJ Remove this - there's never RTP in a REGISTER dialog... */
		/* Set Frame packetization */
		if (p->rtp) {
			ast_rtp_codec_setpref(p->rtp, &peer->prefs);
			p->autoframing = peer->autoframing;
		}
		if (!peer->host_dynamic) {
			ast_log(LOG_ERROR, "Peer '%s' is trying to register, but not configured as host=dynamic\n", peer->name);
			res = AUTH_PEER_NOT_DYNAMIC;
		} else {
			ast_copy_flags(&p->flags[0], &peer->flags[0], SIP_NAT);
			if (ast_test_flag(&p->flags[1], SIP_PAGE2_REGISTERTRYING))
				transmit_response(p, "100 Trying", req);
			if (!(res = check_auth(p, req, peer->name, peer->secret, peer->md5secret, SIP_REGISTER, uri, XMIT_UNRELIABLE, req->ignore))) {
				if (sip_cancel_destroy(p))
					ast_log(LOG_WARNING, "Unable to cancel SIP destruction.  Expect bad things.\n");

				if (check_request_transport(peer, req)) {
					ast_set_flag(&p->flags[0], SIP_PENDINGBYE);
					transmit_response_with_date(p, "403 Forbidden", req);
					res = AUTH_BAD_TRANSPORT;
				} else {

					/* We have a successful registration attempt with proper authentication,
				   	now, update the peer */
					switch (parse_register_contact(p, peer, req)) {
					case PARSE_REGISTER_DENIED:
						ast_log(LOG_WARNING, "Registration denied because of contact ACL\n");
						transmit_response_with_date(p, "603 Denied", req);
						peer->lastmsgssent = -1;
						res = 0;
						break;
					case PARSE_REGISTER_FAILED:
						ast_log(LOG_WARNING, "Failed to parse contact info\n");
						transmit_response_with_date(p, "400 Bad Request", req);
						peer->lastmsgssent = -1;
						res = 0;
						break;
					case PARSE_REGISTER_QUERY:
						ast_string_field_set(p, fullcontact, peer->fullcontact);
						transmit_response_with_date(p, "200 OK", req);
						peer->lastmsgssent = -1;
						res = 0;
						break;
					case PARSE_REGISTER_UPDATE:
						ast_string_field_set(p, fullcontact, peer->fullcontact);
						update_peer(peer, p->expiry);
						/* Say OK and ask subsystem to retransmit msg counter */
						transmit_response_with_date(p, "200 OK", req);
						if (!ast_test_flag((&peer->flags[1]), SIP_PAGE2_SUBSCRIBEMWIONLY))
							peer->lastmsgssent = -1;
						res = 0;
						break;
					}
				}

			} 
		}
	}
	if (!peer && sip_cfg.autocreatepeer) {
		/* Create peer if we have autocreate mode enabled */
		peer = temp_peer(name);
		if (peer) {
			ao2_t_link(peers, peer, "link peer into peer table");
			if (peer->addr.sin_addr.s_addr) {
				ao2_t_link(peers_by_ip, peer, "link peer into peers-by-ip table");
			}
			
			if (sip_cancel_destroy(p))
				ast_log(LOG_WARNING, "Unable to cancel SIP destruction.  Expect bad things.\n");
			switch (parse_register_contact(p, peer, req)) {
			case PARSE_REGISTER_DENIED:
				ast_log(LOG_WARNING, "Registration denied because of contact ACL\n");
				transmit_response_with_date(p, "403 Forbidden (ACL)", req);
				peer->lastmsgssent = -1;
				res = 0;
				break;
			case PARSE_REGISTER_FAILED:
				ast_log(LOG_WARNING, "Failed to parse contact info\n");
				transmit_response_with_date(p, "400 Bad Request", req);
				peer->lastmsgssent = -1;
				res = 0;
				break;
			case PARSE_REGISTER_QUERY:
				ast_string_field_set(p, fullcontact, peer->fullcontact);
				transmit_response_with_date(p, "200 OK", req);
				peer->lastmsgssent = -1;
				res = 0;
				break;
			case PARSE_REGISTER_UPDATE:
				ast_string_field_set(p, fullcontact, peer->fullcontact);
				/* Say OK and ask subsystem to retransmit msg counter */
				transmit_response_with_date(p, "200 OK", req);
				manager_event(EVENT_FLAG_SYSTEM, "PeerStatus", "ChannelType: SIP\r\nPeer: SIP/%s\r\nPeerStatus: Registered\r\nAddress: %s\r\nPort: %d\r\n", peer->name, ast_inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));
				peer->lastmsgssent = -1;
				res = 0;
				break;
			}
		}
	}
	if (!peer && sip_cfg.alwaysauthreject) {
		/* If we found a peer, we transmit a 100 Trying.  Therefore, if we're
		 * trying to avoid leaking information, we MUST also transmit the same
		 * response when we DON'T find a peer. */
		transmit_response(p, "100 Trying", req);
		/* Insert a fake delay between the 100 and the subsequent failure. */
		sched_yield();
	}
	if (!res) {
		ast_devstate_changed(AST_DEVICE_UNKNOWN, "SIP/%s", peer->name);
	}
	if (res < 0) {
		switch (res) {
		case AUTH_SECRET_FAILED:
			/* Wrong password in authentication. Go away, don't try again until you fixed it */
			transmit_response(p, "403 Forbidden (Bad auth)", &p->initreq);
			if (global_authfailureevents)
				manager_event(EVENT_FLAG_SYSTEM, "PeerStatus", "ChannelType: SIP\r\nPeer: SIP/%s\r\nPeerStatus: Rejected\r\nCause: AUTH_SECRET_FAILED\r\nAddress: %s\r\nPort: %d\r\n", 
					name, ast_inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));
			break;
		case AUTH_USERNAME_MISMATCH:
			/* Username and digest username does not match.
			   Asterisk uses the From: username for authentication. We need the
			   devices to use the same authentication user name until we support
			   proper authentication by digest auth name */
		case AUTH_NOT_FOUND:
		case AUTH_PEER_NOT_DYNAMIC:
		case AUTH_ACL_FAILED:
			if (sip_cfg.alwaysauthreject) {
				transmit_fake_auth_response(p, SIP_REGISTER, &p->initreq, XMIT_UNRELIABLE);
				if (global_authfailureevents) {
					manager_event(EVENT_FLAG_SYSTEM, "PeerStatus", "ChannelType: SIP\r\nPeer: SIP/%s\r\nPeerStatus: Rejected\r\nCause: %s\r\nAddress: %s\r\nPort: %d\r\n",
						name, res == AUTH_PEER_NOT_DYNAMIC ? "AUTH_PEER_NOT_DYNAMIC" : "URI_NOT_FOUND",
						ast_inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));
				}
			} else {
				/* URI not found */
				if (res == AUTH_PEER_NOT_DYNAMIC) {
					transmit_response(p, "403 Forbidden", &p->initreq);
					if (global_authfailureevents) {
						manager_event(EVENT_FLAG_SYSTEM, "PeerStatus",
							"ChannelType: SIP\r\n"
							"Peer: SIP/%s\r\n"
							"PeerStatus: Rejected\r\n"
							"Cause: AUTH_PEER_NOT_DYNAMIC\r\n"
							"Address: %s\r\n"
							"Port: %d\r\n",
							name, ast_inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));
					}
				} else {
					transmit_response(p, "404 Not found", &p->initreq);
					if (global_authfailureevents) {
						manager_event(EVENT_FLAG_SYSTEM, "PeerStatus",
							"ChannelType: SIP\r\n"
							"Peer: SIP/%s\r\n"
							"PeerStatus: Rejected\r\n"
							"Cause: %s\r\n"
							"Address: %s\r\n"
							"Port: %d\r\n",
							name,
							(res == AUTH_USERNAME_MISMATCH) ? "AUTH_USERNAME_MISMATCH" : "URI_NOT_FOUND",
							ast_inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));
					}
				}
			}
			break;
		case AUTH_BAD_TRANSPORT:
		default:
			break;
		}
	}
	if (peer)
		unref_peer(peer, "CVE_2011_2536_asterisk1_6_2_11_register_verify: unref_peer: tossing stack peer pointer at end of func");

	return res;
}