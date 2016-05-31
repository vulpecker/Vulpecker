
int CVE_2012_5532_linux3_2_25_main(void)
{
	int fd, len, sock_opt;
	int error;
	struct cn_msg *message;
	struct pollfd pfd;
	struct nlmsghdr *incoming_msg;
	struct cn_msg	*incoming_cn_msg;
	struct hv_ku_msg *hv_msg;
	char	*p;
	char	*key_value;
	char	*key_name;

	daemon(1, 0);
	openlog("KVP", 0, LOG_USER);
	syslog(LOG_INFO, "KVP starting; pid is:%d", getpid());
	/*
	 * Retrieve OS release information.
	 */
	kvp_get_os_info();

	fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
	if (fd < 0) {
		syslog(LOG_ERR, "netlink socket creation failed; error:%d", fd);
		exit(-1);
	}
	addr.nl_family = AF_NETLINK;
	addr.nl_pad = 0;
	addr.nl_pid = 0;
	addr.nl_groups = CN_KVP_IDX;


	error = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (error < 0) {
		syslog(LOG_ERR, "bind failed; error:%d", error);
		close(fd);
		exit(-1);
	}
	sock_opt = addr.nl_groups;
	setsockopt(fd, 270, 1, &sock_opt, sizeof(sock_opt));
	/*
	 * Register ourselves with the kernel.
	 */
	message = (struct cn_msg *)kvp_send_buffer;
	message->id.idx = CN_KVP_IDX;
	message->id.val = CN_KVP_VAL;
	message->seq = KVP_REGISTER;
	message->ack = 0;
	message->len = 0;

	len = netlink_send(fd, message);
	if (len < 0) {
		syslog(LOG_ERR, "netlink_send failed; error:%d", len);
		close(fd);
		exit(-1);
	}

	pfd.fd = fd;

	while (1) {
		struct sockaddr *addr_p = (struct sockaddr *) &addr;
		socklen_t addr_l = sizeof(addr);
		pfd.events = POLLIN;
		pfd.revents = 0;
		poll(&pfd, 1, -1);

		len = recvfrom(fd, kvp_recv_buffer, sizeof(kvp_recv_buffer), 0,
				addr_p, &addr_l);

		if (len < 0 || addr.nl_pid) {
			syslog(LOG_ERR, "recvfrom failed; pid:%u error:%d %s",
					addr.nl_pid, errno, strerror(errno));
			close(fd);
			return -1;
		}

		incoming_msg = (struct nlmsghdr *)kvp_recv_buffer;
		incoming_cn_msg = (struct cn_msg *)NLMSG_DATA(incoming_msg);

		switch (incoming_cn_msg->seq) {
		case KVP_REGISTER:
			/*
			 * Driver is registering with us; stash away the version
			 * information.
			 */
			p = (char *)incoming_cn_msg->data;
			lic_version = malloc(strlen(p) + 1);
			if (lic_version) {
				strcpy(lic_version, p);
				syslog(LOG_INFO, "KVP LIC Version: %s",
					lic_version);
			} else {
				syslog(LOG_ERR, "malloc failed");
			}
			continue;

		case KVP_KERNEL_GET:
			break;
		default:
			continue;
		}

		hv_msg = (struct hv_ku_msg *)incoming_cn_msg->data;
		key_name = (char *)hv_msg->kvp_key;
		key_value = (char *)hv_msg->kvp_value;

		switch (hv_msg->kvp_index) {
		case FullyQualifiedDoCVE_2012_5532_linux3_2_25_mainName:
			kvp_get_doCVE_2012_5532_linux3_2_25_main_name(key_value,
					HV_KVP_EXCHANGE_MAX_VALUE_SIZE);
			strcpy(key_name, "FullyQualifiedDoCVE_2012_5532_linux3_2_25_mainName");
			break;
		case IntegrationServicesVersion:
			strcpy(key_name, "IntegrationServicesVersion");
			strcpy(key_value, lic_version);
			break;
		case NetworkAddressIPv4:
			kvp_get_ip_address(AF_INET, key_value,
					HV_KVP_EXCHANGE_MAX_VALUE_SIZE);
			strcpy(key_name, "NetworkAddressIPv4");
			break;
		case NetworkAddressIPv6:
			kvp_get_ip_address(AF_INET6, key_value,
					HV_KVP_EXCHANGE_MAX_VALUE_SIZE);
			strcpy(key_name, "NetworkAddressIPv6");
			break;
		case OSBuildNumber:
			strcpy(key_value, os_build);
			strcpy(key_name, "OSBuildNumber");
			break;
		case OSName:
			strcpy(key_value, os_name);
			strcpy(key_name, "OSName");
			break;
		case OSMajorVersion:
			strcpy(key_value, os_major);
			strcpy(key_name, "OSMajorVersion");
			break;
		case OSMinorVersion:
			strcpy(key_value, os_minor);
			strcpy(key_name, "OSMinorVersion");
			break;
		case OSVersion:
			strcpy(key_value, os_build);
			strcpy(key_name, "OSVersion");
			break;
		case ProcessorArchitecture:
			strcpy(key_value, processor_arch);
			strcpy(key_name, "ProcessorArchitecture");
			break;
		default:
			strcpy(key_value, "Unknown Key");
			/*
			 * We use a null key name to terminate enumeration.
			 */
			strcpy(key_name, "");
			break;
		}
		/*
		 * Send the value back to the kernel. The response is
		 * already in the receive buffer. Update the cn_msg header to
		 * reflect the key value that has been added to the message
		 */

		incoming_cn_msg->id.idx = CN_KVP_IDX;
		incoming_cn_msg->id.val = CN_KVP_VAL;
		incoming_cn_msg->seq = KVP_USER_SET;
		incoming_cn_msg->ack = 0;
		incoming_cn_msg->len = sizeof(struct hv_ku_msg);

		len = netlink_send(fd, incoming_cn_msg);
		if (len < 0) {
			syslog(LOG_ERR, "net_link send failed; error:%d", len);
			exit(-1);
		}
	}

}