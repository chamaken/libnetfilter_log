/* This example is placed in the public domain. */
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <linux/netfilter/nfnetlink_log.h>

#include <libmnl/libmnl.h>
#include <libnetfilter_log/libnetfilter_log.h>

static int log_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *attrs[NFULA_MAX + 1] = { NULL };
	struct nfulnl_msg_packet_hdr *ph = NULL;
	const char *prefix = NULL;
	uint32_t mark = 0;
	int ret;

	ret = nflog_nlmsg_parse(nlh, attrs);
	if (ret != MNL_CB_OK)
		return ret;

	if (attrs[NFULA_PACKET_HDR])
		ph = mnl_attr_get_payload(attrs[NFULA_PACKET_HDR]);
	if (attrs[NFULA_PREFIX])
		prefix = mnl_attr_get_str(attrs[NFULA_PREFIX]);
	if (attrs[NFULA_MARK])
		mark = ntohl(mnl_attr_get_u32(attrs[NFULA_MARK]));

	printf("log received (prefix=\"%s\" hw=0x%04x hook=%u mark=%u)\n",
		prefix ? prefix : "", ntohs(ph->hw_protocol), ph->hook,
		mark);

	return MNL_CB_OK;
}

int main(int argc, char *argv[])
{
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	int ret;
	unsigned int portid, qnum;

	if (argc != 2) {
		printf("Usage: %s [queue_num]\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	qnum = atoi(argv[1]);

	nl = mnl_socket_open(NETLINK_NETFILTER);
	if (nl == NULL) {
		perror("mnl_socket_open");
		exit(EXIT_FAILURE);
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		exit(EXIT_FAILURE);
	}
	portid = mnl_socket_get_portid(nl);

	/* kernels 3.8 and later is required to omit PF_(UN)BIND */

	nlh = nflog_nlmsg_put_header(buf, NFULNL_MSG_CONFIG, AF_INET, 0);
	if (nflog_attr_put_cfg_cmd(nlh, NFULNL_CFG_CMD_PF_UNBIND) < 0) {
		perror("nflog_attr_put_cfg_cmd");
		exit(EXIT_FAILURE);
	}

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_sendto");
		exit(EXIT_FAILURE);
	}

	nlh = nflog_nlmsg_put_header(buf, NFULNL_MSG_CONFIG, AF_INET, 0);
	if (nflog_attr_put_cfg_cmd(nlh, NFULNL_CFG_CMD_PF_BIND) < 0) {
		perror("nflog_attr_put_cfg_cmd");
		exit(EXIT_FAILURE);
	}

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_sendto");
		exit(EXIT_FAILURE);
	}

	nlh = nflog_nlmsg_put_header(buf, NFULNL_MSG_CONFIG, AF_INET, qnum);
	if (nflog_attr_put_cfg_cmd(nlh, NFULNL_CFG_CMD_BIND) < 0) {
		perror("nflog_attr_put_cfg_cmd");
		exit(EXIT_FAILURE);
	}

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_sendto");
		exit(EXIT_FAILURE);
	}

	nlh = nflog_nlmsg_put_header(buf, NFULNL_MSG_CONFIG, AF_UNSPEC, qnum);
	if (nflog_attr_put_cfg_mode(nlh, NFULNL_COPY_PACKET, 0xffff) < 0) {
		perror("nflog_attr_put_cfg_mode");
		exit(EXIT_FAILURE);
	}

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_sendto");
		exit(EXIT_FAILURE);
	}

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	if (ret == -1) {
		perror("mnl_socket_recvfrom");
		exit(EXIT_FAILURE);
	}
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, 0, portid, log_cb, NULL);
		if (ret < 0){
			perror("mnl_cb_run");
			exit(EXIT_FAILURE);
		}

		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
		if (ret == -1) {
			perror("mnl_socket_recvfrom");
			exit(EXIT_FAILURE);
		}
	}

	mnl_socket_close(nl);

	return 0;
}
