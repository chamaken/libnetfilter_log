
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>

#include <libnetfilter_log/libnetfilter_log.h>

static int print_pkt(struct nfattr *tb[])
{
	if (tb[NFULA_PACKET_HDR-1]) {
		struct nfulnl_msg_packet_hdr *ph =
					NFA_DATA(tb[NFULA_PACKET_HDR-1]);
		printf("hw_protocol=0x%04x hook=%u ", 
			ntohs(ph->hw_protocol), ph->hook);
	}

	if (tb[NFULA_MARK-1]) {
		u_int32_t mark = 
			ntohl(*(u_int32_t *)NFA_DATA(tb[NFULA_MARK-1]));
		printf("mark=%u ", mark);
	}

	if (tb[NFULA_IFINDEX_INDEV-1]) {
		u_int32_t ifi = ntohl(*(u_int32_t *)NFA_DATA(tb[NFULA_IFINDEX_INDEV-1]));
		printf("indev=%u ", ifi);
	}
	if (tb[NFULA_IFINDEX_OUTDEV-1]) {
		u_int32_t ifi = ntohl(*(u_int32_t *)NFA_DATA(tb[NFULA_IFINDEX_OUTDEV-1]));
		printf("outdev=%u ", ifi);
	}
#if 0
	if (tb[NFULA_IFINDEX_PHYSINDEV-1]) {
		u_int32_t ifi = ntohl(*(u_int32_t *)NFA_DATA(tb[NFULA_IFINDEX_PHYSINDEV-1]));
		printf("physindev=%u ", ifi);
	}
	if (tb[NFULA_IFINDEX_PHYSOUTDEV-1]) {
		u_int32_t ifi = ntohl(*(u_int32_t *)NFA_DATA(tb[NFULA_IFINDEX_PHYSOUTDEV-1]));
		printf("physoutdev=%u ", ifi);
	}
#endif
	if (tb[NFULA_PREFIX-1]) {
		char *prefix = NFA_DATA(tb[NFULA_PREFIX-1]);
		printf("prefix=\"%s\" ", prefix);
	}
	if (tb[NFULA_PAYLOAD-1]) {
		printf("payload_len=%d ", NFA_PAYLOAD(tb[NFULA_PAYLOAD-1]));
	}

	fputc('\n', stdout);
	return 0;
}

static int cb(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg,
		struct nfattr *nfa[], void *data)
{
	print_pkt(nfa);
}


int main(int argc, char **argv)
{
	struct nflog_handle *h;
	struct nflog_g_handle *qh;
	struct nflog_g_handle *qh100;
	int rv, fd;
	char buf[4096];

	h = nflog_open();
	if (!h) {
		fprintf(stderr, "error during nflog_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_log handler for AF_INET (if any)\n");
	if (nflog_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error nflog_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_log to AF_INET\n");
	if (nflog_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nflog_bind_pf()\n");
		exit(1);
	}
	printf("binding this socket to group 0\n");
	qh = nflog_bind_group(h, 0);
	if (!qh) {
		fprintf(stderr, "no handle for grup 0\n");
		exit(1);
	}

	printf("binding this socket to group 100\n");
	qh100 = nflog_bind_group(h, 100);
	if (!qh100) {
		fprintf(stderr, "no handle for group 100\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nflog_set_mode(qh, NFULNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet copy mode\n");
		exit(1);
	}

	fd = nflog_fd(h);

	printf("registering callback for group 0\n");
	nflog_callback_register(qh, &cb, NULL);

	printf("going into main loop\n");
	while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
		struct nlmsghdr *nlh;
		printf("pkt received (len=%u)\n", rv);

		/* handle messages in just-received packet */
		nflog_handle_packet(h, buf, rv);
	}

	printf("unbinding from group 100\n");
	nflog_unbind_group(qh100);
	printf("unbinding from group 0\n");
	nflog_unbind_group(qh);

#ifdef INSANE
	/* norally, applications SHOULD NOT issue this command,
	 * since it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nflog_unbind_pf(h, AF_INET);
#endif

	printf("closing handle\n");
	nflog_close(h);

	exit(0);
}
