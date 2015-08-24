/*
 * (C) 2015 by Ken-ichirou MATSUZAWA <chamas@h4.dion.ne.jp>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include <arpa/inet.h>
#include <libmnl/libmnl.h>
#include <libnetfilter_log/libnetfilter_log.h>
#include <errno.h>
#include "internal.h"

/**
 * \defgroup nlmsg Netlink message helper functions
 * @{
 */

/**
 * nflog_nlmsg_put_header - reserve and prepare room for nflog Netlink header
 * \param buf memory already allocated to store the Netlink header
 * \param type message type one of the enum nfulnl_msg_types
 * \param family protocol family to be an object of
 * \param qnum queue number to be an object of
 *
 * This function creates Netlink header in the memory buffer passed
 * as parameter that will send to nfnetlink log. This function
 * returns a pointer to the Netlink header structure.
 */
struct nlmsghdr *
nflog_nlmsg_put_header(char *buf, uint8_t type, uint8_t family, uint16_t qnum)
{
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	struct nfgenmsg *nfg;

	nlh->nlmsg_type	= (NFNL_SUBSYS_ULOG << 8) | type;
	nlh->nlmsg_flags = NLM_F_REQUEST;

	nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
	nfg->nfgen_family = family;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons(qnum);

	return nlh;
}

/**
 * nflog_attr_put_cfg_mode - add a mode attribute to nflog netlink message
 * \param nlh pointer to the netlink message
 * \param mode copy mode defined in linux/netfilter/nfnetlink_log.h
 * \param range copy range
 *
 * this function returns -1 and errno is explicitly set on error.
 * On success, this function returns 1.
 */
int nflog_attr_put_cfg_mode(struct nlmsghdr *nlh, uint8_t mode, uint32_t range)
{
	struct nfulnl_msg_config_mode nfmode = {
		.copy_mode = mode,
		.copy_range = htonl(range)
	};

	mnl_attr_put(nlh, NFULA_CFG_MODE, sizeof(nfmode), &nfmode);

	/* it may returns -1 in future */
	return 0;
}

/**
 * nflog_attr_put_cfg_cmd - add a cmd attribute to nflog netlink message
 * \param nlh pointer to the netlink message
 * \param cmd command one of the enum nfulnl_msg_config_cmds
 *
 * this function returns -1 and errno is explicitly set on error.
 *  On success, this function returns 1.
 */
int nflog_attr_put_cfg_cmd(struct nlmsghdr *nlh, uint8_t cmd)
{
	struct nfulnl_msg_config_cmd nfcmd = {
		.command = cmd
	};

	mnl_attr_put(nlh, NFULA_CFG_CMD, sizeof(nfcmd), &nfcmd);

	/* it may returns -1 in future */
	return 0;
}

static int nflog_parse_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	/* skip unsupported attribute in user-space */
	if (mnl_attr_type_valid(attr, NFULA_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFULA_HWTYPE:		/* hardware type */
	case NFULA_HWLEN:		/* hardware header length */
		if (mnl_attr_validate(attr, MNL_TYPE_U16) < 0)
			return MNL_CB_ERROR;
		break;
	case NFULA_MARK:		/* __u32 nfmark */
	case NFULA_IFINDEX_INDEV:	/* __u32 ifindex */
	case NFULA_IFINDEX_OUTDEV:	/* __u32 ifindex */
	case NFULA_IFINDEX_PHYSINDEV:	/* __u32 ifindex */
	case NFULA_IFINDEX_PHYSOUTDEV:	/* __u32 ifindex */
	case NFULA_UID:			/* user id of socket */
	case NFULA_SEQ:			/* instance-local sequence number */
	case NFULA_SEQ_GLOBAL:		/* global sequence number */
	case NFULA_GID:			/* group id of socket */
	case NFULA_CT_INFO:		/* enum ip_conntrack_info */
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			return MNL_CB_ERROR;
		break;
	case NFULA_PACKET_HDR:
		if (mnl_attr_validate2(attr, MNL_TYPE_UNSPEC,
		    sizeof(struct nfulnl_msg_packet_hdr)) < 0) {
			return MNL_CB_ERROR;
		}
		break;
	case NFULA_TIMESTAMP:		/* nfulnl_msg_packet_timestamp */
		if (mnl_attr_validate2(attr, MNL_TYPE_UNSPEC,
		    sizeof(struct nfulnl_msg_packet_timestamp)) < 0) {
			return MNL_CB_ERROR;
		}
		break;
	case NFULA_HWADDR:		/* nfulnl_msg_packet_hw */
		if (mnl_attr_validate2(attr, MNL_TYPE_UNSPEC,
		    sizeof(struct nfulnl_msg_packet_hw)) < 0) {
			return MNL_CB_ERROR;
		}
		break;
	case NFULA_PREFIX:		/* string prefix */
		if (mnl_attr_validate(attr, MNL_TYPE_NUL_STRING) < 0)
			return MNL_CB_ERROR;
		break;
	case NFULA_HWHEADER:		/* hardware header */
	case NFULA_PAYLOAD:		/* opaque data payload */
	case NFULA_CT:			/* nf_conntrack_netlink.h */
		break;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

/**
 * nflog_nlmsg_parse - set nlattrs from netlink message
 * \param nlh netlink message that you want to read.
 * \param attr pointer to the array of nlattr which size is NFULA_MAX + 1
 *
 * This function returns MNL_CB_ERROR if any error occurs, or MNL_CB_OK on
 * success.
 */
int nflog_nlmsg_parse(const struct nlmsghdr *nlh, struct nlattr **attr)
{
	return mnl_attr_parse(nlh, sizeof(struct nfgenmsg),
			      nflog_parse_attr_cb, attr);
}

/**
 * nflog_nlmsg_snprintf - print a nflog nlattrs to a buffer
 * \param buf buffer used to build the printable nflog
 * \param bufsiz size of the buffer
 * \param nlh netlink message (to get queue num in the futuer)
 * \param attr pointer to a nflog attrs
 * \param type print message type in enum nflog_output_type
 * \param flags The flag that tell what to print into the buffer
 *
 * This function supports the following type - flags:
 *
 *   type: NFLOG_OUTPUT_XML
 *	- NFLOG_XML_PREFIX: include the string prefix
 *	- NFLOG_XML_HW: include the hardware link layer address
 *	- NFLOG_XML_MARK: include the packet mark
 *	- NFLOG_XML_DEV: include the device information
 *	- NFLOG_XML_PHYSDEV: include the physical device information
 *	- NFLOG_XML_PAYLOAD: include the payload (in hexadecimal)
 *	- NFLOG_XML_TIME: include the timestamp
 *	- NFLOG_XML_ALL: include all the logging information (all flags set)
 *
 * You can combine this flags with an binary OR.
 *
 * this function returns -1 and errno is explicitly set in case of
 * failure, otherwise the length of the string that would have been
 * printed into the buffer (in case that there is enough room in
 * it). See snprintf() return value for more information.
 */
int nflog_nlmsg_snprintf(char *buf, size_t bufsiz, const struct nlmsghdr *nlh,
			 struct nlattr **attr, enum nflog_output_type type,
			 uint32_t flags)
{
	/* This is a hack to re-use the existing old API code. */
	struct nflog_data nfad = {
		.nfa	= (struct nfattr **)&attr[1],
	};
	int ret;

	switch (type) {
	case NFLOG_OUTPUT_XML:
		ret = nflog_snprintf_xml(buf, bufsiz, &nfad, flags);
		break;
	default:
		ret = -1;
		errno = EOPNOTSUPP;
		break;
	}
	return ret;
}

/**
 * @}
 */
