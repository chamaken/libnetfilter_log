/* libnetfilter_log.h: Header file for the Netfilter Userspace Log library.
 *
 * (C) 2005 by Harald Welte <laforge@gnumonks.org>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#ifndef __LIBNETFILTER_LOG_H
#define __LIBNETFILTER_LOG_H

#include <libnfnetlink/libnfnetlink.h>
#include <linux/netfilter/nfnetlink_log.h>

struct nflog_handle;
struct nflog_g_handle;

extern int nflog_errno;

extern struct nfnl_handle *nflog_nfnlh(struct nflog_handle *h);
extern int nflog_fd(struct nflog_handle *h);

typedef int nflog_callback(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg,
			    struct nfattr *nfa[], void *data);


extern struct nflog_handle *nflog_open(void);
extern int nflog_close(struct nflog_handle *h);

extern int nflog_bind_pf(struct nflog_handle *h, u_int16_t pf);
extern int nflog_unbind_pf(struct nflog_handle *h, u_int16_t pf);

extern struct nflog_g_handle *nflog_bind_group(struct nflog_handle *h,
						 u_int16_t num);
extern int nflog_unbind_group(struct nflog_g_handle *gh);

extern int nflog_set_mode(struct nflog_g_handle *gh,
			  u_int8_t mode, unsigned int len);
extern int nflog_set_timeout(struct nflog_g_handle *gh, u_int32_t timeout);
extern int nflog_set_qthresh(struct nflog_g_handle *gh, u_int32_t qthresh);
extern int nflog_set_nlbufsiz(struct nflog_g_handle *gh, u_int32_t nlbufsiz);

extern int nflog_callback_register(struct nflog_g_handle *gh, 
				    nflog_callback *cb, void *data);
extern int nflog_handle_packet(struct nflog_handle *h, char *buf, int len);

#endif	/* __LIBNETFILTER_LOG_H */
