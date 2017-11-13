#include <stdint.h>
#include <stdbool.h>
#include <net/if.h>
#include <errno.h>
#include "station_info.h"

struct nl80211_state nlstate;
struct uloop_fd station_fd;
int station_event_fd;
struct nl_cb *cb;


/* libnl 1.x compatibility code */
#if !defined(CONFIG_LIBNL20) && !defined(CONFIG_LIBNL30)
static inline struct nl_handle *nl_socket_alloc(void)
{
	return nl_handle_alloc();
}

static inline void nl_socket_free(struct nl_sock *h)
{
	nl_handle_destroy(h);
}

static inline int nl_socket_set_buffer_size(struct nl_sock *sk,
					    int rxbuf, int txbuf)
{
	return nl_set_buffer_size(sk, rxbuf, txbuf);
}
#endif /* CONFIG_LIBNL20 && CONFIG_LIBNL30 */

int iw_debug = 0;

static int nl80211_init(struct nl80211_state *state)
{
	int err;

	state->nl_sock = nl_socket_alloc();
	if (!state->nl_sock) {
		fprintf(stderr, "Failed to allocate netlink socket.\n");
		return -ENOMEM;
	}

	nl_socket_set_buffer_size(state->nl_sock, 8192, 8192);

	if (genl_connect(state->nl_sock)) {
		fprintf(stderr, "Failed to connect to generic netlink.\n");
		err = -ENOLINK;
		goto out_handle_destroy;
	}

	state->nl80211_id = genl_ctrl_resolve(state->nl_sock, "nl80211");
	if (state->nl80211_id < 0) {
		fprintf(stderr, "nl80211 not found.\n");
		err = -ENOENT;
		goto out_handle_destroy;
	}

	return 0;

 out_handle_destroy:
	nl_socket_free(state->nl_sock);
	return err;
}

void nl80211_cleanup(struct nl80211_state *state)
{
	nl_socket_free(state->nl_sock);
}


void mac_addr_n2a( char *mac_addr, unsigned char *arg)
{
	int i, l;

	l = 0;
	for (i = 0; i < ETH_ALEN ; i++) {
		if (i == 0) {
			sprintf(mac_addr+l, "%02x", arg[i]);
			l += 2;
		} else {
			sprintf(mac_addr+l, ":%02x", arg[i]);
			l += 3;
		}
	}
}

static int (*registered_handler)(struct nl_msg *, void *);
static void *registered_handler_data;

void register_handler(int (*handler)(struct nl_msg *, void *), void *data)
{
	registered_handler = handler;
	registered_handler_data = data;
}

int valid_handler(struct nl_msg *msg, void *arg)
{
	if (registered_handler)
		return registered_handler(msg, registered_handler_data);

	return NL_OK;
}

static int no_seq_check(struct nl_msg *msg, void *arg)
{
	return NL_OK;
}

static int post_event(struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	char res[1024] = {0};
	int size;
	struct encode_ud ud;

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	switch (gnlh->cmd) {
		case NL80211_CMD_DEL_STATION:
			memset(&sta_info,0,sizeof(sta_info));
			mac_addr_n2a((char*)&(sta_info.station_mac[0]), nla_data(tb[NL80211_ATTR_MAC]));

			print_debug_log("del station %s \n", &(sta_info.station_mac[0]));

			memset(&ud, 0, sizeof(struct encode_ud));
			ud.type = STA_INFO;
			ud.session = SPROTO_REQUEST;
			ud.stamac[0] = NULL;
			ud.len = 200;

			memcpy(sta_info.ap_mac,apinfo.apmac,sizeof(apinfo.apmac));

			sta_info.status = STATION_OFF;

			print_debug_log("%s %d  station_mac:%s\n",__FUNCTION__,__LINE__,sta_info.station_mac);
			print_debug_log("%s %d  type:%d\n",__FUNCTION__,__LINE__,sta_info.type);
			print_debug_log("%s %d  ap_mac:%s\n",__FUNCTION__,__LINE__,sta_info.ap_mac);
			if ((size = sproto_encode_data(&ud, res)) <= 0){
				print_debug_log("[encode data failed!]\n");
				return NL_SKIP;
			}

			if (sfd <= 0){
				return NL_SKIP;
			}
			write(sfd, res, size);
		}

	return NL_SKIP;
}

static int __prepare_listen_events(struct nl80211_state *state)
{
	int mcid, ret;

	/* MLME multicast group */
	mcid = nl_get_multicast_id(state->nl_sock, "nl80211", "mlme");
	if (mcid >= 0) {
		ret = nl_socket_add_membership(state->nl_sock, mcid);
		if (ret)
			return ret;
	}

	return 0;
}

void station_event_nl_cb_init()
{
	cb = nl_cb_alloc(iw_debug ? NL_CB_DEBUG : NL_CB_DEFAULT);

	if (!cb) {
		print_debug_log("failed to allocate netlink callbacks\n");
		return ;
	}

	/* no sequence checking for multicast messages */
	nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, NULL);

	register_handler(post_event, NULL);
}

static void *do_events(int sock,void *eloop_ctx,void *sock_ctx)
{
	struct nl80211_state *state = NULL;

	if(eloop_ctx == NULL){
		return NULL;
	}

	state = (struct nl80211_state *)eloop_ctx;
	nl_recvmsgs(state->nl_sock, cb);
	
	return NULL;
}

static void *nl80211_events(struct nl80211_state *state)
{
	int ret;

	ret = __prepare_listen_events(state);
	if (ret == 0){
		station_event_nl_cb_init();
		epoll_register_sock(state->nl_sock->s_fd,EVENT_TYPE_READ,(eloop_sock_handler)do_events,(void *)state,NULL);
	}

	return NULL;
}

void station_event_init()
{
	int err;
	pthread_t thread_handle_id;
	
	epoll_init();
	err = nl80211_init(&nlstate);
	if (err)
		return ;

	nl80211_events(&nlstate);

	/*create the pthread to handle*/
	pthread_create(&thread_handle_id,NULL,&epoll_run,NULL);
}

void station_exit()
{
	nl_cb_put(cb);
}
