#ifndef __STATION_INFO_H
#define __STATION_INFO_H

#include <stdbool.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <endian.h>

#include "nl80211.h"
#include "ieee80211.h"
#include "eloop.h"
#include "apd.h"

#define ETH_ALEN 6

/* libnl 1.x compatibility code */
#if !defined(CONFIG_LIBNL20) && !defined(CONFIG_LIBNL30)
	# define nl_sock nl_handle
#endif

struct nl80211_state {
	struct nl_sock *nl_sock;
	int nl80211_id;
};

enum command_identify_by {
	CIB_NONE,
	CIB_PHY,
	CIB_NETDEV,
	CIB_WDEV,
};

enum id_input {
	II_NONE,
	II_NETDEV,
	II_PHY_NAME,
	II_PHY_IDX,
	II_WDEV,
};


extern int iw_debug;
extern struct nl80211_state nlstate;
extern int nl_get_multicast_id(struct nl_sock *sock, const char *family, const char *group);
extern void station_event_init();
extern void nl80211_cleanup(struct nl80211_state *state);
extern void station_exit();

int valid_handler(struct nl_msg *msg, void *arg);
void register_handler(int (*handler)(struct nl_msg *, void *), void *data);

#endif
