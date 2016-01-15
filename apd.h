#ifndef _APD_H
#define _APD_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>    //for rtnetlink
#include <net/if.h> //for IF_NAMESIZ, route_info
#include <netinet/in.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <pthread.h>
#include <fcntl.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <libubox/usock.h>
#include <limits.h>
#include <uci.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>
#include "sproto.h"


#ifndef LINE_MAX
#define LINE_MAX	1024 * 3
#endif

#define SIZEOF_LENGTH 4
#define ENCODE_BUFFERSIZE 2050
#define ENCODE_MAXSIZE 0x1000000
#define ENCODE_DEEPLEVEL 64
#define BUFLEN 1024 * 2
#define BUFSIZE 8192
#define AP_STATUS				1
#define AP_INFO				  2
#define AP_CMD					3
#define RESPONSE_ERROR	0
#define RESPONSE_PACK	  0
#define RESPONSE_OK		  1
#define REBOOT  				1
#define UPGRADE				  2
#define AP_ON						1


FILE *debug = NULL;

struct field {
	int tag;
	int type;
	const char * name;
	struct sproto_type * st;
};

struct sproto_type {
	const char * name;
	int n;
	int base;
	int maxn;
	struct field *f;
};

struct protocol {
	const char *name;
	int tag;
	struct sproto_type * p[2];
};

struct chunk {
	struct chunk * next;
};

struct pool {
	struct chunk * header;
	struct chunk * current;
	int current_used;
};

struct sproto {
	struct pool memory;
	int type_n;
	int protocol_n;
	struct sproto_type * type;
	struct protocol * proto;
};

struct client {
	struct sockaddr_in sin;

	struct ustream_fd s;
	int ctr;
};

struct encode_ud {
	char *stamac[32];
	int type,
	    session,
	    ok,
	    len;
};

enum {
	STAINFO,
	MAC,
	SIGNAL,
	NOISE,
	ACT,
	RX,
	TX,
	IPADDR,
	ADDR,
	UP,
	__STA_MAX
};

typedef struct ap_cfg_info
{
	char ssid[200],
	     mode[15],
	     channel[5],
	     encrypt[50],
	     hver[30],
	     sver[30],
	     key[300],
	     aip[20],
	     txpower[5],
	     apmac[20],
	     sn[20];
	int flage;
}ApCfgInfo;

typedef struct
{
	char addr[80],
	     md5[36];
	int  cmd,
	     status,
	     stanum;
}apcmd;

struct route_info
{
	u_int dstAddr;
	u_int srcAddr;
	u_int gateWay;
	char ifName[IF_NAMESIZE];
};

const char *ap_iwinfo[] = { "wireless.@wifi-iface[0].device",
	"wireless.@wifi-iface[0].network",
	"wireless.@wifi-iface[0].mode",
	"wireless.@wifi-device[0].type",
	"wireless.@wifi-device[0].channel",
	"wireless.@wifi-device[0].hwmode",
	"wireless.@wifi-device[0].htmode",
	0};

static char *ap_cfg_opt[] = {"mac",
	"hver",
	"sver",
	"rip",
	"aip",
	"ssid",
	"mode",
	"encryption",
	"update",
	"channel",
	"key",
	"status",
	"network",
	"device",
	0};

static char *dev_opt[] = {
	"channel",
	"txpower",
	0};

void print_debug_log(const char *form ,...);
int get_loca_ip(char *locip, char *dev);
void ap_proc_data(struct uloop_fd *fd, unsigned int events);
void ap_watch_dog(struct uloop_timeout *t);
int fill_encode_data(ApCfgInfo *apcfg,char *tagname, char *value);
void fill_data(ApCfgInfo *apcfg,char *tagname, char *value, int len);
int get_gateway_ip(char *ip);
int open_file(char *path, char *res, char *flag);
int get_ap_revision(void);
int uci_set_cfg(struct uci_context *c, char *section, char *type, char *option, char *value);
int set_ap_cfg(void);
int get_netcard_ip(char *dev, char *ip) ;
int proc_update(char *upd);


#endif


