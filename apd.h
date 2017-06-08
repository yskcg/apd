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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <netdb.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "sproto.h"
#include "json_parse.h"
#include "etherdevice.h"


#ifndef LINE_MAX
#define LINE_MAX			1024 * 3
#endif

#define SIZEOF_LENGTH 		4
#define ENCODE_BUFFERSIZE 	2050
#define ENCODE_MAXSIZE 		0x1000000
#define ENCODE_DEEPLEVEL 	64
#define BUFLEN 				1024 * 2
#define BUFSIZE 			8192
#define AP_STATUS			1
#define AP_INFO				2
#define AP_CMD				3
#define STA_INFO			4
#define RESPONSE_ERROR		0
#define RESPONSE_PACK	  	0
#define RESPONSE_OK		  	1
#define REBOOT  			1
#define UPGRADE				2
#define AP_ON				1
#define STATION_ON			1
#define STATION_OFF			0
#define MAX_ITEM_LEN 		(128)
#define MAX_TEMPLATE 		(8)
#define MAC_WIFI_DEVICES	4

#define ETH_LEN				6
#define DEFAULT_LEN			128

#define WIRELESS_2_4G		0
#define WIRELESS_5_8G		1
#define WIRE_CONFIG_FILE	"/etc/config/wireless"
#define AC_DNS_DOMAIN  		"www.morewifi.ac.com"
#define DEFAULT_DEVICE_IP	"192.168.33.111"
#define HOST_IP_FILE		"/tmp/host_ip"
#define MAC_ADDRESS_FILE    "/tmp/mac_address"
#define MAC_ADDRESS_5G_FILE "/tmp/mac_address_5G"
#define BSSID_IS_5G			1
#define APD_LISTEN_EVENT_ON    "morewifi_notify_on"
#define APD_LISTEN_EVENT_OFF   "morewifi_notify_off"


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

typedef struct {
	unsigned char station_mac[32];
	unsigned char bssid[32];
	unsigned char ap_mac[32];
	unsigned char status;			//1:on;0:off
	unsigned char type;				//1:5G;0:2.4G
	unsigned char ssid[64];
}station_info;

typedef struct encode_ud {
	char *stamac[32];
	int type,
	    session,
	    ok,
	    len;
}encode_ud_info;

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
	char 	ssid[128];
	char	mode[16];
	char	channel[8];
	char	encrypt[64];
	char	hver[32];
	char	model[32];
	char	sver[32];
	char	key[128];
	char	aip[32];
	char	txpower[8];
	char	apmac[32];
	char	sn[32];
	char 	hidden[16];
	char 	disabled[16];
	char 	type[16];
	int 	flage;
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

typedef struct{
	char name[64];
	char hwmode[32];
	char htmode[32];
	char channel[32];
	char txpower[32];
}wifi_device;

const char *ap_iwinfo[] = { "wireless.@wifi-iface[0].device",
	"wireless.@wifi-iface[0].network",
	"wireless.@wifi-iface[0].mode",
	"wireless.@wifi-device[0].type",
	"wireless.@wifi-device[0].channel",
	"wireless.@wifi-device[0].hwmode",
	"wireless.@wifi-device[0].htmode",
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
