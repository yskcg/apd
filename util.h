#ifndef _AP_UTIL_H
#define _AP_UTIL_H
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <linux/genetlink.h>
#include <sys/types.h>
#include <unistd.h>
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
#include <sys/wait.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <limits.h>
#include <sys/stat.h>
#include <netdb.h>
#include <netdb.h>
#include <sys/types.h>
#include <libubus.h>
#include <assert.h>


#include <libiptc/libiptc.h>
#include <libubox/blob.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uclient.h>
#include <libubox/runqueue.h>

#include <libubus.h>
#include <ubusmsg.h>
#include <ubus_common.h>

#define DEFAULT_DEVICE_IP	"192.168.33.111"
#define HOST_IP_FILE		"/tmp/host_ip"

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

/*API*/
extern int is_ip(const char *str);
extern int get_ap_revision(void);
extern int open_file(char *path, char *res, char *flag);
extern int memcat(char *res, char *buf, int slen, int len);
extern void mac_string_to_value(unsigned char *mac,unsigned char *buf);
extern int my_strtok(char *src, char *dst[], int n);
extern void get_sn(void);
extern void get_host_ip(char *hostip);
/*debug*/
extern void print_debug_log(const char *form ,...);

extern ApCfgInfo apinfo;
extern FILE *debug ;
#endif
