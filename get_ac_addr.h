#ifndef __CORE_H
#define __CORE_H
#include "apd.h"

#define MAC_ADDRESS_FILE    "/tmp/mac_address"

/*API*/

extern int get_gateway_ip(char *ip);
extern int get_netcard_mac(void);
#endif
