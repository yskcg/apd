#ifndef _UBUS_H
#define _UBUS_H

#include "etherdevice.h"
#include "apd.h"

#define STATION_ON			1
#define STATION_OFF			0


#define LOG_FILE			"/tmp/log/apd.log"

/*function declartion*/
extern void server_main(void);
extern int apd_ubus_listen(struct ubus_context *ctx, char * type);

extern struct ubus_context *uctx;
#endif
 
