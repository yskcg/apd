SPIDER_VER	=	$(shell date +'0.%y.%m%d%H%M.%S')

LDFLAGS += -ljson-c -lpthread -lblobmsg_json -lm -ldl -lubox -luci -lubus -lm -lnl-tiny

APD_OBJS = apd.o json_parse.o sproto.o dns.o queue.o ubus.o  genl.o get_ac_addr.o util.o station_info.o eloop.o wireless_conf.o
APD_OBJS_H =  sproto.h msvcint.h json_parse.h dns.h queue.h ubus.h etherdevice.h station_info.h util.h get_ac_addr.h eloop.h list.h wireless_conf.h


TARGET_CPPFLAGS:= -I$(STAGING_DIR)/usr/include/libnl-tiny $(TARGET_CPPFLAGS) -DCONFIG_LIBNL20 -D_GNU_SOURCE

CFLAGS +=$(TARGET_CPPFLAGS) 

all:apd

sproto.o:sproto.c sproto.h msvcint.h
	@$(CC) -Wall -c -g sproto.c  $(CFLAGS)

json_parse.o:json_parse.c json_parse.h
	@$(CC) -Wall -c -g json_parse.c  $(CFLAGS)

dns.o:dns.c dns.h
	@$(CC) -Wall -c -g dns.c  $(CFLAGS)

queue.o:queue.c queue.h
	@$(CC) -Wall -c -g queue.c  $(CFLAGS)

ubus.o:ubus.c ubus.h
	@$(CC) -Wall -c -g ubus.c  $(CFLAGS)

station_info.o:station_info.c station_info.h
	@$(CC) -Wall -c -g station_info.c $(CFLAGS) 

genl.o:genl.c station_info.h
	@$(CC) -Wall -c -g genl.c $(CFLAGS) 

get_ac_addr.o:get_ac_addr.c get_ac_addr.h
	@$(CC) -Wall -c -g get_ac_addr.c $(CFLAGS) 

util.o:util.c util.h 
	@$(CC) -Wall -c -g util.c $(CFLAGS)

eloop.o:eloop.c eloop.h
	@$(CC) -Wall -c -g eloop.c $(CFLAGS)

wireless_conf.o:wireless_conf.c wireless_conf.h
	@$(CC) -Wall -c -g wireless_conf.c  $(CFLAGS) 

apd.o:apd.c $(APD_OBJS_H)
	@$(CC) -Wall -c -g apd.c  $(CFLAGS) 

	
apd:$(APD_OBJS)
	$(CC) -Wall  $(APD_OBJS) $(CFLAGS) $(LDFLAGS) -o apd
	
clean:
	@rm -rf apd
	@rm -rf *bak
	@rm -rf *.o
