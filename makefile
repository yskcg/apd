SPIDER_VER	=	$(shell date +'0.%y.%m%d%H%M.%S')

CFLAGS += -DWIFISPIDER=\"$(SPIDER_VER)\"
LDFLAGS += -ljson-c -lblobmsg_json -lm -ldl -lubox -luci -lubus

all:apd

sproto.o:sproto.c sproto.h msvcint.h
	@$(CC) -Wall -g -c sproto.c sproto.h msvcint.h

json_parse.o:json_parse.c json_parse.h
	@$(CC) -Wall -g -c json_parse.c

apd.o:apd.c apd.h json_parse.h etherdevice.h
	@$(CC) -Wall -g -c apd.c 
	
apd:apd.o sproto.o json_parse.o
	@$(CC) -Wall -g -o apd apd.o json_parse.o sproto.o $(CFLAGS) $(LDFLAGS)
	
clean:
	@rm -rf apd
	@rm -rf *bak
	@rm -rf *.o
