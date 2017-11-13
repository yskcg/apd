#ifndef __H_ROAM_ELOOP_H
#define __H_ROAM_ELOOP_H

#include "util.h"
#include "list.h"


/**
 * @sock:file descriptor number for the socket
* @eloop_ctx:Registered callback context data(eloop_data)
* @sock_ctx:Registered callback context data(user_data)
*/
typedef void (*eloop_sock_handler)(int sock,void *eloop_ctx,void *sock_ctx);

typedef enum{
	EVENT_TYPE_READ = 0,
	EVENT_TYPE_WRITE,
	EVENT_TYPE_EXCEPTION
}eloop_event_type;

struct eloop_sock{
	int sock;
	unsigned char active;
	unsigned char flags;
	void *eloop_data;
	void *user_data;
	eloop_sock_handler handler;
};

struct eloop_sock_table{
	int count;
	struct eloop_sock *table;
	eloop_event_type type;
	int changed;
};

struct eloop_data{
	int max_sock;
	int count;			//sum of all table counts
	int epoll_fd;
	int epoll_max_event_num;
	int epoll_max_fd;
	struct eloop_sock  *epoll_table;
	struct epoll_event *epoll_events;
	
	struct eloop_sock_table readers;
	struct eloop_sock_table writers;
	struct eloop_sock_table exceptions;
};

#define ALLOC_MAGIC 0xa84ef1b2
#define FREED_MAGIC 0x67fd487a

#define SOCK_ACTIVE 1
#define SOCK_UNACTIVE 0
struct os_alloc_trace{
	unsigned int magic;
	struct dl_list list;
	size_t len;
};

extern int epoll_init(void);
extern void eloop_destroy(void);
extern int epoll_register_sock(int sock,eloop_event_type type,eloop_sock_handler handler,void *eloop_data,void *user_data);
extern void eloop_unregister_sock(int sock, eloop_event_type type);
extern void *epoll_run();

#endif
