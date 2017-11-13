#ifndef __DNS_H
#define __DNS_H

#include<stdlib.h>
#include<stdio.h>
#include<unistd.h>
#include<string.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<errno.h>
#include<time.h>

#include "util.h"

#define MAXSIZE 256
#define MAXqueryname 63
#define MAX16 65536
#define DNSPORT 53
#define FLAG 0x0200
#define MAX_RESULT 16

/*struct dnsheader, 12 bytes*/
struct dnsheader
{
	//2 byte ID
	uint16_t id;

	//2 byte flag broken down with bitfields
	//BYTE 1 in REVERSE ORDER 	//pos
	unsigned char rd :1; 		//7
	unsigned char tc :1;		//6
	unsigned char aa :1; 		//5
	unsigned char opcode :4;	//4-1
	unsigned char qr :1; 		//0
	
	//BYTE 2 in REVERSE ORDER
	unsigned char rcode :4;		//15-12 
	unsigned char z :3; 		//12-9	
	unsigned char ra :1; 		//9-8
	
	//counts, each 2 bytes
	uint16_t q_count; 
	uint16_t ans_count; 
	uint16_t auth_count; 
	uint16_t add_count;
};

/* struct question, contains qtype and qclass*/
struct question
{
	uint16_t qtype;
	uint16_t qclass;
};

/* struct record*/
struct record
{
	uint16_t name;		//2 byte pointer
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t data_len;
	unsigned char* rdata;
};
/* struct query, contains the actual name requested and the struct question with qtype and qclass*/
struct query
{
	unsigned char *name;
	struct question *ques;
};

extern int get_dns(const char *query_name,unsigned long int dns_server,char *result);

#endif
