#include "dns.h"

/***************************************************************************
 *	Purpose: To write a DNS client. Particularly create a query, and parse the response
 *
 *	Notes:	There is a bug somewhere (that eludes me to no end)that for some replies
 *			the rdata get shifted by a byte and essentially writes only the first
 *			three bytes. Those answers i marked with /24 (block 24. (FIXED, or so rare as to be irrelevent)
 ***************************************************************************/
 
/*	The idea is simple, AND the ip with 0xFF ==> 11111111, which corresponds to an ip byte, then shift 
	by 8 (1 byte) and do the same thing*/
void convert(int ip,char *result)
{
    unsigned char bytes[4];
	
	ip = ntohl(ip);
	print_debug_log("%u\n",ip);
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >>8) & 0xFF;
    bytes[2] = (ip >>16) & 0xFF;
    bytes[3] = (ip >>24) & 0xFF;     
	if(bytes[0] == 4){
		printf("%d.%d.%d.00/24 (block 24)\n", bytes[1], bytes[2], bytes[3]);
	}else{
		//printf("%s %d %d.%d.%d.%d\n", __FUNCTION__,__LINE__,bytes[3], bytes[2], bytes[1], bytes[0]);
		sprintf(result,"%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);
	}       
}

int letter_counter = 0;
/* Purpose: formats the given hostname into a dns query format, as in 3www5yahoo3com */
void seperate(unsigned char* name,unsigned char* host)
{
	char *tokens = NULL;
	int counter = 0;
	char buf[128] = {0};

	if(host == NULL){
		return 0;
	}
	
	memcpy(buf,host,strlen(host));
	tokens = strtok(buf, ".");

	while(1){
		if(tokens == NULL){
			break;
		}else{
			char *i;
			name[letter_counter] = (unsigned char)strlen(tokens);
			letter_counter++;
			for(i = tokens; *i != NULL; i++){
				name[letter_counter] = *i;
				letter_counter++;
			}
		}
		tokens = strtok(NULL, ".");
	}
	name[letter_counter] = '\0';
}

int prepare_dns_query(char *query_name,char *dns_server)
{
	int sockFd;
	int n;
	uint16_t ID_q ;
	long int times;
	unsigned char buf[256];			//used to create the query
	struct dnsheader *dns = NULL;
	struct question *queryinfo;
	unsigned char* queryname;
	struct sockaddr_in a;
	struct sockaddr_in servAddr;	//sockaddr for the server address

	if(query_name ==NULL || dns_server == NULL){
		return 0;
	}

	//Set the dnsheader pointer to point at the beggining of the buffer
	dns = (struct dnsheader *)&buf;
	memset(buf,0,sizeof(buf));
	
	//fill id and flag info
	times = time(NULL);
	srand(times);			//random seed, using time(NULL)
	ID_q = (uint16_t)rand()% 65536+1;	//2 byte ID 

	//filling in dns header
	dns->id = ID_q;
	dns->qr = 0; 
	dns->opcode = 0; 
	dns->aa = 0;
	dns->tc = 0;
	dns->rd = 0;
	dns->ra = 0; 
	dns->z = 0;
	dns->rcode = 0;
	dns->q_count = htons(1); 
	dns->ans_count = 0;
	dns->auth_count = 0;
	dns->add_count = 0;

	//given unsiged char queryname, make it point to the address of buf after the dnsheader
	queryname = (unsigned char*)&buf[sizeof(struct dnsheader)];
	seperate(queryname, query_name);

	//given unsigned char queryinfo, make it point to the address of buf after dnsheader and queryname (including the null byte)
	queryinfo =(struct question*)&buf[sizeof(struct dnsheader) + (strlen((unsigned char*)queryname) + 1)];
	queryinfo->qtype = htons(1); 
	queryinfo->qclass = htons(1);
	
	//creat socket
	if ((sockFd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) 
	{
		return 0;
	}

	//fill in remote server's info
	memset(&servAddr,0, sizeof(servAddr));		//clear struct
	servAddr.sin_family = AF_INET;			//specify family
	servAddr.sin_port = htons(53);			//specify port
	inet_pton(AF_INET, dns_server, &servAddr.sin_addr);  

	//send query
	int length = sizeof(struct dnsheader)+strlen((unsigned char*)queryname)+sizeof(struct question)+1;
	n = sendto(sockFd,(char*)buf,length,0, (struct sockaddr*)&servAddr, sizeof(servAddr));

	if (n < 0){
		return 0;
	}
	
	return sockFd;
}


int parese_dns(int socket,char * dns_server,char **result)
{
	int len;
	int serv_len ;
	int ans_length;		//previous answer length
	int found = 0;		//found count
	int num_answers;
	int offset;
	char buf[256] = {0};
	struct sockaddr_in servAddr;	//sockaddr for the server address
	struct dnsheader *response = NULL;
	struct timeval tv_out;
	struct dnsheader *dns = NULL;
	struct record *answer;			//used to parse the ANSWERS
	
	response = (struct dnsheader *)&buf;
	//fill in remote server's info
	serv_len = sizeof(servAddr);
	memset(&servAddr,0, sizeof(servAddr));		//clear struct
	servAddr.sin_family = AF_INET;			//specify family
	servAddr.sin_port = htons(53);			//specify port
	inet_pton(AF_INET, dns_server, &servAddr.sin_addr); 


	
	tv_out.tv_sec = 2;//等待3秒
	tv_out.tv_usec = 0;
	setsockopt(socket,SOL_SOCKET,SO_RCVTIMEO,&tv_out, sizeof(tv_out));
	//receive the dns server response

	len = recvfrom(socket, (char*)buf, sizeof(buf), 0, (struct sockaddr*)&servAddr, &serv_len);

	if (len < 0){
		return 0;
	}

	dns = (struct dnsheader*)&buf;
	num_answers = htons(dns->ans_count);
	//parse answer
	offset = sizeof(struct dnsheader);		
	offset += letter_counter+1;				
	offset += sizeof(struct question);		
	answer = (struct record*)&buf[offset];		//the start of answer is located after sizeof(dnsheader, leter_counter (length of formated string) and question)
	
	while(num_answers != 0){
		//find LENGTH, which is the length of original offset plus 3x uint16_t if you follow the struct of an answer and 1x uint32
		uint16_t *d_length = (uint16_t*)&buf[offset+sizeof(uint16_t)*3+sizeof(uint32_t)];
		
		//the whole answer length which includes the name, type, class, ttl, data_len (length of data, integer) and d_length(actual data) in network order
		ans_length = sizeof(answer->name) + sizeof(answer->type) + sizeof(answer->class) + sizeof(answer->ttl) + sizeof(answer->data_len) + ntohs(*d_length); //+1
		
		if(ntohs(answer->class) == 1 && ntohs(answer->type) == 1){	//ip address
			answer = (struct record*)&buf[offset-4];
			convert((int)answer->rdata,&result[found]);
			found++;
			offset = offset + ans_length;
			answer = (struct record*)&buf[offset];
		}else{														//cname
			offset = offset + ans_length;
			answer = (struct record*)&buf[offset];
		}
		num_answers--;
	}

	return found;
}

int get_dns(char *query_name,char *dns_server,char **result)
{
	int sockFd;						//actual socket
	int numbers = 0;
	int ret = -1;

	struct record *answer;			//used to parse the ANSWERS
	struct question *queryinfo;


	if(query_name ==NULL || dns_server == NULL){
		return 0;
	}

	//send dns query
	sockFd = prepare_dns_query(query_name,dns_server);
	
	if(sockFd <=0){
		return 0;
	}

	//recieve answer
	numbers = parese_dns(sockFd,dns_server,result);

	return numbers;
}
