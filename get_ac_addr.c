#include "get_ac_addr.h"

static int readNlSock(int sockFd, char *bufPtr, int seqNum, int pId)
{
	struct nlmsghdr *nlHdr;
	int readLen = 0, msgLen = 0;
	do
	{
		if((readLen = recv(sockFd, bufPtr, BUFSIZE - msgLen, 0)) < 0)
		{
			perror("SOCK READ: ");
			return -1;
		}
		nlHdr = (struct nlmsghdr *)bufPtr;
		if((NLMSG_OK(nlHdr, readLen) == 0) || (nlHdr->nlmsg_type == NLMSG_ERROR))
		{
			perror("Error in recieved packet");
			return -1;
		}
		if(nlHdr->nlmsg_type == NLMSG_DONE)
			break;
		else
		{
			bufPtr += readLen;
			msgLen += readLen;
		}
		if((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0)
			break;
	}while((nlHdr->nlmsg_seq != seqNum) || (nlHdr->nlmsg_pid != pId));

	return msgLen;
}

static unsigned long int parseRoutes(struct nlmsghdr *nlHdr, struct route_info *rtInfo, char *ifName)
{
	struct rtmsg *rtMsg;
	struct rtattr *rtAttr;
	int rtLen;
	struct in_addr dst;
	struct in_addr gate;

	rtMsg = (struct rtmsg *)NLMSG_DATA(nlHdr);

	if((rtMsg->rtm_family != AF_INET) || (rtMsg->rtm_table != RT_TABLE_MAIN)){
		return 0;;
	}

	
	rtAttr = (struct rtattr *)RTM_RTA(rtMsg);
	rtLen = RTM_PAYLOAD(nlHdr);
	for(;RTA_OK(rtAttr,rtLen);rtAttr = RTA_NEXT(rtAttr,rtLen)){
		switch(rtAttr->rta_type) {
			case RTA_OIF:
				if_indextoname(*(int *)RTA_DATA(rtAttr), rtInfo->ifName);
				break;
			case RTA_GATEWAY:
				rtInfo->gateWay = *(u_int *)RTA_DATA(rtAttr);
				break;
			case RTA_PREFSRC:
				rtInfo->srcAddr = *(u_int *)RTA_DATA(rtAttr);
				break;
			case RTA_DST:
				rtInfo->dstAddr = *(u_int *)RTA_DATA(rtAttr);
				break;
		}
	}

	
	dst.s_addr = rtInfo->dstAddr;
	if (strstr((char *)inet_ntoa(dst), "0.0.0.0")){
		sprintf(ifName, "%s", rtInfo->ifName);
		gate.s_addr = rtInfo->gateWay;
		return gate.s_addr;
	}else{
		return 0;
	}
}

static int get_gateway(char *ifName)
{
	struct nlmsghdr *nlMsg;
	struct route_info rtInfo;
	char msgBuf[BUFSIZE];
	int sock, len, msgSeq = 0;
	unsigned long int  ip_int = 0;

	if((sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0)
	{
		perror("Socket Creation: ");
		return -1;
	}
	memset(msgBuf, 0, BUFSIZE);

	nlMsg = (struct nlmsghdr *)msgBuf;

	nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)); // Length of message.
	nlMsg->nlmsg_type = RTM_GETROUTE; // Get the routes from kernel routing table .

	nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST; // The message is a request for dump.
	nlMsg->nlmsg_seq = msgSeq++; // Sequence of the message packet.
	nlMsg->nlmsg_pid = getpid(); // PID of process sending the request.

	if (send(sock, nlMsg, nlMsg->nlmsg_len, 0) < 0){
		print_debug_log("Write To Socket Failed¡­\n");
		close(sock);
		return -1;
	}

	
	if ((len = readNlSock(sock, msgBuf, msgSeq, getpid())) < 0) {
		print_debug_log("Read From Socket Failed¡­\n");
		close(sock);
		return -1;
	}
	for( ; NLMSG_OK(nlMsg,len); nlMsg = NLMSG_NEXT(nlMsg,len)){

		memset(&rtInfo, 0, sizeof(struct route_info));
		ip_int = parseRoutes(nlMsg, &rtInfo,ifName);
		if( ip_int >0){
			break;
		}
	}

	close(sock);
	if (strlen(ifName) == 0 )
		return 0;
	return ip_int;
}

static int get_ac_dns_address(char *ip)
{
	struct hostent *h;
	int numbers = 0;
	unsigned long int ip_int = 0;
	char ifname[20];
	char result[4][64] = {0};

	if((h=gethostbyname(AC_DNS_DOMAIN)) ==NULL){
		print_debug_log("%s,%d Can't get the IP\n",__FUNCTION__,__LINE__);
		//try other method --get the dns from the gateway
		ip_int = get_gateway(ifname);
		if ( ip_int > 0){
			numbers = get_dns(AC_DNS_DOMAIN,ip_int,result);
			print_debug_log("%d \n",numbers);
			if(numbers >0){
				print_debug_log("%s %d hostname:%s address:%s\n",__FUNCTION__,__LINE__,AC_DNS_DOMAIN,&result[0]);
				strcpy(ip,(const char *)&result[0]);
			}
		}
		
		return is_ip(ip);
	}

	strcpy(ip,inet_ntoa(*((struct in_addr *)h->h_addr)));
	print_debug_log("%s,%d AC address:%s---%s\n",__FUNCTION__,__LINE__,ip,inet_ntoa(*((struct in_addr *)h->h_addr)));

	return is_ip(ip);
}

static int get_ip_in_cfgfile(char *file, char *ip)
{
	FILE *fp;
	char data[1024] = {0}, *str = NULL, *start = NULL, *end = NULL;
	int i, len;
	if ((fp = fopen(file, "r")) == 	NULL){
		print_debug_log("[open %s failed!!]\n", file);
		return -1;
	}
	while(!feof(fp))
	{
		memset(data, 0, sizeof(data));
		fgets(data, sizeof(data), fp);
		if ((str = strstr(data, "AC_IP_ADDR")) == NULL)
			continue;
		len = strlen(str);
		for(i = 0; i < len; i++)
		{
			start = str + i;
			if(*start >= '1' && *start <= '9')
				break;
		}
		if ((end = strstr(start, "'")) == NULL)
			end = strstr(start, "\n");
		*end = '\0';

		strcpy(ip, start);
		break;
	}
	fclose(fp);
	return is_ip(ip);
}

int get_netcard_mac(void)
{
	/*get the mac address from flash*/
	int file_size;
	char shell_cmd[128] = {'\0'};
	char buf[32] = {'\0'};
	FILE *fp = NULL;

	sprintf(shell_cmd," . /usr/sbin/get_mac.sh");
	system(shell_cmd);

	sleep(1);

	if (access(MAC_ADDRESS_FILE,F_OK) !=0){
		return -1;
	}

	if ((fp = fopen(MAC_ADDRESS_FILE, "r")) == NULL){
		return -1;
	}

	fseek(fp, 0, SEEK_END);
	file_size = ftell(fp);

	if (file_size == 0){
		fclose(fp);
		return -1;
	}

	fseek(fp,0,SEEK_SET);
	/*get the aplist file content*/
	while((fgets(buf,32,fp))!=NULL){
		/*get the mac address of ap*/
		if (!(strlen(buf) <=1 && buf[0] ==10)){
			memset(apinfo.apmac,'\0',sizeof(apinfo.apmac));
			strncpy(apinfo.apmac,buf,strlen(buf));
			memset(buf,'\0',sizeof(buf));
		}
	}

	fclose(fp);

	return 1;
}

static int get_ip_in_dhcp_opt(char *file, char *ip)
{
	FILE *fp;
	char data[1024] = {0}, opt[128] = {0};
	int i;
	if ((fp = fopen(file, "r")) == 	NULL){
		print_debug_log("[open %s failed!!]\n", file);
		return -1;
	}
	fgets(opt, sizeof(opt), fp);
	fclose(fp);
	if (strlen(opt) < 8){
		print_debug_log("[read /tmp/opt43 failed!!]\n");
		return -1;
	}
	opt[strlen(opt) - 1] = 0;
	for(i = 0; i < 7; i++)
	{
		memset(data, 0, sizeof(data));
		sprintf(data, "%c%c", opt[i], opt[i + 1]);
		i++;
		if (strlen(ip) == 0)
			sprintf(ip + strlen(ip), "%ld", strtol(data, NULL, 16));
		else
			sprintf(ip + strlen(ip), ".%ld", strtol(data, NULL, 16));
	}
	return is_ip(ip);
}

int get_gateway_ip(char *ip)
{
	char ifname[20];
	unsigned long int ip_int = 0;
	struct in_addr in;

	if (ip == NULL)
		return 0;
	if (get_ip_in_cfgfile("/etc/config/ap", ip) > 0){//ÅäÖÃÎÄ¼þÂ·¾¶
		return 1;
	}
	
	if (get_ip_in_dhcp_opt("/tmp/opt43", ip) > 0){
		return 1;
	}
	
	if (get_ac_dns_address(ip) >0){
		return 1;
	}
	
	ip_int = get_gateway(ifname);
	if ( ip_int <= 0){
		return 0;
	}else{
		in.s_addr = ip_int;
		sprintf(ip, "%s", (char *)inet_ntoa(in));
		return 1;
	}

	return 0;
}
