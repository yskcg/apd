#include "apd.h"
#include <errno.h>
#include <string.h>

char ac[20];
static struct sproto *spro_new;
static ApCfgInfo apinfo, rcvinfo;
static char ac_info[512] = {'\0'};
apcmd cmdinfo;
static struct uloop_timeout timeout;
static struct uloop_fd apufd;
static char *stamac = NULL;
static int sfd, tt = 300, conn_tmout = 0, mac_len = 0, macnum = 0;
static int live = 0;
#define SERVER_PORT    4444
static struct uci_context *ctx = NULL;
static struct ubus_context *uctx;
static struct blob_buf b;

//for station info
static station_info sta_info;

//for request the ac info ,type=0:need ac's moid sn;
static int ac_type;

int proc_status_cmd(apcmd *cmd);
void rcv_and_proc_data(struct uloop_fd *fd, unsigned int events);
static void get_sta_info(void);
int get_netcard_mac(void);
int create_socket();

int memcat(char *res, char *buf, int slen, int len)
{
	int i;
	if (buf == NULL || len <= 0)
		return 0;
	for(i = 0; i < len; i++){
		res[i + slen] = buf[i];
	}
	res[i + slen] = 0;
	return slen + len;
}

char char_to_data(const char ch)
{
    switch(ch)
    {
    case '0': return 0;
    case '1': return 1;
    case '2': return 2;
    case '3': return 3;
    case '4': return 4;
    case '5': return 5;
    case '6': return 6;
    case '7': return 7;
    case '8': return 8;
    case '9': return 9;
    case 'a':
    case 'A': return 10;
    case 'b':
    case 'B': return 11;
    case 'c':
    case 'C': return 12;
    case 'd':
    case 'D': return 13;
    case 'e':
    case 'E': return 14;
    case 'f':
    case 'F': return 15;
    }
    return 0;
}

static void mac_string_to_value(unsigned char *mac,unsigned char *buf)
{
    int i;
    int len;
	const char * p_temp = mac;

	if(mac && buf){
		len = strlen((const char *)mac);
		for (i=0;i<(len-5)/2;i++){
			//mach_len = sscanf((const char *)mac+i*3,"%2x",&buf[i]);

			buf[i] = char_to_data(*p_temp++) * 16;
			buf[i] += char_to_data(*p_temp++);
			p_temp++;
		}
	}
}

int sproto_read_entity(char *name)
{
	FILE *fp;
	int len;
	unsigned char spro_buf[BUFLEN];
	if ((fp = fopen(name, "rb")) == NULL)
		return -1;
	if ((len = fread(spro_buf, 1, sizeof(spro_buf), fp)) <= 0){
		fclose(fp);
		return 0;
	}
	if ((spro_new = sproto_create(spro_buf, len)) == NULL){
		print_debug_log("[debug] [sproto_create() failed!]\n");
		return 0;
	}
	fclose(fp);
	return len;
}

int sproto_encode_cb(void *ud, const char *tagname, int type, int index, struct sproto_type *st, void *value, int length)
{
	struct encode_ud *self = (encode_ud_info *)ud;
	int sz;

	if (length < 2 * SIZEOF_LENGTH)
		return 0;

	switch (type) {
		case SPROTO_TINTEGER: {
			if (strcasecmp(tagname, "type") == 0)
				*(uint32_t *)value = self->type;
			else if (strcasecmp(tagname, "session") == 0)
				*(uint32_t *)value = self->session;
			else if (strcasecmp(tagname, "apstatus") == 0)
				*(uint32_t *)value = cmdinfo.status;
			else if (strcasecmp(tagname, "stanum") == 0)
				*(uint32_t *)value = cmdinfo.stanum;
			else if (strcasecmp(tagname, "sta_status") == 0)
				*(uint32_t *)value = sta_info.status;
			else if (strcasecmp(tagname, "sta_type") == 0)
				*(uint32_t *)value = sta_info.type;
			else if (strcasecmp(tagname, "ac_type") == 0)
				*(uint32_t *)value = ac_type;

			print_debug_log("[debug] [encode] [%s:%d]\n", tagname, *(int *)value);
			return 4;
		}
		case SPROTO_TBOOLEAN: {
			if (strcasecmp(tagname, "ok") == 0){
				*(int *)value = self->ok;
			}
			print_debug_log("[debug] [encode] [%s:%d]\n", tagname, *(int *)value);
			return 4;
		}
		case SPROTO_TSTRING: {
			if (strcasecmp(tagname, "stamac") == 0){
				if (self->stamac[macnum] != NULL){
					strcpy(value, self->stamac[macnum++]);
					sz = strlen(value);
				}
			}else{
				sz = fill_encode_data(&apinfo, (char *)tagname, (char *)value);
				if(self->type == STA_INFO){
					sz = fill_encode_data_sta_info(&sta_info,(char *)tagname,(char *)value);
				}
			}

			print_debug_log("[debug] [encode][%s:%s,%d]\n",tagname, (char *)value, sz);
			return sz;
		}
		case SPROTO_TSTRUCT: {
			if (strcasecmp(tagname, "smac") == 0 && self->stamac[macnum] == NULL){
				return 0;
			}

			int r = sproto_encode(st, value, length, sproto_encode_cb, self);
			return r;
		}
		default:
			print_debug_log("[debug] [unknown type!]\n");
	}
	return 1;
}

int sproto_encode_data(struct encode_ud *ud, char *res)
{
	int header_len, rpc_len;
	char header[BUFLEN] = {0}, buf[BUFLEN] = {0}, pro_buf[BUFLEN] = {0};
	struct sproto_type *pro_type;
	int size;

	if((pro_type = sproto_type(spro_new, "package")) == NULL){
		print_debug_log("[debug] [sproto_type() failed!]\n");
		return 0;
	}

	if((header_len = sproto_encode(pro_type, header, sizeof(header), sproto_encode_cb, ud)) < 0)
		return 0;
	memcat(buf, header, 0, header_len);

	if((pro_type = sproto_protoquery(spro_new, ud->type, ud->session)) == NULL){
		print_debug_log("[debug] [sproto_protoquery() failed!]\n");
		return 0;
	}

	if((rpc_len = sproto_encode(pro_type, pro_buf, ud->len, sproto_encode_cb, ud)) < 0){
		return 0;
	}

	memcat(buf, pro_buf, header_len, rpc_len);

	size = sproto_pack(buf, header_len + rpc_len, res, sizeof(buf));
	print_debug_log("[debug] [encode len:%d, pack size:%d]\n", header_len + rpc_len, size);
	return size;
}


int sproto_parser_cb(void *ud, const char *tagname, int type, int index, struct sproto_type *st, void *value, int length)
{
	struct encode_ud *self = ud;

	switch (type) {
		case SPROTO_TINTEGER: {
			if (strcasecmp(tagname, "type") == 0)
				self->type = ntohl(*(uint64_t *)value);
			else if (strcasecmp(tagname, "session") == 0)
				self->session = ntohl(*(uint64_t *)value);
			else if (strcasecmp(tagname, "apcmd") == 0)
				cmdinfo.cmd = ntohl(*(uint64_t *)value);

			print_debug_log("[debug] [parser] [%s:%d]\n", tagname, ntohl(*(uint64_t *)value));
			break;
		}
		case SPROTO_TBOOLEAN: {
			self->ok = ntohl(*(uint64_t *)value);
			print_debug_log("[debug] [parser] [%s:%d]\n", tagname, ntohl(*(uint64_t *)value));
			break;
		}
		case SPROTO_TSTRING: {
			if(self->type == AC_INFO){
				if (strcasecmp(tagname, "ac_info") == 0){
					strncpy(ac_info, (char *)value, length);
					print_debug_log("[debug] [parser] [%s:%s,%d],ac_info:%s\n", tagname, (char *)value, length,ac_info);
				}
			}else{
				fill_data(&rcvinfo, (char *)tagname, (char *)value, length);
			}
			print_debug_log("[debug] [parser] [%s:%s,%d]\n", tagname, (char *)value, length);
			break;
		}
		case SPROTO_TSTRUCT: {
			int r = sproto_decode(st, value, length, sproto_parser_cb, self);
			if (r < 0 || r != length)
				return r;
			break;
		}
		default:
			print_debug_log("[debug] [unknown type!]\n");
	}
	return 0;
}

int sproto_header_parser(char *pack, int size, struct encode_ud *ud, char *unpack)
{
	int unpack_len, header_len;
	struct sproto_type *stype;

	if ((unpack_len = sproto_unpack(pack, size, unpack, BUFLEN)) <= 0){
		print_debug_log("[debug] [error] [sproto_unpack() failed!]\n");
		return 0;
	}
	print_debug_log("[debug] [unpack len:%d]\n", unpack_len);
	if ((stype = sproto_type(spro_new, "package")) == NULL){
		print_debug_log("[debug] [error] [sproto_type() failed!]\n");
		return 0;
	}
	if ((header_len = sproto_decode(stype, unpack, unpack_len, sproto_parser_cb, ud)) <= 0){
		print_debug_log("[debug] [error] [sproto_decode() failed!]\n");
		return 0;
	}
	return header_len;
}

int sproto_parser(char *data, int headlen, struct encode_ud *ud)
{
	struct sproto_type *stype;
	int len;

	if ((stype = sproto_protoquery(spro_new, ud->type, ud->session)) == NULL){
		print_debug_log("[debug] [error] [sproto_protoquery() failed!]\n");
		return 0;
	}
	if ((len = sproto_decode(stype, data + headlen, BUFLEN, sproto_parser_cb, ud)) <= 0){
		print_debug_log("[debug] [error] [sproto_decode() failed!]\n");
		return 0;
	}
	return len;
}

int sproto_proc_data(int fd, char *data, int len)
{
	struct encode_ud ud;
	char res[BUFLEN] = {0}, unpack[BUFLEN] = {0};
	int size, length, headlen;
	char shell_cmd[1024] = {'\0'};

	memset(&ud, 0, sizeof(struct encode_ud));

	if ((headlen = sproto_header_parser(data, len, &ud, unpack)) <= 0){
		print_debug_log("[debug] [sproto header parser failed!!]\n");
		return 0;
	}
	print_debug_log("[debug] [header parser] [type:%d,session:%d]\n", ud.type, ud.session);

	if (sproto_parser(unpack, headlen, &ud) <= 0)
	{
		print_debug_log("sproto_parser() failed!\n");
		goto parser_error;
	}
	if (ud.session == SPROTO_RESPONSE)
	{
		if (ud.ok == RESPONSE_OK && ud.type == AP_STATUS){
			if (live == 0) {
				live = 1;
				// authd may change led
				system("(/etc/init.d/authd disable; /etc/init.d/authd stop)");
				system("(uci delete firewall._auth && uci commit firewall && /etc/init.d/firewall restart)");

				system("(ubus call sysd status_led '{\"status\":\"ok\"}')");
				/*stop the dnsmasq*/
				system("(/etc/init.d/dnsmasq disable; /etc/init.d/dnsmasq stop)");

				ud.type = AC_INFO;
				ud.session = SPROTO_REQUEST;
				ud.len = 32;

				size = sproto_encode_data(&ud, res);
				length = write(fd, res, size);
				print_debug_log("%s %d size:%d length:%d\n",__FUNCTION__,__LINE__,size,length);
			}
			conn_tmout = 0;
			return 1;
		}else if (ud.ok == RESPONSE_OK && ud.type == AC_INFO){
			sprintf(shell_cmd,"ubus send %s '%s'",WIFISPIDER_AC_EVENT,ac_info);
			print_debug_log("%s %d shell_cmd:%s\n",__FUNCTION__,__LINE__,shell_cmd);
			system(shell_cmd);
			print_debug_log("%s %d \n",__FUNCTION__,__LINE__);
			return 1;
		}else if (ud.ok == RESPONSE_OK){
			return 1;
		}else{
			ud.session = SPROTO_REQUEST;
		}
		ud.len = 1024;
	}
	else if (ud.session == SPROTO_REQUEST)
	{
		ud.session = SPROTO_RESPONSE;
		ud.ok = RESPONSE_OK;
		ud.len = 30;
		if (ud.type == AP_INFO)
			set_ap_cfg();
		else if (ud.type == AP_CMD)
		{
			size = sproto_encode_data(&ud, res);
			length = write(fd, res, size);
			return proc_status_cmd(&cmdinfo);
		}
	}
	size = sproto_encode_data(&ud, res);
	length = write(fd, res, size);
	if(length < 0)
	{
		print_debug_log("[debug] [Recieve Data From Server %s Failed!]\n");
		return 0;
	}
	return 1;
parser_error:
	ud.session = SPROTO_RESPONSE;
	ud.ok = RESPONSE_ERROR;
	size = sproto_encode_data(&ud, res);
	length = write(fd, res, size);
	return length;
}

int readNlSock(int sockFd, char *bufPtr, int seqNum, int pId)
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

void parseRoutes(struct nlmsghdr *nlHdr, struct route_info *rtInfo,char *gateway, char *ifName)
{
	struct rtmsg *rtMsg;
	struct rtattr *rtAttr;
	int rtLen;
	struct in_addr dst;
	struct in_addr gate;

	rtMsg = (struct rtmsg *)NLMSG_DATA(nlHdr);

	if((rtMsg->rtm_family != AF_INET) || (rtMsg->rtm_table != RT_TABLE_MAIN))
		return;

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
	if (strstr((char *)inet_ntoa(dst), "0.0.0.0"))
	{
		sprintf(ifName, "%s", rtInfo->ifName);
		gate.s_addr = rtInfo->gateWay;
		sprintf(gateway, "%s", (char *)inet_ntoa(gate));
		gate.s_addr = rtInfo->srcAddr;
		gate.s_addr = rtInfo->dstAddr;
	}
	return;
}

int get_gateway(char *gateway, char *ifName)
{
	struct nlmsghdr *nlMsg;
	struct route_info rtInfo;
	char msgBuf[BUFSIZE];
	int sock, len, msgSeq = 0;

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
		print_debug_log("Write To Socket Failed…\n");
		close(sock);
		free(nlMsg);
		return -1;
	}

	if ((len = readNlSock(sock, msgBuf, msgSeq, getpid())) < 0) {
		print_debug_log("Read From Socket Failed…\n");
		close(sock);
		free(nlMsg);
		return -1;
	}
	for( ; NLMSG_OK(nlMsg,len); nlMsg = NLMSG_NEXT(nlMsg,len)){
		memset(&rtInfo, 0, sizeof(struct route_info));
		parseRoutes(nlMsg, &rtInfo, gateway, ifName);
	}
	close(sock);
	if (strlen(ifName) == 0 || strlen(gateway) == 0)
		return 0;
	return 1;
}

int is_ip(const char *str)
{
    struct in_addr addr;
    int ret;

		if (str == NULL)
			return -1;
    ret = inet_pton(AF_INET, str, &addr);
    return ret;
}

int get_ip_in_cfgfile(char *file, char *ip)
{
	FILE *fp;
	char data[1024] = {0}, *str = NULL, *start = NULL, *end = NULL;
	int i, len;
	if ((fp = fopen(file, "r")) == 	NULL){
		print_debug_log("[debug] [open %s failed!!]\n", file);
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
		return;
	}

	fseek(fp, 0, SEEK_END);
	file_size = ftell(fp);

	if (file_size == 0){
		fclose(fp);
		return;
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

int get_ip_in_dhcp_opt(char *file, char *ip)
{
	FILE *fp;
	char data[1024] = {0}, opt[128] = {0};
	int i;
	if ((fp = fopen(file, "r")) == 	NULL){
		print_debug_log("[debug] [open %s failed!!]\n", file);
		return -1;
	}
	fgets(opt, sizeof(opt), fp);
	fclose(fp);
	if (strlen(opt) < 8){
		print_debug_log("[debug] [read /tmp/opt43 failed!!]\n");
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

int get_ac_dns_address(char *ip)
{
	struct hostent *h;

	if((h=gethostbyname(AC_DNS_DOMAIN))==NULL){
		print_debug_log("%s,%d Can't get the IP\n",__FUNCTION__,__LINE__);
		return;
	}

	strcpy(ip,inet_ntoa(*((struct in_addr *)h->h_addr)));
	print_debug_log("%s,%d AC address:%s---%s\n",__FUNCTION__,__LINE__,ip,inet_ntoa(*((struct in_addr *)h->h_addr)));

	return is_ip(ip);
}

int get_gateway_ip(char *ip)
{
	char ifname[20];
	if (ip == NULL)
		return 0;
	if (get_ip_in_cfgfile("/etc/config/ap", ip) > 0){//配置文件路径
		return 1;
	}
	if (get_ip_in_dhcp_opt("/tmp/opt43", ip) > 0){
		return 1;
	}
	if (get_ac_dns_address(ip) >0){
		return 1;
	}
	if (get_gateway(ip, ifname) > 0){
		return 1;
	}

	return 0;
}


static int usage(char *prog)
{
	printf(
			"Usage: %s [OPTIONS] DIRECTORY...\n"
			"Options:\n"
			"        -d     show debug infomastion\n"
			"        -t     set post ap info time\n"
			"\n", prog);
	return 1;
}

int open_file(char *path, char *res, char *flag)
{
	FILE *fp;
	char buf[LINE_MAX], *str, *start, *end;
	if ((fp = fopen(path, "r")) == NULL)
		return -1;
	while(!feof(fp)){
		bzero(buf, sizeof(buf));
		if (fgets(buf, sizeof(buf), fp) == NULL){
			fclose(fp);
			return 0;
		}
		if ((str = strstr(buf, flag)) == NULL)
			continue;
		if ((start = strchr(str, '"')) == NULL && (start = strchr(str, '\'')) == NULL)
			continue;
		if ((end = strchr(start + 1, '"')) == NULL && (end = strchr(start + 1, '\'')) == NULL )
			continue;
		break;
	}
	strncpy(res, start + 1, end - start - 1);
	res[strlen(res)] = 0;
	fclose(fp);
	return 1;
}

int proc_status_cmd(apcmd *cmd)
{
	char addr[100] = {0};

	if (cmd->cmd == 0)
		return 0;

	if (cmd->cmd == REBOOT)
	{
		close(sfd);
		system("reboot");
	}
	else if (cmd->cmd == UPGRADE)
	{
		close(sfd);
		system("rm -rf /etc/config/wireless");
		sprintf(addr, "wget %s -O %s", cmd->addr,"/tmp/ap_firmware.img");
		system(addr);
		memset(addr,'\0',sizeof(addr));
		sprintf(addr, "sysupgrade %s", "/tmp/ap_firmware.img");
		system(addr);
	}
	return 1;
}

int get_ap_revision(void)
{
	char sver[50], hver[50], model[50];
	bzero(sver, sizeof(sver));
	bzero(hver, sizeof(hver));
	if (open_file("/etc/openwrt_release", sver, "RELEASE") <= 0)
		return 0;
	if (open_file("/etc/device_info", hver, "REVISION") <= 0)
		return 0;
	if (open_file("/etc/device_info", model, "PRODUCT") <= 0)
		return 0;
	strncpy(apinfo.hver, hver, 30);
	strncpy(apinfo.sver, sver, 30);
	strncpy(apinfo.model, model, 30);
	print_debug_log("[debug][sw:%s, hw:%s model:%s]\n", sver, hver, model);
	return 1;
}

int get_ap_iwinfo(struct uci_context *c)
{
	int i, len;
	struct uci_ptr p;
	char ifname[100], name[100];

	for (i = 0; ap_iwinfo[i] != NULL; i++){
		bzero(name, sizeof(name));
		bzero(ifname, sizeof(ifname));
		strcpy(ifname, ap_iwinfo[i]);
		strcpy(name, strrchr(ifname, '.') + 1);
		if (uci_lookup_ptr(c, &p, ifname, true) != UCI_OK)
		{
			uci_perror (c, ifname);
			return 0;
		}
		len = strlen(p.o->v.string);
		if (strcasecmp(name, "encryption") == 0)
		{
			bzero(name, sizeof(name));
			strcpy(name, "encrypt");
		}
		print_debug_log("[debug] [ap opt cfg] [%s:%s]\n", name, p.o->v.string);
		fill_data(&apinfo, name, p.o->v.string, len);
	}
	return 1;
}

int del_wireless_cfg(struct uci_context *c, char *section, char *option)
{
	struct uci_ptr ptr ={
		.package = "wireless",
		.section = section,
	};
	if(option){
		ptr.option = option;
	}
	print_debug_log("[debug] [del cfg] [sec:%s, opt:%s]\n", section, option);
	uci_delete(c, &ptr); //写入配置
	uci_commit(c, &ptr.p, false); //提交保存更改
	return 1;
}

int uci_set_cfg(struct uci_context *c, char *section, char *type, char *option, char *value)
{
	struct uci_ptr ptr ={
		.package = "wireless",
		.section = section,
		.value = type,
	};
	uci_set(c, &ptr);

	ptr.option = option;
	ptr.value= value;
	print_debug_log("[debug] [set cfg] [sec:%s, opt:%s, val:%s]\n", section, option, value);
	uci_set(c, &ptr); //写入配置
	uci_commit(c, &ptr.p, false); //提交保存更改
	uci_save(c, ptr.p); //卸载包
	return 1;
}


static int my_strtok(char *src, char *dst[], int n)
{
	char *p;
	int i, j;

	for (i = 0; i < n; i++){
		dst[i] = NULL;
	}

	print_debug_log("[debug] strtok src %s \n", src);

	i = 0;
	p = src;
	dst[i++] = src;
	while(*p) {
		if (*p == ',') {
			*p = 0;
			dst[i++] = p + 1;
		}
		p++;
	}

	for (j = 0; j < i; j++)
		print_debug_log("[debug] strtok dst[%d] %s(%d) \n", j, dst[j], strlen(dst[j]));

	return i;
}

int set_ap_cfg(void)
{
	char path[] = WIRE_CONFIG_FILE;
	int i=0 ,j= 0;
	int n, n1, n2,n3,n4,n5;
	int wifi_iface_number = 0;
	int wifi_device_number = 0;
	char *ssid[MAX_TEMPLATE];
	char *encrypt[MAX_TEMPLATE];
	char *key[MAX_TEMPLATE];
	char *type[MAX_TEMPLATE];
	char *hidden[MAX_TEMPLATE];
	char *disabled[MAX_TEMPLATE];

	char buf[MAX_ITEM_LEN];
	char *option_value = NULL;
	struct uci_package * pkg = NULL;
	struct uci_element *se, *tmp;
	struct uci_section *s;

	wifi_device device_info[MAC_WIFI_DEVICES] = {0};

	ctx = uci_alloc_context();
	if (ctx == NULL){
		return 0;
	}

	if (UCI_OK != uci_load(ctx, path, &pkg)){
		return 0;
	}

	n = my_strtok(rcvinfo.ssid, ssid, MAX_TEMPLATE);
	n1 = my_strtok(rcvinfo.encrypt, encrypt, MAX_TEMPLATE);
	n2 = my_strtok(rcvinfo.key, key, MAX_TEMPLATE);
	n3 = my_strtok(rcvinfo.hidden, hidden, MAX_TEMPLATE);
	n4 = my_strtok(rcvinfo.type, type, MAX_TEMPLATE);
	n5 = my_strtok(rcvinfo.disabled, disabled, MAX_TEMPLATE);

	if (n1 != n || n2 != n || n3!=n || n4!=n || n5!=n ) {
		print_debug_log("[debug] strtok %d %d %d %d %d %d \n", n, n1, n2,n3,n4,n5);
		uci_free_context(ctx);
		ctx = NULL;
		return 0;
	}

	uci_foreach_element_safe(&pkg->sections, tmp, se){
		s = uci_to_section(se);
		print_debug_log("[debug] %s,%d %s %s \n", __FUNCTION__,__LINE__,s->type, s->e.name);
		/*disable the old wireless config*/
		if (strcmp(s->type, "wifi-iface") == 0 && strstr(s->e.name, "cfg") != NULL){
			uci_set_cfg(ctx, s->e.name, "wifi-iface", "disabled", "1");
		}

		/*get the attr of wifi device*/
		if (strcmp(s->type, "wifi-device") == 0 && strstr(s->e.name, "radio") != NULL){
			memcpy(device_info[wifi_device_number].name,s->e.name,strlen(s->e.name) +1);
			print_debug_log("[debug] %s,%d name:%s sizeof:%d strlen:%d\n",__FUNCTION__,__LINE__,device_info[wifi_device_number].name,\
								sizeof(s->e.name),strlen(s->e.name));
			option_value = uci_lookup_option_string(ctx,s,"hwmode");
			if (option_value){
				memcpy(device_info[wifi_device_number].hwmode,option_value,sizeof(option_value));
				print_debug_log("[debug] %s,%d hwmode:%s\n",__FUNCTION__,__LINE__,option_value);
			}
			option_value = uci_lookup_option_string(ctx,s,"htmode");
			if (option_value){
				memcpy(device_info[wifi_device_number].htmode,option_value,sizeof(option_value));
				print_debug_log("[debug] %s,%d htmode:%s\n",__FUNCTION__,__LINE__,option_value);
			}
			option_value = uci_lookup_option_string(ctx,s,"channel");
			if (option_value){
				memcpy(device_info[wifi_device_number].channel,option_value,sizeof(option_value));
				print_debug_log("[debug] %s,%d channel:%s\n",__FUNCTION__,__LINE__,option_value);
			}
			option_value = uci_lookup_option_string(ctx,s,"txpower");
			if (option_value){
				memcpy(device_info[wifi_device_number].txpower,option_value,sizeof(option_value));
				print_debug_log("[debug] %s,%d txpower:%s\n",__FUNCTION__,__LINE__,option_value);
			}

			wifi_device_number = wifi_device_number +1;
		}

		if (strcmp(s->type, "wifi-iface") == 0 && strstr(s->e.name, "__auto_gen_by_ac_") != NULL){
			del_wireless_cfg(ctx, s->e.name, NULL);
			i = i +1;
		}
	}

	if (strlen(rcvinfo.channel) != 0){
		for(i=0;i<wifi_device_number;i++){
			//Not support for 5G chang the channel
			print_debug_log("%s %d hwmode:%s\n",__FUNCTION__,__LINE__,device_info[i].hwmode);
			if(strstr(device_info[i].hwmode,"11a") == NULL ){
				uci_set_cfg(ctx, device_info[i].name, "wifi-device", "channel", rcvinfo.channel);
			}

			if (strlen(rcvinfo.txpower) != 0){
				uci_set_cfg(ctx, "radio0", "wifi-device", "txpower", rcvinfo.txpower);
			}
		}
	}

	for (i = 0; i < n ; i++) {
		for(j=0;j<wifi_device_number;j++){
			sprintf(buf, "__auto_gen_by_ac_%d", wifi_iface_number);
			print_debug_log("%s %d type:%d hwmode:%s\n",__FUNCTION__,__LINE__,atoi(type[i]),device_info[j].hwmode);
			if( atoi(type[i]) == WIRELESS_5_8G ){
				print_debug_log("%s %d \n",__FUNCTION__,__LINE__);

				if ( strstr(device_info[j].hwmode,"11a") != NULL ){
					if (ssid[i] && ssid[i][0] !=0){
						uci_set_cfg(ctx, buf, "wifi-iface", "ssid", ssid[i]);
						if (encrypt[i]){
							uci_set_cfg(ctx, buf, "wifi-iface", "encryption", encrypt[i]);
						}
						if (key[i] && key[i][0] != 0){
							uci_set_cfg(ctx, buf, "wifi-iface", "key", key[i]);
						}

						if (hidden[i] && hidden[i][0] != 0){
							uci_set_cfg(ctx, buf, "wifi-iface", "hidden", hidden[i]);
						}
						if (disabled[i] && disabled[i][0] != 0){
							uci_set_cfg(ctx, buf, "wifi-iface", "disabled", disabled[i]);
						}

						uci_set_cfg(ctx, buf, "wifi-iface", "network", "lan");
						uci_set_cfg(ctx, buf, "wifi-iface", "mode", "ap");
						uci_set_cfg(ctx, buf, "wifi-iface", "device", device_info[j].name);
					}

					wifi_iface_number = wifi_iface_number +1;
				}
			}else if( atoi(type[i]) == WIRELESS_2_4G ){
				if ( strstr(device_info[j].hwmode,"11a") == NULL ){
					if (ssid[i] && ssid[i][0] !=0){
						uci_set_cfg(ctx, buf, "wifi-iface", "ssid", ssid[i]);
						if (encrypt[i]){
							uci_set_cfg(ctx, buf, "wifi-iface", "encryption", encrypt[i]);
						}
						if (key[i] && key[i][0] != 0){
							uci_set_cfg(ctx, buf, "wifi-iface", "key", key[i]);
						}
						if (hidden[i] && hidden[i][0] != 0){
							uci_set_cfg(ctx, buf, "wifi-iface", "hidden", hidden[i]);
						}

						if (disabled[i] && disabled[i][0] != 0){
							uci_set_cfg(ctx, buf, "wifi-iface", "disabled", disabled[i]);
						}

						uci_set_cfg(ctx, buf, "wifi-iface", "network", "lan");
						uci_set_cfg(ctx, buf, "wifi-iface", "mode", "ap");
						uci_set_cfg(ctx, buf, "wifi-iface", "device", device_info[j].name);
					}

					wifi_iface_number = wifi_iface_number +1;
				}
			}else{
				if (ssid[i] && ssid[i][0] !=0){
					uci_set_cfg(ctx, buf, "wifi-iface", "ssid", ssid[i]);
					if (encrypt[i]){
						uci_set_cfg(ctx, buf, "wifi-iface", "encryption", encrypt[i]);
					}
					if (key[i] && key[i][0] != 0){
						uci_set_cfg(ctx, buf, "wifi-iface", "key", key[i]);
					}
					if (hidden[i] && hidden[i][0] != 0){
						uci_set_cfg(ctx, buf, "wifi-iface", "hidden", hidden[i]);
					}

					if (disabled[i] && disabled[i][0] != 0){
						uci_set_cfg(ctx, buf, "wifi-iface", "disabled", disabled[i]);
					}

					uci_set_cfg(ctx, buf, "wifi-iface", "network", "lan");
					uci_set_cfg(ctx, buf, "wifi-iface", "mode", "ap");
					uci_set_cfg(ctx, buf, "wifi-iface", "device", device_info[j].name);
				}

				wifi_iface_number = wifi_iface_number +1;
			}
		}
	}

	uci_free_context(ctx);
	ctx = NULL;
	system("wifi restart");
	return 1;
}

int fill_encode_data(ApCfgInfo *apcfg,char *tagname, char *value)
{
	if (apcfg == NULL)
		return 0;
	if (strcasecmp(tagname, "hver") == 0)
		strcpy(value, apcfg->hver);
	else if (strcasecmp(tagname, "sver") == 0)
		strcpy(value, apcfg->sver);
	else if (strcasecmp(tagname, "mac") == 0)
		strcpy(value, apcfg->apmac);
	else if (strcasecmp(tagname, "sn") == 0)
		strcpy(value, apcfg->sn);
	else if (strcasecmp(tagname, "model") == 0)
		strcpy(value, apcfg->model);
	else if (strcasecmp(tagname, "aip") == 0)
		strcpy(value, apcfg->aip);
	else if (strcasecmp(tagname, "txpower") == 0)
		strcpy(value, "20");//apcfg->txpower);
	return strlen(value);
}

int fill_encode_data_sta_info(station_info *sta_info,char *tagname, char *value)
{
	if (sta_info == NULL)
		return 0;
	if (strcasecmp(tagname, "sta_mac") == 0)
		strcpy(value, &(sta_info->station_mac[0]));
	else if (strcasecmp(tagname, "sta_bssid") == 0)
		strcpy(value, &(sta_info->bssid[0]));
	else if (strcasecmp(tagname, "sta_ssid") == 0)
		strcpy(value, &(sta_info->ssid[0]));
	else if (strcasecmp(tagname, "sta_ap_mac") == 0)
		strcpy(value, &(sta_info->ap_mac[0]));

	return strlen(value);
}

void fill_data(ApCfgInfo *apcfg,char *tagname, char *value, int len)
{
	if (strlen(value) == 0)
		return;

	if (strcasecmp(tagname, "ssid") == 0)
		strncpy(apcfg->ssid, value, len);
	else if (strcasecmp(tagname, "channel") == 0)
		strncpy(apcfg->channel, value, len);
	else if (strcasecmp(tagname, "encrypt") == 0)
		strncpy(apcfg->encrypt, value, len);
	else if (strcasecmp(tagname, "key") == 0)
		strncpy(apcfg->key, value, len);
	else if (strcasecmp(tagname, "txpower") == 0)
		strncpy(apcfg->txpower, value, len);
	else if (strcasecmp(tagname, "addr") == 0)
		strncpy(cmdinfo.addr, value, len);
	else if (strcasecmp(tagname, "type") == 0)
		strncpy(apcfg->type,value,len);
	else if (strcasecmp(tagname, "hidden") == 0)
		strncpy(apcfg->hidden,value,len);
	else if (strcasecmp(tagname, "disabled") == 0)
		strncpy(apcfg->disabled,value,len);

	apcfg->flage = 1;
	return;
}

int ap_post_data(void)
{
	struct encode_ud ud;
	char res[2056] = {0};
	int size, len;

	if (strcasecmp(apinfo.apmac, "00:00:00:00:00:00") == 0){
		return -1;
	}

	memset(&ud, 0, sizeof(struct encode_ud));
	ud.type = AP_STATUS;
	ud.session = SPROTO_REQUEST;
	ud.stamac[0] = NULL;
	ud.len = 200;

	if ((size = sproto_encode_data(&ud, res)) <= 0){
		print_debug_log("[debug] [encode data failed!]\n");
		return 0;
	}

	if (sfd <= 0)
		return 0;
	len = write(sfd, res, size);
	print_debug_log("[debug] [write] [data len:%d]\n", len);
	return len;
}

int get_sta_mac(char mac[][18], struct encode_ud *ud)
{
	char *buf = NULL, *str = NULL;
	int i = 0;

	if (stamac == NULL)
		return -1;
	buf = alloca(mac_len);
	memset(buf, 0, mac_len);
	strcpy(buf, stamac);
	str = strtok(buf, ",");
	while(str)
	{
		strncpy(mac[i], str, 17);
		ud->stamac[i] = mac[i];
		mac[i][17] = 0;
		i++;
		str = strtok(NULL, ",");
	}
	ud->stamac[i] = NULL;
	free(stamac);
	stamac = NULL;
	mac_len = 0;
	macnum = 0;
	return i;
}

void  ap_connect_status(struct uloop_timeout *t)
{
	int len, size;
	char res[1024 * 6] = {0};
	char mac[32][18] = {{0}};
	struct encode_ud ud;

	memset(&ud, 0, sizeof(struct encode_ud));
	if (conn_tmout >= 3 || sfd <= 0){
		if (sfd > 0){
			uloop_fd_delete(&apufd);
			close(sfd);
			print_debug_log("%s,%d\n",__FUNCTION__,__LINE__,conn_tmout);
		}
		sfd = 0;

		while(1){
			if (create_socket() == 0)
				break;
			sleep(2);
		}
		print_debug_log("[debug] [NEW] [connect]!!\n");
		uloop_fd_add(&apufd, ULOOP_READ);
		ap_post_data();
		conn_tmout = 0;
		goto timeset;
	}

	get_sta_info();
	cmdinfo.stanum = get_sta_mac(mac, &ud);
	cmdinfo.status = AP_ON;
	ud.type = AP_STATUS;
	ud.session = SPROTO_REQUEST;
	ud.len = (cmdinfo.stanum + 7) * 25;
	if ((size = sproto_encode_data(&ud, res)) <= 0){
		print_debug_log("[debug] [encode data failed!]\n");
		goto timeset;
	}

	conn_tmout++;
	if((len = write(sfd, res, size)) <= 0){
		print_debug_log("Recieve Data From Server %s Failed!\n");
		close(sfd);
		sfd = 0;
		goto timeset;
	}
	print_debug_log("[debug] <send> [data len:%d]\n", len);

timeset:
	uloop_timeout_set(t, 15000);
	return;
}

void rcv_and_proc_data(struct uloop_fd *fd, unsigned int events)
{
	print_debug_log("[debug] [error info] %d %s %d (%d %d)\n", errno, strerror(errno), events, fd->eof, fd->error);
	char buf[BUFLEN] = {0};
	int len;

	if (fd->eof || fd->error) {
		uloop_fd_delete(&apufd);
		close(sfd);
		sfd = 0;
		fd->fd = 0;
		return;
	}
	if (fd->fd <= 0) {
		return;
	}
	len = read(fd->fd, buf, sizeof(buf));
	print_debug_log("[debug] [read data len:%d]\n", len);

	if (len <= 0){
		print_debug_log("[debug] [read data error or server closed!]\n");
		return;
	}
	print_debug_log("[debug] [rcv] [data len:%d]\n", len);
	memset(&rcvinfo, 0, sizeof(ApCfgInfo));
	memset(&cmdinfo, 0, sizeof(apcmd));
	if (sproto_proc_data(sfd, buf, len) <= 0){
		print_debug_log("[debug] [process data failed!]\n");
	}

	return;
}

void print_debug_log(const char *form ,...)
{
	if(debug == NULL)
		return;

	va_list arg;
	char pbString[256];

	va_start(arg,form);
	vsprintf(pbString, form, arg);
	fprintf(debug, pbString);
	va_end(arg);
	return;
}

void get_sn(void)
{
	FILE *fp;
	int i;
	char *p;
	char data[1024];
	if ((fp = fopen("/etc/sn", "r")) == NULL)
		return;
	memset(data, 0, sizeof(data));
	fgets(data, sizeof(data), fp);
	fclose(fp);

	i = 0;
	p = data;
	while (i < 14 && *p != 0 && *p != '\r' && *p != '\n') {
		if (*p != '\t' && *p != ' ')
			apinfo.sn[i++] = *p;
		p++;
	}
	apinfo.sn[i] = 0;

	return;
}

void apd_init(void)
{
	if (sproto_read_entity("/usr/share/apc.sp") <= 0)
	{
		print_debug_log("[debug] [protocol not exsited!!]\n");
		exit(0);
	}
	get_ap_revision();
	get_sn();
	get_netcard_mac();
	return;
}

static struct ubus_object apd_object;

static const struct blobmsg_policy return_policy[__STA_MAX] = {
	[STAINFO] = { .name = "results", .type = BLOBMSG_TYPE_ARRAY },
};

static const struct blobmsg_policy sta_policy[__STA_MAX] = {
	[MAC] = { .name = "mac", .type = BLOBMSG_TYPE_STRING },
	[SIGNAL] = { .name = "signal", .type = BLOBMSG_TYPE_INT32 },
	[NOISE] = { .name = "noise", .type = BLOBMSG_TYPE_INT32 },
	[ACT] = { .name = "inactive", .type = BLOBMSG_TYPE_INT32 },
	[RX] = { .name = "rx", .type = BLOBMSG_TYPE_TABLE },
	[TX] = { .name = "tx", .type = BLOBMSG_TYPE_TABLE },
};

static void apd_ubus_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct blob_attr *tb[__STA_MAX], *attr;
	int len;

	blobmsg_parse(return_policy, __STA_MAX, tb, blob_data(msg), blob_len(msg));
	if (!tb[STAINFO]) {
		fprintf(stderr, "No return code received from server\n");
		return;
	}
	blobmsg_for_each_attr(attr, tb[STAINFO], len)
	{
		blobmsg_parse(sta_policy, __STA_MAX, tb, blobmsg_data(attr), blobmsg_data_len(attr));
		if (tb[MAC])
		{
			if (mac_len - strlen(stamac) < 18)
			{
				mac_len += 100;
				stamac = realloc(stamac, mac_len);
			}
			sprintf(stamac + strlen(stamac), "%s,", blobmsg_get_string(tb[MAC]));
		}
	}
	return;
}

int foreach_wlan(char name[][10])
{
	FILE *fp;
	int i = 0;
	char *str = NULL, buf[1024], *end = NULL;

	if ((fp = fopen("/proc/net/dev", "r")) == NULL)
		return -1;
	while(!feof(fp))
	{
		bzero(buf, sizeof(buf));
		fgets(buf, sizeof(buf), fp);
		if ((str = strstr(buf, "wlan")) == NULL)
			continue;
		end = strstr(str, ":");
		strncpy(name[i], str, end - str);
		name[++i][0] = 0;
	}
	fclose(fp);
	return 1;
}

static void get_sta_info(void)
{
	uint32_t id, i;
	char wname[10][10] = {{0}};
	if (ubus_lookup_id(uctx, "iwinfo", &id)) {
		fprintf(stderr, "Failed to look up auth object\n");
		return;
	}
	if (stamac == NULL)
	{
		if ((stamac = calloc(100, 1)) == NULL)
			return;
		mac_len = 100;
	}
	foreach_wlan(wname);
	for(i = 0; wname[i][0] != 0; i++)
	{
		blob_buf_init(&b, 0);
		blobmsg_add_string(&b, "device", wname[i]);
		ubus_invoke(uctx, id, "assoclist", b.head, apd_ubus_cb, NULL, 2000);
	}
	return;
}

void get_host_ip(char *hostip)
{
	char shell_cmd[128] = {'\0'};
    int file_size;
    char buf[32] = {'\0'};
    FILE *fp = NULL;
	
	memset(hostip,'\0',sizeof(hostip));
	sprintf(shell_cmd,"ip -4 addr show dev br-lan | grep inet | awk '{print$2}' | sed -e 's/\\/.*//g' | sed -e '/%s/d' >%s",DEFAULT_DEVICE_IP,HOST_IP_FILE);
	
	print_debug_log("%s %d shell_cmd:%s\n",shell_cmd);
    system(shell_cmd);

    if (access(HOST_IP_FILE,F_OK) !=0){
        return ;
    }

    if ((fp = fopen(HOST_IP_FILE, "r")) == NULL){
        return;
    }

    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);

    if (file_size == 0){
        fclose(fp);
        unlink(HOST_IP_FILE);
        return;
    }

    fseek(fp,0,SEEK_SET);
    /*get the aplist file content*/
    while((fgets(buf,32,fp))!=NULL){
        /*get the mac address of ap*/
        if (!(strlen(buf) <=1 && buf[0] ==10)){
            strncpy(hostip,buf,strlen(buf));
            memset(buf,'\0',sizeof(buf));
        }
    }

    fclose(fp);
    unlink(HOST_IP_FILE);
	hostip[strlen(hostip)-1] = '\0';
	print_debug_log("%s %d hostip:%s\n",__FUNCTION__,__LINE__,hostip);
    return ;

}

int create_socket()
{
	//struct sockaddr_in loc_addr;
	struct sockaddr_in remo_addr;
	char hostip[INET_ADDRSTRLEN] = {0};
	char ac_addr[32] = {'\0'};
	char cmd[256];

	if (live == 1) {
		live = 0;
		system("(ubus call sysd status_led '{\"status\":\"linklost\"}')");
	}

	if (is_ip(ac) > 0)
		strncpy(ac_addr, ac, 20);
	else {
		/*1: go to find the gateway address or option 43 ac dns domain*/
		memset(ac_addr,'\0',sizeof(ac_addr));
		get_gateway_ip(ac_addr);

		if (get_gateway_ip(ac_addr) <= 0){
			print_debug_log("[debug [ac addr] Can't get the ac control address !!!]");
			return -1;
		}

	}

	print_debug_log("[debug] [ac_addr ip:%s]\n", ac_addr);

	sprintf(cmd, "ping -q -c 3 %s || killall udhcpc", ac_addr);
	system(cmd);


	get_host_ip(hostip);
	if (is_ip(hostip) <= 0)
		return -1;

	strcpy(apinfo.aip, hostip);

	if((sfd = socket(AF_INET, SOCK_STREAM, 0)) <= 0){
		print_debug_log("Create Socket Failed!\n");
		return -1;
	}
	
	remo_addr.sin_family = AF_INET;
	remo_addr.sin_port = htons(SERVER_PORT);
	remo_addr.sin_addr.s_addr = inet_addr(ac_addr);
	if(connect(sfd, (struct sockaddr*)&remo_addr, (socklen_t)sizeof(remo_addr)) < 0){
		print_debug_log("[debug] [Can Not Connect To %s!]\n", ac_addr);
		close(sfd);
		return -1;
	}

	apufd.cb = rcv_and_proc_data;
	apufd.fd = sfd;
	return 0;
}

static void apd_ubus_receive_event(struct ubus_context *ctx, struct ubus_event_handler *ev,
			  const char *type, struct blob_attr *msg)
{
	unsigned char mac[6] = {0};
	char res[1024] = {0};
	int size, len;
	char *str;
	int wifi_type;
	char *buf = NULL;
	struct encode_ud ud;

	str = blobmsg_format_json(msg, true);

	if(strcmp(type,APD_LISTEN_EVENT_ON) == 0){
		memset(&ud, 0, sizeof(struct encode_ud));
		ud.type = STA_INFO;
		ud.session = SPROTO_REQUEST;
		ud.stamac[0] = NULL;
		ud.len = 200;

		memset(&sta_info,0,sizeof(sta_info));

		json_parse(str,"station_mac",&(sta_info.station_mac[0]));
		/*dele the ':' and make string to int*/
		mac_string_to_value(&(sta_info.station_mac[0]),mac);
		if (is_broadcast_ether_addr((const u8 *)mac) || is_multicast_ether_addr((const u8 *)mac) || is_zero_ether_addr((const u8 *)mac)){
			return ;
		}

		json_parse(str,"bssid",&(sta_info.bssid[0]));
		memset(mac,0,sizeof(mac));
		mac_string_to_value(&(sta_info.bssid[0]),mac);
		print_debug_log("%s %d bssid=%02x:%02x:%02x:%02x:%02x:%02x\n",__FUNCTION__,__LINE__,\
						mac[0]&0xff,mac[1]&0xff,mac[2]&0xff,mac[3]&0xff,mac[4]&0xff,mac[5]&0xff);
		if (is_broadcast_ether_addr((const u8 *)mac) || is_multicast_ether_addr((const u8 *)mac) || is_zero_ether_addr((const u8 *)mac)){
			return ;
		}

		json_parse(str,"type",&(wifi_type));
		sta_info.type = atoi(&wifi_type);
		json_parse(str,"ssid",&(sta_info.ssid[0]));
		memcpy(sta_info.ap_mac,apinfo.apmac,sizeof(apinfo.apmac));

		sta_info.status = STATION_ON;

		print_debug_log("%s %d  station_mac:%s\n",__FUNCTION__,__LINE__,sta_info.station_mac);
		print_debug_log("%s %d  status:%d\n",__FUNCTION__,__LINE__,sta_info.status);
		print_debug_log("%s %d  ssid:%s\n",__FUNCTION__,__LINE__,sta_info.ssid);
		print_debug_log("%s %d  bssid:%s\n",__FUNCTION__,__LINE__,sta_info.bssid);
		print_debug_log("%s %d  type:%d\n",__FUNCTION__,__LINE__,sta_info.type);
		print_debug_log("%s %d  ap_mac:%s\n",__FUNCTION__,__LINE__,sta_info.ap_mac);
		if ((size = sproto_encode_data(&ud, res)) <= 0){
			print_debug_log("[debug] [encode data failed!]\n");
			return 0;
		}

		if (sfd <= 0)
			return 0;
		len = write(sfd, res, size);
	}

	free(str);
}

static int apd_ubus_listen(struct ubus_context *ctx, char * type)
{
	static struct ubus_event_handler listener;
	const char *event;
	int ret = 0;

	memset(&listener, 0, sizeof(listener));
	listener.cb = apd_ubus_receive_event;

	if (type == NULL){
		return 0;
	}

	event = type;

	ret = ubus_register_event_handler(ctx, &listener, event);
	if (ret){
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int ch;
	const char *ubus_socket = NULL;
	char network_mode[32] = {0};
	FILE *network_fp = NULL;
	struct stat st;
	long int size;
	long int read_size;

	while ((ch = getopt(argc, argv, "dt:i:")) != -1) {
		switch(ch) {
			case 'd':
				debug = stdout;
				break;
			case 't':
				tt = atoi(optarg);
				break;
			case 's':
				ubus_socket = optarg;
				break;
			case 'i':
				strcpy(ac, optarg);
				break;
			default:
				return usage(argv[0]);
		}
	}
	memset(&apinfo, 0, sizeof(ApCfgInfo));
	memset(&cmdinfo, 0, sizeof(apcmd));
	/*wan mode exit*/
	bzero(network_mode, sizeof(network_mode));
	system(". /sbin/network_mode.sh");
	network_fp = fopen("/tmp/log/network_mode","r");
	if (! network_fp){
		return 0;
	}

	stat("/tmp/log/network_mode", &st);
	size = st.st_size;
	if (size >32){
		size = 32;
	}
	read_size = fread(network_mode,size,1,network_fp);
	if(read_size <= 0){
		return 0;
	}

	/*route mode exit the process*/
	if (strstr(network_mode,"route")){
		printf("route mode\n");
		return 0;
	}

	while(1){
		if (create_socket() == 0)
			break;
		sleep(2);
	}
	signal (SIGPIPE, SIG_IGN);
	uloop_init();
	timeout.cb = ap_connect_status;
	uctx = ubus_connect(ubus_socket);
	if (!uctx) {
		fprintf(stderr, "Failed to connect to ubus\n");
		return -1;
	}

	apd_ubus_listen(uctx,APD_LISTEN_EVENT_ON);
	//apd_ubus_listen(uctx,APD_LISTEN_EVENT_OFF);
	ubus_add_uloop(uctx);
	int ret = ubus_add_object(uctx, &apd_object);
	if (ret) {
		fprintf(stderr, "Failed to add_object object: %s\n", ubus_strerror(ret));
		return  -1;
	}
	apd_init();
	ap_post_data();
	uloop_fd_add(&apufd, ULOOP_READ);
	uloop_timeout_set(&timeout, 10000);
	uloop_run();
	uloop_done();
	ubus_free(uctx);
	close(sfd);
	return 0;
}



