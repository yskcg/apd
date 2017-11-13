#include "apd.h"
#include <errno.h>
#include <string.h>


queue_rev_msg recv_msg;
static struct sproto *spro_new;
ApCfgInfo rcvinfo;
static char ac_info[512] = {'\0'};
char ac[20];
apcmd cmdinfo;
static struct uloop_timeout timeout;
static struct uloop_fd apufd;
int sfd;
static int tt = 300, conn_tmout = 0, macnum = 0;
static int live = 0;

//for station info
station_info sta_info;

//for request the ac info ,type=0:need ac's moid sn;
static int ac_type;

int proc_status_cmd(apcmd *cmd);
void rcv_and_proc_data(struct uloop_fd *fd, unsigned int events);
int create_socket();


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
		print_debug_log("[sproto_create() failed!]\n");
		return 0;
	}
	fclose(fp);
	return len;
}

int sproto_encode_cb(void *ud, const char *tagname, int type, int index, struct sproto_type *st, void *value, int length)
{
	struct encode_ud *self = (encode_ud_info *)ud;
	int sz = 0;

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
			else if (strcasecmp(tagname, "sta_status") == 0)
				*(uint32_t *)value = sta_info.status;
			else if (strcasecmp(tagname, "sta_type") == 0)
				*(uint32_t *)value = sta_info.type;
			else if (strcasecmp(tagname, "ac_type") == 0)
				*(uint32_t *)value = ac_type;

			print_debug_log("[encode] [%s:%d]\n", tagname, *(int *)value);
			return 4;
		}
		case SPROTO_TBOOLEAN: {
			if (strcasecmp(tagname, "ok") == 0){
				*(int *)value = self->ok;
			}
			print_debug_log("[encode] [%s:%d]\n", tagname, *(int *)value);
			return 4;
		}
		case SPROTO_TSTRING: {
			if (strcasecmp(tagname, "stamac") == 0){
				if (self->stamac[macnum] != NULL){
					strcpy(value, self->stamac[macnum++]);
					sz = strlen((const char *)value);
				}
			}else{
				sz = fill_encode_data(&apinfo, (char *)tagname, (char *)value);
				if(self->type == STA_INFO){
					sz = fill_encode_data_sta_info(&sta_info,(char *)tagname,(char *)value);
				}
			}

			print_debug_log("[encode][%s:%s,%d]\n",tagname, (char *)value, sz);
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
			print_debug_log("[unknown type!]\n");
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
		print_debug_log("[sproto_type() failed!]\n");
		return 0;
	}

	if((header_len = sproto_encode(pro_type, header, sizeof(header), sproto_encode_cb, ud)) < 0)
		return 0;
	memcat(buf, header, 0, header_len);

	if((pro_type = sproto_protoquery(spro_new, ud->type, ud->session)) == NULL){
		print_debug_log("[sproto_protoquery() failed!]\n");
		return 0;
	}

	if((rpc_len = sproto_encode(pro_type, pro_buf, ud->len, sproto_encode_cb, ud)) < 0){
		return 0;
	}

	memcat(buf, pro_buf, header_len, rpc_len);

	size = sproto_pack(buf, header_len + rpc_len, res, sizeof(buf));
	print_debug_log("[encode len:%d, pack size:%d]\n", header_len + rpc_len, size);
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

			print_debug_log("[parser] [%s:%d]\n", tagname, ntohl(*(uint64_t *)value));
			break;
		}
		case SPROTO_TBOOLEAN: {
			self->ok = ntohl(*(uint64_t *)value);
			print_debug_log("[parser] [%s:%d]\n", tagname, ntohl(*(uint64_t *)value));
			break;
		}
		case SPROTO_TSTRING: {
			if(self->type == AC_INFO){
				if (strcasecmp(tagname, "ac_info") == 0){
					strncpy(ac_info, (char *)value, length);
					print_debug_log("[parser] [%s:%s,%d],ac_info:%s\n", tagname, (char *)value, length,ac_info);
				}
			}else{
				fill_data(&rcvinfo, (char *)tagname, (char *)value, length);
			}
			print_debug_log("[parser] [%s:%s,%d]\n", tagname, (char *)value, length);
			break;
		}
		case SPROTO_TSTRUCT: {
			int r = sproto_decode(st, value, length, sproto_parser_cb, self);
			if (r < 0 || r != length)
				return r;
			break;
		}
		default:
			print_debug_log("[unknown type!]\n");
	}
	return 0;
}

int sproto_header_parser(char *pack, int size, struct encode_ud *ud, char *unpack)
{
	int unpack_len, header_len;
	struct sproto_type *stype;

	if ((unpack_len = sproto_unpack(pack, size, unpack, BUFLEN)) <= 0){
		print_debug_log("[error] [sproto_unpack() failed!]\n");
		return 0;
	}
	print_debug_log("[unpack len:%d]\n", unpack_len);
	if ((stype = sproto_type(spro_new, "package")) == NULL){
		print_debug_log("[error] [sproto_type() failed!]\n");
		return 0;
	}
	if ((header_len = sproto_decode(stype, unpack, unpack_len, sproto_parser_cb, ud)) <= 0){
		print_debug_log("[error] [sproto_decode() failed!]\n");
		return 0;
	}
	return header_len;
}

int sproto_parser(char *data, int headlen, struct encode_ud *ud)
{
	struct sproto_type *stype;
	int len;

	if ((stype = sproto_protoquery(spro_new, ud->type, ud->session)) == NULL){
		print_debug_log("[error] [sproto_protoquery() failed!]\n");
		return 0;
	}
	if ((len = sproto_decode(stype, data + headlen, BUFLEN, sproto_parser_cb, ud)) <= 0){
		print_debug_log("[error] [sproto_decode() failed!]\n");
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
		print_debug_log("[sproto header parser failed!!]\n");
		return 0;
	}
	print_debug_log("[header parser] [type:%d,session:%d]\n", ud.type, ud.session);

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
			if (live == 0) {
				live = 1;
				system("(ubus call sysd status_led '{\"status\":\"linklost\"}')");
			}

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
		if (ud.type == AP_INFO){
			if (live == 0) {
				live = 1;
				// authd may change led
				system("(/etc/init.d/authd disable; /etc/init.d/authd stop)");
				system("(uci delete firewall._auth && uci commit firewall && /etc/init.d/firewall restart)");

				system("(ubus call sysd status_led '{\"status\":\"ok\"}')");
				/*stop the dnsmasq*/
				system("(/etc/init.d/dnsmasq disable; /etc/init.d/dnsmasq stop)");
				usleep(500);
			}
			conn_tmout = 0;
			set_ap_cfg();
		}else if (ud.type == AP_CMD){
			size = sproto_encode_data(&ud, res);
			length = write(fd, res, size);
			return proc_status_cmd(&cmdinfo);
		}
	}
	size = sproto_encode_data(&ud, res);
	length = write(fd, res, size);
	if(length < 0)
	{
		print_debug_log("[Recieve Data From Server %s Failed!]\n");
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
	return strlen((const char *)value);
}

int fill_encode_data_sta_info(station_info *sta_info,char *tagname, char *value)
{
	if (sta_info == NULL)
		return 0;
	if (strcasecmp(tagname, "sta_mac") == 0)
		strcpy(value, (const char *)&(sta_info->station_mac[0]));
	else if (strcasecmp(tagname, "sta_bssid") == 0)
		strcpy(value, (const char *)&(sta_info->bssid[0]));
	else if (strcasecmp(tagname, "sta_ssid") == 0)
		strcpy(value, (const char *)&(sta_info->ssid[0]));
	else if (strcasecmp(tagname, "sta_ap_mac") == 0)
		strcpy(value, (const char *)&(sta_info->ap_mac[0]));

	return strlen((const char*)value);
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
		print_debug_log("[encode data failed!]\n");
		return 0;
	}

	if (sfd <= 0)
		return 0;
	len = write(sfd, res, size);
	print_debug_log("[write] [data len:%d]\n", len);
	return len;
}

void ap_connect_status(struct uloop_timeout *t)
{
	int len, size;
	char res[1024 * 6] = {0};
	struct encode_ud ud;

	memset(&ud, 0, sizeof(struct encode_ud));
	if (conn_tmout >= 3 || sfd <= 0){
		if (sfd > 0){
			uloop_fd_delete(&apufd);
			queue_free(&recv_msg);
			close(sfd);
			print_debug_log("%s,%d\n",__FUNCTION__,__LINE__,conn_tmout);
		}
		sfd = 0;

		while(1){
			if (create_socket() == 0)
				break;
			sleep(2);
		}
		print_debug_log("[NEW] [connect]!!\n");
		uloop_fd_add(&apufd, ULOOP_READ);
		ap_post_data();
		conn_tmout = 0;
		goto timeset;
	}

	cmdinfo.status = AP_ON;
	ud.type = AP_STATUS;
	ud.session = SPROTO_REQUEST;
	ud.stamac[0] = NULL;
	ud.len = 200;

	if ((size = sproto_encode_data(&ud, res)) <= 0){
		print_debug_log("[encode data failed!]\n");
		goto timeset;
	}

	conn_tmout++;
	if((len = write(sfd, res, size)) <= 0){
		print_debug_log("Recieve Data From Server %s Failed!\n");
		close(sfd);
		sfd = 0;
		goto timeset;
	}
	print_debug_log("<send> [data len:%d]\n", len);

timeset:
	uloop_timeout_set(t, 15000);
	return;
}

void rcv_and_proc_data(struct uloop_fd *fd, unsigned int events)
{
	print_debug_log("[error info] %d %s %d (%d %d)\n", errno, strerror(errno), events, fd->eof, fd->error);
	char buf[BUFLEN] = {0};
	int len;

	if (fd->eof || fd->error) {
		uloop_fd_delete(&apufd);
		close(sfd);
		sfd = 0;
		fd->fd = 0;
		queue_free(&recv_msg);
		return;
	}
	if (fd->fd <= 0) {
		return;
	}
	len = read(fd->fd, buf, sizeof(buf));
	print_debug_log("[read data len:%d]\n", len);

	if (len <= 0){
		print_debug_log("[read data error or server closed!]\n");
		return;
	}
	print_debug_log("[rcv] [data len:%d]\n", len);
	queue_enqueue(&recv_msg,buf,len);
	print_debug_log("%s %d front:%d rear:%d queue_size:%d\n",__FUNCTION__,__LINE__,recv_msg.front,recv_msg.rear,recv_msg.size);
	return;
}

void *rcv_handle(void *arg)
{
	char buf[BUFLEN] = {0};
	int len;

	while(1){
		pthread_mutex_lock(&queue_lock);
		
		if(queue_is_empty(&recv_msg)){
			pthread_cond_wait(&queue_ready,&queue_lock);
			print_debug_log("queue_ready queue size is:%d \n",recv_msg.size);
		}

		if(!queue_is_empty(&recv_msg)){
			memset(&rcvinfo, 0, sizeof(ApCfgInfo));
			memset(&cmdinfo, 0, sizeof(apcmd));

			len = queue_dequeue(&recv_msg,buf);
			if( len> 0){
				print_debug_log("%s %d front:%d rear:%d queue_size:%d\n",__FUNCTION__,__LINE__,recv_msg.front,recv_msg.rear,recv_msg.size);
				if (sproto_proc_data(sfd, buf, len) <= 0){
					print_debug_log("[process data failed!]\n");
				}
			}
		}

		pthread_mutex_unlock(&queue_lock);
	}
}

void apd_init(void)
{
	if (sproto_read_entity("/usr/share/apc.sp") <= 0)
	{
		print_debug_log("[protocol not exsited!!]\n");
		exit(0);
	}
	get_ap_revision();
	get_sn();
	get_netcard_mac();
	return;
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

		if (get_gateway_ip(ac_addr) <= 0){
			print_debug_log("[debug [ac addr] Can't get the ac control address !!!]");
			return -1;
		}

	}

	print_debug_log("[ac_addr ip:%s]\n", ac_addr);

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
		print_debug_log("[Can Not Connect To %s!]\n", ac_addr);
		close(sfd);
		return -1;
	}

	apufd.cb = rcv_and_proc_data;
	apufd.fd = sfd;
	return 0;
}

void  pthread_init()
{
	pthread_mutex_init(&queue_lock,NULL);
	pthread_cond_init(&queue_ready,NULL);
}

void pthread_main()
{
	pthread_t thread_handle_id;
	pthread_init();
	//pthread handle the queue of receive msg
	pthread_create(&thread_handle_id,NULL,&rcv_handle,NULL);
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
	memset(network_mode, 0,sizeof(network_mode));
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
	server_main();

	pthread_main();
	queue_init(&recv_msg,MAX_RCEIVE_MSG_LEN);

	station_event_init();
	apd_init();
	ap_post_data();
	uloop_fd_add(&apufd, ULOOP_READ);
	uloop_timeout_set(&timeout, 10000);
	uloop_run();
	uloop_done();
	ubus_free(uctx);
	queue_free(&recv_msg);
	close(sfd);
	station_exit();
	nl80211_cleanup(&nlstate);
	eloop_destroy();
	return 0;
}



