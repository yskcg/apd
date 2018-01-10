#include "util.h"

ApCfgInfo apinfo;
FILE *debug = NULL;

int is_ip(const char *str)
{
    struct in_addr addr;
    int ret;

		if (str == NULL)
			return -1;
    ret = inet_pton(AF_INET, str, &addr);
    return ret;
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

static char char_to_data(const char ch)
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

void mac_string_to_value(unsigned char *mac,unsigned char *buf)
{
    int i;
    int len;
	const char * p_temp = (const char *)mac;

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

int open_file(char *path, char *res, char *flag)
{
	FILE *fp;
	int len;
	char buf[LINE_MAX];
	char *str = NULL ;
	char *start = NULL;
	char *end = NULL;

	if ((fp = fopen(path, "r")) == NULL)
		return -1;
	while(!feof(fp)){
		memset(buf,0, sizeof(buf));
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

	start = start +1;
	end = end -1;
	len = end -start +1;
	strncpy(res, start, len);
	print_debug_log("%s %d len:%d %d start:%d end:%d\n",__FUNCTION__,__LINE__,strlen(res),len,start,end);
	res[len] = '\0';
	fclose(fp);
	return 1;
}

void print_debug_log(const char *form ,...)
{
	int len = 0;
	int offsets = 0;
	if (debug == NULL){
		return;
	}

	va_list arg;
	char pbString[256];
	time_t t;

	/*add the timestamp*/
	time(&t);
	len = sprintf(pbString,"%s",ctime(&t));
	offsets = len;
	len = sprintf(pbString+offsets -1,"[debug]");
	offsets = offsets + len;
	va_start (arg, form);
	vsprintf (pbString+offsets -1, form, arg);
	fprintf (debug, pbString);
	va_end (arg);
	fflush(debug);
	return;
}

int my_strtok(char *src, char *dst[], int n)
{
	char *p;
	int i, j;

	for (i = 0; i < n; i++){
		dst[i] = NULL;
	}

	print_debug_log("strtok src %s \n", src);

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
		print_debug_log("strtok dst[%d] %s(%d) \n", j, dst[j], strlen(dst[j]));

	return i;
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

void get_host_ip(char *hostip)
{
	char shell_cmd[256] = {'\0'};
    int file_size;
    char buf[32] = {'\0'};
    FILE *fp = NULL;
	

	sprintf(shell_cmd," . /usr/sbin/get_host_ip.sh");
	system(shell_cmd);
	
	sleep(1);

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
