#include "ubus.h"

struct blob_buf b;
struct ubus_context *uctx;

/*ubus cmd*/
static const struct blobmsg_policy ap_debug_policy[__STA_MAX] = {
	[DEBUG] = {.name = "enable",.type = BLOBMSG_TYPE_BOOL },

};

static int ubus_proc_ap_debug(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	struct blob_attr *tb[__STA_MAX];
	char debug_flag = -1;
	
	blob_buf_init (&b, 0);
	blobmsg_parse(ap_debug_policy, ARRAY_SIZE(ap_debug_policy), tb, blob_data(msg), blob_len(msg));

	if (tb[DEBUG] ){
		debug_flag = blobmsg_get_bool(tb[DEBUG]);
	}

	if (debug_flag == TRUE){
		if ((debug = fopen(LOG_FILE, "a")) == NULL){
			debug = stdout;
			goto error;
		}

		blobmsg_add_string (&b, "status", "on");
		ubus_send_reply (uctx, req, b.head);
	}else if(debug_flag == FALSE){
		debug = NULL;
		blobmsg_add_string (&b, "status", "off");
		ubus_send_reply (uctx, req, b.head);
	}

	return UBUS_STATUS_OK;

error:
	blobmsg_add_string (&b, "status", "error");
	
	return ubus_send_reply (uctx, req, b.head);

}

static const struct ubus_method apd_methods[] = {
	UBUS_METHOD_MASK ("debug", ubus_proc_ap_debug, ap_debug_policy, 1 << DEBUG),
};

static struct ubus_object_type apd_object_type = UBUS_OBJECT_TYPE ("apd", apd_methods);

static struct ubus_object apd_cmd_object = {
	.name = "apd",
	.type = &apd_object_type,
	.methods = apd_methods,
	.n_methods = ARRAY_SIZE (apd_methods),
};

void server_main(void)
{
	int ret;
	
	ret = ubus_add_object (uctx, &apd_cmd_object);
	if (ret){
		fprintf (stderr, "Failed to add object: %s\n", ubus_strerror (ret));
	}

	return;
}

/*ubus event listen*/
static void apd_ubus_receive_event(struct ubus_context *ctx, struct ubus_event_handler *ev,
			  const char *type, struct blob_attr *msg)
{
	unsigned char mac[6] = {0};
	char res[1024] = {0};
	int size;
	char *str;
	int wifi_type;
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

		json_parse(str,"type",(unsigned char *)&(wifi_type));
		sta_info.type = atoi((const char *)&wifi_type);
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
			print_debug_log("[encode data failed!]\n");
			return ;
		}

		if (sfd <= 0){
			return ;
		}
		write(sfd, res, size);
	}

	free(str);
}

int apd_ubus_listen(struct ubus_context *ctx, char * type)
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
