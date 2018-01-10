#include "wireless_conf.h"

static struct uci_context *ctx = NULL;
static int del_wireless_cfg(struct uci_context *c, char *section, char *option)
{
	struct uci_ptr ptr ={
		.package = "wireless",
		.section = section,
	};
	if(option){
		ptr.option = option;
	}
	print_debug_log("[del cfg] [sec:%s, opt:%s]\n", section, option);
	uci_delete(c, &ptr); //Ð´ÈëÅäÖÃ
	uci_commit(c, &ptr.p, false); //Ìá½»±£´æ¸ü¸Ä
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
	print_debug_log("[set cfg] [sec:%s, opt:%s, val:%s]\n", section, option, value);
	uci_set(c, &ptr); //Ð´ÈëÅäÖÃ
	uci_commit(c, &ptr.p, false); //Ìá½»±£´æ¸ü¸Ä
	uci_save(c, ptr.p); //Ð¶ÔØ°ü
	return 1;
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
	const char *option_value = NULL;
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
		print_debug_log("strtok %d %d %d %d %d %d \n", n, n1, n2,n3,n4,n5);
		uci_free_context(ctx);
		ctx = NULL;
		return 0;
	}

	uci_foreach_element_safe(&pkg->sections, tmp, se){
		s = uci_to_section(se);
		print_debug_log("%s,%d %s %s \n", __FUNCTION__,__LINE__,s->type, s->e.name);
		/*disable the old wireless config*/
		if (strcmp(s->type, "wifi-iface") == 0 ){
			uci_set_cfg(ctx, s->e.name, "wifi-iface", "disabled", "1");
		}

		/*get the attr of wifi device*/
		if (strcmp(s->type, "wifi-device") == 0 && strstr(s->e.name, "radio") != NULL){
			memcpy(device_info[wifi_device_number].name,s->e.name,strlen(s->e.name) +1);
			print_debug_log("%s,%d name:%s sizeof:%d strlen:%d\n",__FUNCTION__,__LINE__,device_info[wifi_device_number].name,\
								sizeof(s->e.name),strlen(s->e.name));
			option_value = uci_lookup_option_string(ctx,s,"hwmode");
			if (option_value){
				memcpy(device_info[wifi_device_number].hwmode,option_value,strlen(option_value));
				print_debug_log("%s,%d hwmode:%s\n",__FUNCTION__,__LINE__,option_value);
			}
			option_value = uci_lookup_option_string(ctx,s,"htmode");
			if (option_value){
				memcpy(device_info[wifi_device_number].htmode,option_value,strlen(option_value));
				print_debug_log("%s,%d htmode:%s\n",__FUNCTION__,__LINE__,option_value);
			}
			option_value = uci_lookup_option_string(ctx,s,"channel");
			if (option_value){
				memcpy(device_info[wifi_device_number].channel,option_value,strlen(option_value));
				print_debug_log("%s,%d channel:%s\n",__FUNCTION__,__LINE__,option_value);
			}
			option_value = uci_lookup_option_string(ctx,s,"txpower");
			if (option_value){
				memcpy(device_info[wifi_device_number].txpower,option_value,strlen(option_value));
				print_debug_log("%s,%d txpower:%s\n",__FUNCTION__,__LINE__,option_value);
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
