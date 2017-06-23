#include "json_parse.h"

int json_parse(const char *json_input,const char *field,char * output)
{
	struct json_object *new_obj;
	struct json_object *o = NULL;
	static char value[256] = {'\0'};

	if (output == NULL){
		return -1;
	}

	memset(value,0,sizeof(value));
	new_obj = json_tokener_parse(json_input);
	
	if (!new_obj)
		return 1; // oops, we failed.

	o = json_object_object_get(new_obj, field);

	print_debug_log("%s %d field:%s type:%d\n",__FUNCTION__,__LINE__,field,json_object_get_type(o));
	if(json_object_is_type(o, json_type_string)){
		if(json_object_get_string_len(o) > 0){
			memcpy(output,json_object_get_string(o),json_object_get_string_len(o));
			output[json_object_get_string_len(o)] = '\0';
		}
	}else if(json_object_is_type(o, json_type_int)){
		*output = json_object_get_int(o);
	}

	json_object_put(new_obj);
	
	return 0;
}
