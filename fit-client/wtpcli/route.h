#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#include "json-c/json.h"

enum msg_type {
MSG_TYPE_GETVER=0,
MSG_TYPE_GETVPN,
MSG_TYPE_PUTROUTESTATE, //  == getcmd.

MSG_TYPE_GETTASK,
MSG_TYPE_PUT_USER_SEARCH_KEYS,
	
	
};
int get_iface_ip(char* name,struct in_addr* ip);
int get_iface_mac(char* name,char* macaddr);
int send_msg(int type,char* msg,int len,char* recv,int* recvlen);

int get_wan_port(char* ret_port_name);


json_object* create_sjon_from_string(char* str);
const char* find_value_from_sjon_by_key(json_object* obj,char* skey);

void free_json(json_object* obj);
