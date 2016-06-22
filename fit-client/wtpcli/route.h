#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#include "json-c/json.h"

int get_iface_ip(char* name,struct in_addr* ip);
int send_msg(int type,char* msg,int len,char* recv,int* recvlen);

int get_wan_port(char* ret_port_name);


json_object* create_sjon_from_string(char* str);
char* find_value_from_sjon_by_key(json_object* obj,char* skey);

void free_json(json_object* obj);
