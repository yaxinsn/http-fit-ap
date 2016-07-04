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

char* skip_str_prefix(char* src,char c);

char* find_value_from_sjon_by_key2(json_object* obj,char* skey);

struct ifinfo
{
    unsigned long r_bytes,r_pkt,r_err,r_drop,r_fifo,r_frame;
    unsigned long r_compr,r_mcast;
    unsigned long t_bytes,t_pkt,t_err,t_drop,t_fifo,t_coll;
    unsigned long t_corrier,t_compr;
};
int get_net_dev_stat(char* name,struct ifinfo* ifc);
uint8_t get_memory_usage(void);
int get_cpu_usage(void);