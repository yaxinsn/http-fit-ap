
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <debug_pub.h>

#include <utils/utils.h>
#include <utils/vty.h>
#include <utils/thread.h>
#include <utils/command.h>
#include <utils/log.h>
#include <utils/vector.h>
#include <utils/network.h>
#include <time.h>
#include "local.h"
#include "route.h" //untils and seng_msg log soso.

/* 所有的任务们。 */

//#define __log(fmt,...)  __z_log("%s:"fmt,...)
#define __log printf
#if 0
int __log(const char *format,...)
{
  va_list args;
  int len;
  char buf[2000];
  	time_t a;
	time(&a);
	
	len = sprintf(buf,"%s: ",ctime(&a));
	
  va_start(args, format);
  fprintf(stderr,format,args);//
  va_end (args);
}
#endif

#define VERSION_WTP "1.0.0"



/* get the version info  */
int _check_version(void)
{
	
	return 0;
}
int check_version(struct thread* th)
{
	int ret;
	struct thread_master* m = th->arg;
	ret = _check_version();
	if(ret != 0)
	{
		__log("%s failed and errorcode %d, and enter init state\n",__func__,ret);
		route_wtp_init(m);//to init state
	}
	else
	{
		thread_add_timer(m,check_version,m,24*60*60);// 24 hour
	}
	return 0;
}

/* report route state */
int __vpn_upgrade()
{
	
}
int __reset_dail_up()
{
	system("/etc/init.d/network restart");
	return 0;
}
int __reboot()
{
	system("reboot");
	return 0;
}
int _report_route_stat_operation(int optcode)
{
	switch(optcode)
	{
		case 1:
			__reboot();
		break;
		case 2:
			__reset_dail_up();
		break;
		case 3:
			__vpn_upgrade();
		break;
		default:
			break;
	}
	return 0;
}

int __get_cpu_info()
{
	return 10;
}
int __get_wan_info()
{
	return 20;
}
int __get_mem_info()
{
	return 30;
}
int _report_route_stat(void)
{
	int optcode = 100;
	//get cpu mem info
	// send msg
	// get optcode;
	_report_route_stat_operation(optcode);
	return 0;
}
int report_route_stat(struct thread *th)
{
	int ret;
	
	struct thread_master* m = th->arg;
	ret = _report_route_stat();
	if(ret != 0)
	{
		__log("%s failed and errorcode %d, and enter init state\n",__func__,ret);
		route_wtp_init(m);//to init state
	}
	else
	{
		thread_add_timer(m,report_route_stat,m,5*60);// 5 minutes
	}
	return 0;
}

/* report self and get vpnlist when setup  */
/*
{"ip":"172.16.14.2",
"mac":"00:11:22:33:44:55:",
}

*/
struct vpn_data
{
    char* name;
    char* pwd;
};

char* parse_vpn_name(char* str)
{
    char* _v=0;
    json_object* json_obj = create_sjon_from_string(str);
    _v = find_value_from_sjon_by_key(json_obj,"user");
    printf("%s:%d name=%p %s\n",__func__,__LINE__,_v,_v);

    free_json(json_obj);
    return NULL;
}
char* parse_vpn_pwd(char* str)
{
    char* pwd_v=0;
    json_object* json_obj = create_sjon_from_string(str);
    pwd_v = find_value_from_sjon_by_key(json_obj,"pwd");
    printf("%s:%d pwd=%p %s\n",__func__,__LINE__,pwd_v,pwd_v);

    free_json(json_obj);
    return NULL;
}
int prase_vpn_(char* str,int id)
{

    char* vpn_value=0;
    char vpnname[32];
    sprintf(vpnname,"vpn%d",id);
    json_object* json_obj = create_sjon_from_string(str);
    vpn_value = find_value_from_sjon_by_key(json_obj,vpnname);
    printf("%s:%d %s=%p %s\n",__func__,__LINE__,vpnname,vpn_value,vpn_value);
    if(vpn_value!=NULL){
    //printf("%s:%d %s=\n%s\n\n",__func__,__LINE__,vpnname,vpn_value);
        parse_vpn_name(vpn_value);
        parse_vpn_pwd(vpn_value);
    }
    free_json(json_obj);
}
int test_json_vpnlists(char* str)
{
    char* vpnList_value=0;
    
    char vpnlist[1024]= {0};
    FILE* fp = fopen("/work/http-post/http-main/wtpcli/vpnlist.txt","r");
    if(fp == 0){
        perror("open vpnlist.txt");
        return 0;
    }
    fgets(vpnlist,1024,fp);
    fclose(fp);
    
    printf("%s:%d  vpnlist :%p %s\n",__func__,__LINE__,vpnlist,vpnlist);
    json_object* json_obj = create_sjon_from_string(vpnlist);
    
    vpnList_value = find_value_from_sjon_by_key(json_obj,"vpnList");

    printf("%s:%d  vpnList_value = %s\n",__func__,__LINE__,vpnList_value);

    
          json_object_object_foreach(json_obj, key, val) {           
            printf("\t%s: %s\n", key, json_object_to_json_string(val));
  }
   
   // prase_vpn_(vpnList_value,1);
    
    //prase_vpn_(vpnList_value,10);
    free_json(json_obj);
    return 0;
    
}
int test_json(char* str)
{
    char* ipv=0;
    json_object* json_obj = create_sjon_from_string(str);
    
    printf("%s:%d  json_obj %p\n",__func__,__LINE__,json_obj);
    ipv = find_value_from_sjon_by_key(json_obj,"ip");

    printf("%s:%d  ipvalue form json = %s\n",__func__,__LINE__,ipv);
    
    free_json(json_obj);
    return 0;
    
}

int _get_vpnlist(void)
{
	char send_m[2000];
	
	char recv_m[2000];
    char wan_port[64]={0};
	struct in_addr addr;
	int ret;
	int recv_len;
	unsigned char mac[6];
	char mac_str[32];
	
		
	ret = get_wan_port(wan_port);
	if(ret != 0)
	{
	    __log("get wan port  failed!\n");
	    return -1;
	}
	else
	{
            printf("ret_port_name %p %s\n",wan_port,wan_port);
	    __log(" wan port ::%s>\n",wan_port);
	}
	ret = get_iface_ip(wan_port,&addr);
	if(ret != 0)
	{
	    __log("get_ %s ip failed!\n",wan_port);
	    return -1;
	}
	
		__log("_get_vpnlist :%d\n",__LINE__);
	ret = get_iface_mac("eth1",mac);
	if(ret != 0)
	{
	    __log("get_ %s mac failed!\n","eth1");
	    return -1;
	}
	else
	{
	    sprintf(mac_str,"%02X:%02X:%02X:%02X:%02X:%02X",
	        mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
	       // printf("mac_str %s\n",mac_str);
	}

	
		__log("_get_vpnlist :%d\n",__LINE__);
	sprintf(send_m,"{\"ip\":\"%s\",\"mac\":\"%s\"}",inet_ntoa(addr),mac_str);
	
	ret = send_msg(0,send_m,strlen(send_m)+1,recv_m,&recv_len);
	
	return ret;
}
int get_vpnlist(struct thread* th)//get vpnlist when setup.
{
	//crypto and sen_msg();
	// call http_post();
	struct thread_master* m = th->arg;
	int ret;
	ret = _get_vpnlist();
	if(ret!=0)
	{
		//error
		__log("get_vpnlist failed and errorcode %d\n",ret);
		
		thread_add_timer(m,get_vpnlist,m,3*60);// 3 minutes
	}
	else
	{
		__log("report_self is success!\n");
		thread_add_timer(m,report_route_stat,m,5*60);// 5 minutes
		thread_add_timer(m,check_version,m,10*60);// 10 minutes
	}
	return 0;
}
int route_wtp_init(struct thread_master* m)
{
	
    test_json_vpnlists(NULL);
		thread_add_timer(m,get_vpnlist,m,3);// 3 sec

	return 0;
		
}



