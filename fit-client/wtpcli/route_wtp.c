
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#include <stdarg.h>

#include <debug_pub.h>
       #include <sys/socket.h>
       #include <netinet/in.h>
       #include <netinet/ip.h> /* superset of previous */
       #include <sys/socket.h>
       #include <netinet/in.h>
       #include <arpa/inet.h>
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
int _p_log(const char* func,int line,const char* fmt,...);


int _p_log(const char* func,int line,const char* fmt,...)
{
	va_list args;
	int l;
	char buf[1024]={0};
	va_start(args,fmt);
	l = sprintf(buf,"%s:%d",func,line);
	vsprintf(buf+l,fmt,args);
	printf("%s",buf);
	va_end(args);
}
#define __log(fmt,...) \
	_p_log(__func__,__LINE__,fmt"\n", ##__VA_ARGS__)

#if 0
int _p_log_system(const char* func,int line,char* xxx)
{
	int l;
	char buf[1024]={0};
	l = sprintf(buf,"%s:%d",func,line);
	sprintf(buf+l, "<%s>\n",xxx);
	printf("%s",buf);
}
#define system(xxx) \
	_p_log_system(__func__,__LINE__,xxx)
#endif

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

struct wtp_ctx
{
    struct thread_master* m;
    char ver[32];
    char padd[4];
    char* secretKey;
    char* publicKey;
};

struct wtp_ctx  g_wtp_ctx;


int get_vpnlist(struct thread* th);
int route_wtp_init(struct thread_master* m);
/**************************************parse msg form server and by json*********************/
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

int handler_getVer_retsult(char* str)
{
    char* ver_v=0;
    char* secretKey_v=0;
    char* publicKey_v=0;
    json_object* json_obj = create_sjon_from_string(str);
    ver_v = find_value_from_sjon_by_key(json_obj,"ver");
    secretKey_v = find_value_from_sjon_by_key(json_obj,"secretKey");
    publicKey_v = find_value_from_sjon_by_key(json_obj,"publicKey");
    __log("%s:%d ver=%s secretKey_v %s publicKey_v %s\n",__func__,__LINE__,ver_v,secretKey_v,publicKey_v);
    /* save to global ver. */
    memset(g_wtp_ctx.ver,0,sizeof(g_wtp_ctx.ver));
    memcpy(g_wtp_ctx.ver,ver_v,strlen(ver_v));

    if(g_wtp_ctx.secretKey != NULL)
        free(g_wtp_ctx.secretKey);
    g_wtp_ctx.secretKey = malloc(strlen(secretKey_v)+1);
    if( g_wtp_ctx.secretKey == NULL)
    {
        __log("malloc secretKey failed!\n");
        return -1;
    }    
    
    memset(g_wtp_ctx.secretKey,0,strlen(secretKey_v)+1);

    strcpy(g_wtp_ctx.secretKey,secretKey_v);


    if(g_wtp_ctx.publicKey != NULL)
        free(g_wtp_ctx.publicKey);
    g_wtp_ctx.publicKey = malloc(strlen(publicKey_v)+1);
    if( g_wtp_ctx.publicKey == NULL)
    {
        __log("malloc publicKey failed!\n");
        return -1;
    }    
    memset(g_wtp_ctx.publicKey,0,strlen(publicKey_v)+1);
    strcpy(g_wtp_ctx.publicKey,publicKey_v);

    //do new verion
    if(strcmp(ver_v,VERSION_WTP) != 0)
    {
        __log("new verion %s old version %s \n",ver_v,VERSION_WTP);
        /* TODO  */
    }
    free_json(json_obj);
    return 0;
}

char* parse_vpn_name(char* str,char* ret)
{
    char* _v=0;
    json_object* json_obj = create_sjon_from_string(str);
    _v = find_value_from_sjon_by_key(json_obj,"user");
    printf("%s:%d name=%p %s\n",__func__,__LINE__,_v,_v);

    strncpy(ret,_v,strlen(_v));
    free_json(json_obj);
    return ret;
}
char* parse_vpn_pwd(char* str,char* ret)
{
    char* pwd_v=0;
    json_object* json_obj = create_sjon_from_string(str);
    pwd_v = find_value_from_sjon_by_key(json_obj,"pwd");
    strncpy(ret,pwd_v,strlen(pwd_v));
    printf("%s:%d pwd=%p %s\n",__func__,__LINE__,pwd_v,pwd_v);

    free_json(json_obj);
    return ret;
}
int prase_vpn_user_info(char* str,int id,char* ret_user,char* ret_pass)
{

    char* vpn_value=0;
    char vpnname[32];
    int ret = -1;
    sprintf(vpnname,"vpn%d",id);
    json_object* json_obj = create_sjon_from_string(str);
    vpn_value = find_value_from_sjon_by_key(json_obj,vpnname);
    printf("%s:%d %s=%p %s\n",__func__,__LINE__,vpnname,vpn_value,vpn_value);
    if(vpn_value!=NULL){
    //printf("%s:%d %s=\n%s\n\n",__func__,__LINE__,vpnname,vpn_value);
        parse_vpn_name(vpn_value,ret_user);
        parse_vpn_pwd(vpn_value,ret_pass);
        ret = 0;
    }
    free_json(json_obj);
    return ret;
}
//#define LAN_PORT  "br-lan"
#define LAN_PORT  "eth1"
char* select_vpn_inner_ip()
{

	struct in_addr addr;
	int ret;
	struct in_addr ip;
	char* ip_str = "172.25.15.1";
	
    unsigned char* ip_x = 0;
    
                // inet_ntoa("172.25.15.1",&ip);
    ret = get_iface_ip(LAN_PORT,&addr);
	if(ret != 0)
	{
	    __log("get lan ip failed,vpn set default ip.\n");
	    //return -1;
	}
	else
	{
    	ip_x = ( unsigned char*)&addr.s_addr;
    	if (ip_x[0] == 192)
            if(ip_x[1] ==168)
            {
                // inet_ntoa("172.25.15.1",&ip);
                 ip_str = "172.25.15.1";
                 //return ip;
            }
        if(ip_x[0] == 172)
        {
           
                 //inet_ntoa("10.25.15.1",&ip);
                 ip_str = "10.25.15.1";
                 //return ip; 
        }
        if(ip_x[0] == 10)
        {
                // inet_ntoa("172.25.15.1",&ip);
                 ip_str = "172.25.15.1";
                 //return ip;
            
        }
    }
    return ip_str;
        
}
int check_private_ip(struct in_addr ip)
{
    unsigned char* ip_x = ( unsigned char*)&ip.s_addr;

    if (ip_x[0] == 10)
    return 0;           //0 is private ip
    if (ip_x[0] == 172)
    if(ip_x[1] >=16 && ip_x[1]<=31)
        return 0;


    if (ip_x[0] == 192)
    if(ip_x[1] ==168)
        return 0;
    return 1; // 1 is public ip.
}

int handle_getVPN_retsult(char* str)
{
    const char* vpnList_value=0;
    int i;
    int ret;
    char cmd[256];
    char ret_user[256];
    char ret_passwd[256];
   // char vpnlist[1024]= {0};
    int remote_ip_end;
    
	struct in_addr addr; 
    char* remote_ip_str;
    json_object* json_obj = create_sjon_from_string(str);
    
    vpnList_value = find_value_from_sjon_by_key(json_obj,"vpnList");

   // printf("%s:%d  vpnList_value = %s\n",__func__,__LINE__,vpnList_value);

 #if 0   
          json_object_object_foreach(json_obj, key, val) {           
            printf("\t%s: %s\n", key, json_object_to_json_string(val));
  }

#endif
        
/*

     uci set   pptpd.pptpd=service
uci set pptpd.pptpd.enabled=1
uci set pptpd.pptpd.localip= br-wan ip
pptpd.pptpd.remoteip=0-255的全网 IP
pptpd.@login[0]=login
pptpd.@login[0].username=youruser
pptpd.@login[0].password=1234
pptpd.@login[0].remoteip=172.25.15.2-254
# uci add pptpd login
uci set pptpd.@login[2].username=sdfsf
uci commit
uci set pptpd.@login[2].password=sdfsf1111
uci set pptpd.@login[2].remoteip=172.16.7.2
uci commit
cat pptpd

        */
    remote_ip_str = select_vpn_inner_ip();
    inet_aton(remote_ip_str,&addr);
    remote_ip_end = addr.s_addr;
    remote_ip_end = ntohl(remote_ip_end)&0xff;
    remote_ip_end = htonl(remote_ip_end);
    addr.s_addr = remote_ip_end;
    system("/etc/init.d/pptpd stop");
    system("rm /etc/config/pptpd");
    //new one
    system("touch /etc/config/pptpd");
    system("uci set pptpd.pptpd=service");
    
    system("uci set pptpd.pptpd.enable=1");
    while(1)
    {
        i++;
        ret = prase_vpn_user_info(vpnList_value,i,ret_user,ret_passwd);
        if(ret == -1)
            break;
        system("uci add pptpd login");
        sprintf(cmd,"uci set pptpd.@login[%d].username='%s'",i-1,ret_user);
        system(cmd);
        sprintf(cmd,"uci set pptpd.@login[%d].password='%s'",i-1,ret_passwd);
        system(cmd);
        sprintf(cmd,"uci set pptpd.@login[%d].remoteip='%s-%s'",i-1,remote_ip_str,inet_ntoa(addr));
        system(cmd);
        system("uci commit");
    
    }
    system("/ete/init.d/pptpd retart");
    free_json(json_obj);
    return 0;
    
}
int test_json(char* str)
{
    const char* ipv=0;
    json_object* json_obj = create_sjon_from_string(str);
    
    printf("%s:%d  json_obj %p\n",__func__,__LINE__,json_obj);
    ipv = find_value_from_sjon_by_key(json_obj,"ip");

    printf("%s:%d  ipvalue form json = %s\n",__func__,__LINE__,ipv);
    
    free_json(json_obj);
    return 0;
    
}


/* get the version info  */
int _check_version(void)
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
           // printf("ret_port_name %p %s\n",wan_port,wan_port);
	    __log(" wan port ::%s>\n",wan_port);
	}
	ret = get_iface_ip(wan_port,&addr);
	if(ret != 0)
	{
	    __log("get %s ip failed!\n",wan_port);
	    return -1;
	}
	
	ret = get_iface_mac(wan_port,mac);
	if(ret != 0)
	{
	    __log("get %s mac failed!\n",wan_port);
	    return -1;
	}
	else
	{
	    sprintf(mac_str,"%02X:%02X:%02X:%02X:%02X:%02X",
	        mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
	       // printf("mac_str %s\n",mac_str);
	}
		__log("_get_vpnlist :%d\n",__LINE__);
	sprintf(send_m,"{\"ip\":\"%s\",\"netType\":\"%d\" ,\"mac\":\"%s\",\"ver\":\"%s\",\"board\":\"%s\"}",
	    inet_ntoa(addr),check_private_ip(addr),mac_str,VERSION_WTP,"WE826");
	
	ret = send_msg(MSG_TYPE_GETVER,send_m,strlen(send_m)+1,recv_m,&recv_len);
	/* handler recv msg */
	if(recv_len > 0)
	{
	    __log("%s:%d <%s>\n",__func__,__LINE__,recv_m);
	    handler_getVer_retsult(recv_m);
	}
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
	
	thread_add_timer(g_wtp_ctx.m,get_vpnlist,g_wtp_ctx.m,3);// 3 sec
	return 0;
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
int handler_getTask_retsult(char* str)
{
    char* _v=0;
    char* tasktype_v=0;
    char* taskurl_v=0;
    char cmd[1024];
    
    json_object* json_obj = create_sjon_from_string(str);
    tasktype_v = find_value_from_sjon_by_key(json_obj,"taskType");
    taskurl_v = find_value_from_sjon_by_key(json_obj,"taskUrl");
    
    //__log("%s:%d ver=%s secretKey_v %s publicKey_v %s\n",__func__,__LINE__,_v,secretKey_v,publicKey_v);

    //action server's cmd or task

    if(atoi(tasktype_v) ==1) //have new task.
    {
        sprintf(cmd,"wget \"%s\" -O work.tar",taskurl_v);
        __log("do cmd <%s>",cmd);
        system(cmd);

        system("tar xf /tmp/work.tar -C /tmp/work");
        system("/tmp/work/main.sh &");
    }

    
     
    free_json(json_obj);
    return 0;
}
int get_new_task(struct thread* th)//get vpnlist when setup.
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
           // printf("ret_port_name %p %s\n",wan_port,wan_port);
	    __log(" wan port ::%s>\n",wan_port);
	}
	ret = get_iface_ip(wan_port,&addr);
	if(ret != 0)
	{
	    __log("get %s ip failed!\n",wan_port);
	    return -1;
	}
	
	ret = get_iface_mac(wan_port,mac);
	if(ret != 0)
	{
	    __log("get %s mac failed!\n",wan_port);
	    return -1;
	}
	else
	{
	    sprintf(mac_str,"%02X:%02X:%02X:%02X:%02X:%02X",
	        mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
	       // printf("mac_str %s\n",mac_str);
	}
		__log("_get_vpnlist :%d\n",__LINE__);
	sprintf(send_m,"{\"ip\":\"%s\",\"mac\":\"%s\"}",
	    inet_ntoa(addr),mac_str);
	
	ret = send_msg(MSG_TYPE_GETTASK,send_m,strlen(send_m)+1,recv_m,&recv_len);
	/* handler recv msg */
	if(recv_len > 0)
	{
	    __log("%s:%d <%s>\n",__func__,__LINE__,recv_m);
	    handler_getTask_retsult(recv_m);
	}
	return 0;
}
int __opration_res_new_task()
{
    
	thread_add_timer(g_wtp_ctx.m,get_new_task,g_wtp_ctx.m,3);// 3 sec
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
		case 4:
		    __opration_res_new_task();
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
int _report_route_stat_restult(char* str)
{
    char* _v=0;
    char* rspCode_v=0;
    char* rspDesc_v=0;
    char* opt_v = 0;
    char* delVpn_v = 0;
    int opt_code;
    
    json_object* json_obj = create_sjon_from_string(str);
    rspCode_v = find_value_from_sjon_by_key(json_obj,"rspCode");
    rspDesc_v = find_value_from_sjon_by_key(json_obj,"rspDesc");
    opt_v     = find_value_from_sjon_by_key(json_obj,"opt");
    delVpn_v  = find_value_from_sjon_by_key(json_obj,"delVpn");
    
//    __log("%s:%d ver=%s secretKey_v %s publicKey_v %s\n",__func__,__LINE__,_v,secretKey_v,publicKey_v);
    /* save to global ver. */
   opt_code = atoi(opt_v);
    _report_route_stat_operation(opt_code);
    free_json(json_obj);
    return 0;
}
int _report_route_stat(void)
{
	int optcode = 100;
	char send_m[2000]={0};
	char recv_m[2000]={0};
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
           // printf("ret_port_name %p %s\n",wan_port,wan_port);
	    __log(" wan port ::%s>\n",wan_port);
	}
	ret = get_iface_ip(wan_port,&addr);
	if(ret != 0)
	{
	    __log("get %s ip failed!\n",wan_port);
	    return -1;
	}
	
	ret = get_iface_mac(wan_port,mac);
	if(ret != 0)
	{
	    __log("get %s mac failed!\n",wan_port);
	    return -1;
	}
	else
	{
	    sprintf(mac_str,"%02X:%02X:%02X:%02X:%02X:%02X",
	        mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
	       // printf("mac_str %s\n",mac_str);
	}
		sprintf(send_m,"{\"ip\":\"%s\",\"mac\":\"%s\", \"cpuInfo\":\"%d\" ,\"memInfo\":\"%d\",\"WanInfo\":\"%d\"}",
	    inet_ntoa(addr),mac_str,__get_cpu_info(),__get_mem_info(),__get_wan_info());
	
	ret = send_msg(MSG_TYPE_PUTROUTESTATE,send_m,strlen(send_m)+1,recv_m,&recv_len);
	/* handler recv msg */
	if(recv_len > 0)
	{
	    __log("%s:%d <%s>\n",__func__,__LINE__,recv_m);
	    _report_route_stat_restult(recv_m);
	}
	return 0;
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
	    __log(" wan port ::%s>\n",wan_port);
	}
	ret = get_iface_ip(wan_port,&addr);
	if(ret != 0)
	{
	    __log("get_ %s ip failed!\n",wan_port);
	    return -1;
	}
	
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
	
	ret = send_msg(MSG_TYPE_GETVPN,send_m,strlen(send_m)+1,recv_m,&recv_len);
	if(recv_len >0)
	{
	    __log("%s:%d <%s>\n",__func__,__LINE__,recv_m);
	    handle_getVPN_retsult(recv_m);
	}
	return ret;
}
int get_vpnlist(struct thread* th)//get vpnlist when setup.
{
	//crypto and sen_msg();
	// call http_post();
	struct thread_master* m = th->arg;
	int ret=0;
	ret = _get_vpnlist();
	if(ret!=0)
	{
		//error
		__log("get_vpnlist failed and errorcode %d\n",ret);
		
		thread_add_timer(m,get_vpnlist,m,3*60);// 3 minutes
	}
	else
	{
		__log("get vpn list  is success!\n");
		thread_add_timer(m,report_route_stat,m,1*5);// 5 minutes
		thread_add_timer(m,check_version,m,2*5);// 10 minutes
	}
	return 0;
}
int route_wtp_init(struct thread_master* m)
{
	g_wtp_ctx.m= m;
    //test_json_vpnlists(NULL);
		thread_add_timer(m,get_vpnlist,m,3);// 3 sec

	return 0;
		
}



