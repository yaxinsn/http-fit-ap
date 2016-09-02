
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

#include "json-utils.h" //untils and seng_msg log soso.
#include "linux-utils.h" //untils and seng_msg log soso.
#include "connection.h"

/* 所有的任务们。 */

//#define __log(fmt,...)  __z_log("%s:"fmt,...)
int _p_log(const char* func,int line,const char* fmt,...);


int _p_log(const char* func,int line,const char* fmt,...)
{
	va_list args;
	int l;
	static FILE* log_fp = 0;
	static int log_line = 0;
	int fd;
	char buf[1024]={0};

	if(log_fp == NULL)
	{
	    log_fp = fopen("/tmp/cli.log","w");
	}
	
	time_t a;
	time(&a);
	va_start(args,fmt);
	l = sprintf(buf,"%s",ctime(&a));
	l -=1;
	l += sprintf(buf+l,"|%s|%d|  ",func,line);
	vsprintf(buf+l,fmt,args);
	va_end(args);
	
	if(log_fp == NULL)
	    fprintf(stderr,"%s",buf);
	else 
	{
	    log_line++;
	    fprintf(log_fp,"%s",buf);
	    fflush(log_fp);
	}
	if(log_line >=2048)
	{
	    fd = fileno(log_fp);
	    ftruncate(fd, 0);
	    lseek(fd, 0, SEEK_SET);
	    log_line = 0;
	}
	
}
#define __log(fmt,...) \
	_p_log(__func__,__LINE__,fmt"\n", ##__VA_ARGS__)

#define __err_log(fmt,...) \
	_p_log(__func__,__LINE__,"ERROR|"fmt"\n", ##__VA_ARGS__)
#if 0
#define __system(cmd)   do{ \
    __log("do system cmd: %s",cmd); \
    }while(0);
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

#define LAN_PORT  "br-lan"
//#define LAN_PORT  "eth1"

struct wtp_base_info
{
    char wanport[32];
    u8   mac[6];
    struct in_addr wanip;
    int nettype;
};
#define ROUTE_PURPOSE_VPN_SERVER        1
#define ROUTE_PURPOSE_USER_INTERNET     2
#define ROUTE_PURPOSE_OTHER             3
struct wtp_ctx
{
    struct thread_master* m;
    char curr_ver[32];
    //char ver[32];
    char board_type[64];
    char padd[4];
    char* secretKey;
    char* publicKey;
    
    int   lan_low_traffic;
    uint8_t wan_usage;
    int state;/* 1 = init; 2= running */
    int routetype; /* 1 ROUTE_PURPOSE_VPN_SERVER : */
    struct wtp_base_info binfo;
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


#define __system(cmd)   do{ \
    __log("do system cmd: %s",cmd); \
    system(cmd);        \
    }while(0);



int __init_my_board_name(void)
{
    FILE* fp;
    char* ret;
    char* path = "/tmp/sysinfo/board_name";
    strcpy(g_wtp_ctx.board_type, "zbt-wa06");
    fp = fopen(path,"r");
    if(!fp)
    {
        __err_log("oepen %s failed",path);
        return -1;
    }
    ret = fgets(g_wtp_ctx.board_type,sizeof(g_wtp_ctx.board_type),fp);
    if(NULL == ret){
        __err_log("fgets %s failed",path);
        fclose(fp);
        return -1;
    }
    if(g_wtp_ctx.board_type[strlen(g_wtp_ctx.board_type)-1] == '\n')
    {
        g_wtp_ctx.board_type[strlen(g_wtp_ctx.board_type)-1] = 0;
    }
    fclose(fp);
    
    return 0;
}

int __init_my_version(void)
{
    FILE* fp;
    char* ret;
    strcpy(g_wtp_ctx.curr_ver, VERSION_WTP);
    fp = fopen("/etc/.cli_version","r");
    if(!fp)
    {
        __err_log("oepen /etc/.cli_version failed");
        return -1;
    }
    ret = fgets(g_wtp_ctx.curr_ver,sizeof(g_wtp_ctx.curr_ver),fp);
    if(NULL == ret){
        __err_log("fgets /etc/.cli_version failed");
        fclose(fp);
        return -1;
    }
    
    if(g_wtp_ctx.curr_ver[strlen(g_wtp_ctx.curr_ver)-1] == '\n')
    {
        g_wtp_ctx.curr_ver[strlen(g_wtp_ctx.curr_ver)-1] = 0;
    }
    fclose(fp);
    
    return 0;
}
int __do_upgrade(char* ver_url)
{
    //wget bin/
    char* cmd = malloc(strlen(ver_url)+64);
    char* ver_url_v = skip_str_prefix(ver_url,34);
    __log("ver_url_v <%s>",ver_url_v);
    if(!strcmp(ver_url_v,"false"))
    {
        __log("disable upgrade");
        
    }
    else
    {
        sprintf(cmd,"wget %s -O /tmp/firmware.bin",ver_url_v);
        __system(cmd);
        __system("md5sum /tmp/firmware.bin >/tmp/firmware.bin.md5code");
        __system("killall -9 start_cli.sh ");
        __system("killall -9 url_log ");
        __system("/usr/sbin/sysup.sh /tmp/firmware.bin &");
    }
    free(cmd);
    return 0;
}
int do_upgrade()
{

}
int handler_getVer_retsult(char* str)
{
    char* ver_j;
    char* secretKey_j;
    char* publicKey_j;
    //char buf[256]={0};
   // char ver_b[256];
    char* ver_v;
    char* secretKey_v;
    char* publicKey_v;
    char* ver_url_j; 
    json_object* json_obj = create_sjon_from_string(str);
    ver_j = find_value_from_sjon_by_key2(json_obj,"ver");
    ver_url_j = find_value_from_sjon_by_key2(json_obj,"ver_url");
    if(ver_j)
    {
      //  memset(ver_b,0,sizeof(ver_b));
      //  strncpy(ver_b,ver_j,sizeof(ver_b));
        ver_v = skip_str_prefix(ver_j,(char)(34));

        if(strcmp(ver_v,g_wtp_ctx.curr_ver) != 0)
        {
            __log("new verion %s old version %s ",ver_v,g_wtp_ctx.curr_ver);
            __log("ver_url_j <%s> ",ver_url_j);
            
            if(ver_url_j)
            {
                __do_upgrade(ver_url_j);
            }
            else
            {
                __err_log("not ver_url for %s",ver_v);
            }
        }
    }
    else
    {
         __err_log("not find  ver_url ");
    }
    
    publicKey_j = find_value_from_sjon_by_key2(json_obj,"publicKey");
    if(publicKey_j)
    {
        publicKey_v = skip_str_prefix(publicKey_j,(char)(34));
        g_wtp_ctx.publicKey = publicKey_v;
    }
    secretKey_j = find_value_from_sjon_by_key2(json_obj,"secretKey");
    if(secretKey_j)
    {
        secretKey_v = skip_str_prefix(secretKey_j,(char)(34));
        g_wtp_ctx.secretKey = secretKey_v;
    }
    __log("ver=%s secretKey_v %s publicKey_v %s .",ver_v,secretKey_v,publicKey_v);

  
    //do new version
    
    
    free_json(json_obj);
    if(secretKey_j)
        free(secretKey_j);
    if(publicKey_j)
        free(publicKey_j);
    if(ver_url_j)
        free(ver_url_j);
    if(ver_j)
        free(ver_j);
            
    return 0;
}

char* parse_vpn_name_or_pwd2(json_object*  json_obj,char* key,char* ret)
{
    const char* value_j=0;
    
    char* value_b;
    char* value_v;
    value_j = find_value_from_sjon_by_key(json_obj,key);
    if(!value_j){
        __err_log("find %s fail from json",key);
       
        return -1;
    }
    value_b = malloc(strlen(value_j)+1);
    if(value_b == 0)
        return NULL;
    memset(value_b,0,strlen(value_j)+1);
    strncpy(value_b,value_j,strlen(value_j));
    
    value_v = skip_str_prefix(value_b,(char)(34));

    strncpy(ret,value_v,strlen(value_v));
   // ret = skip_str_prefix(ret,char(34));
    
    free(value_b);
    return ret;
}
#if 0
char* parse_vpn_name_or_pwd(char* key,char* str,char* ret)
{
    const char* value_j=0;
    
    char* value_b;
    char* value_v;
    json_object* json_obj = create_sjon_from_string(str);
    value_j = find_value_from_sjon_by_key(json_obj,key);
    if(!value_j){
        __err_log("find %s fail from json",key);
        free_json(json_obj);
        return -1;
    }
    value_b = malloc(strlen(value_j)+1);
    if(value_b == 0)
        return NULL;
    memset(value_b,0,strlen(value_j)+1);
    strncpy(value_b,value_j,strlen(value_j));
    
    value_v = skip_str_prefix(value_b,(char)(34));

    strncpy(ret,value_v,strlen(value_v));
   // ret = skip_str_prefix(ret,char(34));
    free_json(json_obj);
    free(value_b);
    return ret;
}

#endif

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
	    __err_log("get lan ip failed,vpn set default ip.");
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
#define PPTP_CONF "/etc/pptpd.conf"
int __set_remoteip_pptpd()
{
   char* remote_ip;
    char cmd[256];
    
    remote_ip = select_vpn_inner_ip();
    __log("get peerip %s; set remoteip at pptpd.conf,and get firewall ",remote_ip);
    __system("sed -i '/remoteip/d' "PPTP_CONF);
    
    sprintf(cmd,"echo 'remoteip %s-255' >>"PPTP_CONF,remote_ip);
    __system(cmd);

    __system("/etc/init.d/firewall restart");
    sprintf(cmd,"iptables -t nat -I delegate_postrouting -s %s/24 -j MASQUERADE",remote_ip);
    __system(cmd);
    sprintf(cmd,"iptables -t filter -I  delegate_forward -s %s/24 -j ACCEPT",remote_ip);
    __system(cmd);
    sprintf(cmd,"iptables -t filter -I  FORWARD -s %s/24 -p tcp --dport 80 -m string --algo kmp --string \"GET\"  -j NFLOG  --nflog-prefix 'http_get'   --nflog-group 2",remote_ip);
    __system(cmd);
	return 0;
    
}
int handle_getVPN_retsult(char* str)
{
    const char* vpnList_value=0;
    int i;
    int ret;
    char cmd[256];
    char ret_user[256];
    char ret_passwd[256];
    enum json_type type;
    char routetype_str[6];
   // char vpnlist[1024]= {0};
    
    char* remote_ip_str;
    json_object* json_obj = create_sjon_from_string(str);
    
    json_object* val;
    json_object* routetype_jsobj;
    
    routetype_jsobj = find_value_from_json_object_by_key(json_obj,"routetype");
    if(!routetype_jsobj)
    {
        __err_log("vpnlist json not have routetype");
    }
    else
    {
        type = json_object_get_type(routetype_jsobj);
        if(type == json_type_int)
        {
            g_wtp_ctx.routetype = json_object_get_int(routetype_jsobj);
            __err_log("routetype json type json_type_int!");
            __log("routetype  = %d",g_wtp_ctx.routetype);
        }
        else if (type == json_type_string)
        {
            strncpy(routetype_str,json_object_get_string(routetype_jsobj),5);
            sscanf(routetype_str,"\"%d\"",g_wtp_ctx.routetype);
            
            __err_log("routetype json type json_type_string!");
            __log("routetype  = %d",g_wtp_ctx.routetype);
            
            
        }
    }
    
    val = find_value_from_json_object_by_key(json_obj,"vpnlist");
    if(!val){
        __err_log("getVPN : sjon not find 'vpnList', return -1;");
        return -1;
    }
    __system("killall -9 pptpd");
    __system("rm /tmp/pptpd/* -rf");
    __system("echo > /etc/ppp/chap-secrets");

    type = json_object_get_type(val);
    
    //__log("------type %d-------------",type);
    if(type == json_type_array){
        __log("this json array");
        int arraylen = json_object_array_length(val); /*Getting the length of the array*/
        int i;
        json_object* jvalue;
        json_object* jarray = val;
        
        __log("this json array arraylen %d",arraylen);
        for(i =0;i< arraylen;i++)
        {
            jvalue = json_object_array_get_idx(jarray, i); /*Getting the array element at position i*/
            type = json_object_get_type(jvalue);
            __log("jvalue type %d",type);


            parse_vpn_name_or_pwd2(jvalue,"user",ret_user);
            parse_vpn_name_or_pwd2(jvalue,"pwd",ret_passwd);
            __log("arrry[%d] : user <%s> pwd <%s>",i,ret_user,ret_passwd);
            
            sprintf(cmd,"echo '%s pptp-server %s * ' >>/etc/ppp/chap-secrets",
                    ret_user,ret_passwd);
            __system(cmd);
        }
     }
     else
     {
        
        __err_log("vpnlist is not json array,so can't parse it !");
     }

    __set_remoteip_pptpd();
    __system("/usr/sbin/pptpd -w  -c "PPTP_CONF);
    free_json(json_obj);
    return 0;
    
}



/* get the version info  */
int _check_version(void)
{
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
	    __err_log("get wan port  failed!");
	    return -1;
	}
	else
	{
	    __log(" wan port is %s>",wan_port);
	}
	ret = get_iface_ip(wan_port,&addr);
	if(ret != 0)
	{
	    __err_log("get %s ip failed!",wan_port);
	    return -1;
	}
	
	ret = get_iface_mac("eth0",mac);
	if(ret != 0)
	{
	    __err_log("get %s mac failed!",wan_port);
	    return -1;
	}
	else
	{
	    sprintf(mac_str,"%02X:%02X:%02X:%02X:%02X:%02X",
	        mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
	}
	
	sprintf(send_m,"{\"ip\":\"%s\",\"nettype\":\"%d\" ,\"mac\":\"%s\",\"ver\":\"%s\",\"board\":\"%s\"}",
	    inet_ntoa(addr),g_wtp_ctx.binfo.nettype,mac_str,g_wtp_ctx.curr_ver,g_wtp_ctx.board_type);
	
    __log("send message <%s>",send_m);
	ret = send_msg(MSG_TYPE_GETVER,send_m,strlen(send_m)+1,recv_m,&recv_len);
	/* handler recv msg */
	if ((ret >= 0)&&(recv_len >0))
	{
	    recv_m[recv_len] = 0;
	    __log("recv message len %d <%s> ",recv_len,recv_m);
	    handler_getVer_retsult(recv_m);
	}
	return 0;
}
int check_version(struct thread* th)
{
	int ret;
	struct thread_master* m = th->arg;
	
    __log(" enter check_version:");
	ret = _check_version();
	if(ret != 0)
	{
		__err_log("failed and errorcode %d, and enter init state",ret);
		
    	__log("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");
    	__log("^^chk version fail enter init:^^^");
    	__log("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");
		route_wtp_init(m);//to init state
	}
	else
	{
		thread_add_timer(m,check_version,m,24*60*60);// 24 hour
	}
	return 0;
}

/* report route state */
int __vpn_renew()
{
	
	thread_add_timer(g_wtp_ctx.m,get_vpnlist,g_wtp_ctx.m,3);// 3 sec
	return 0;
}
int __reset_dail_up()
{

    __log("dail up again !\n");
	__system("/etc/init.d/network restart");
	//__vpn_renew();
	__log("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");
	__log("^^dail up again enter init:^^^^^^");
	__log("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");
	route_wtp_init(g_wtp_ctx.m);
	return 0;
}
int __reboot()
{
    __log("will reboot!");
    sleep(3);
	__system("reboot");
	return 0;
}
int handler_getTask_retsult(char* str)
{
    char* tasktype_j=0;
    char* taskurl_j=0;
    char* tasktype_v=0;
    char* taskurl_v=0;
    char cmd[1024];
    
    json_object* json_obj = create_sjon_from_string(str);
    tasktype_j = find_value_from_sjon_by_key2(json_obj,"tasktype");
    if(tasktype_j)
    {
        tasktype_v = skip_str_prefix(tasktype_j,34);    
    }
    taskurl_j = find_value_from_sjon_by_key2(json_obj,"taskurl");
    if(taskurl_j){
            taskurl_v = skip_str_prefix(taskurl_j,34);    //__log("%s:%d ver=%s secretKey_v %s publicKey_v %s\n",__func__,__LINE__,_v,secretKey_v,publicKey_v);

        //action server's cmd or task
        __log("taskurl_v <%s>",taskurl_v);
        if(!strcmp(taskurl_v,"false"))
        {
            __log("disable task");
        
        }
        else
        //if(atoi(tasktype_v) ==1) //have new task.// not care the taskType --2016.8.22
        {
            sprintf(cmd,"wget %s -O /tmp/work.tar",taskurl_v);
            //__log("do cmd <%s>",cmd);
            __system(cmd);
            
            __system("mkdir -p /tmp/work/");
            __system("tar xf /tmp/work.tar -C /tmp/work");
            __system("rm /tmp/work.tar -f");
            __system("/tmp/work/main.sh &");
        }
    }
    else
    {
        
        __err_log("taskurl is null");
    }

    
     
    free_json(json_obj);
    if(tasktype_j)
        free(tasktype_j);
    if(taskurl_j)
        free(taskurl_j);
    return 0;
}
int get_new_task(struct thread* th)//get vpnlist when setup.
{
	char send_m[2000]={0};
	
	char recv_m[2000]={0};;
    char wan_port[64]={0};
	struct in_addr addr;
	int ret;
	int recv_len;
	unsigned char mac[6];
	char mac_str[32];


    __log("  enter task get_new_work");
	ret = get_wan_port(wan_port);
	if(ret != 0)
	{
	    __err_log("get wan port  failed!");
	    return -1;
	}
	else
	{
	    __log(" wan port is %s",wan_port);
	}
	ret = get_iface_ip(wan_port,&addr);
	if(ret != 0)
	{
	    __err_log("get %s ip failed!",wan_port);
	    return -1;
	}
	
	ret = get_iface_mac("eth0",mac);
	if(ret != 0)
	{
	    __err_log("get %s mac failed!",wan_port);
	    return -1;
	}
	else
	{
	    sprintf(mac_str,"%02X:%02X:%02X:%02X:%02X:%02X",
	        mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
	}
	sprintf(send_m,"{\"ip\":\"%s\",\"mac\":\"%s\"}",
	    inet_ntoa(addr),mac_str);
	
    __log("send  message<%s>",send_m);
	ret = send_msg(MSG_TYPE_GETTASK,send_m,strlen(send_m)+1,recv_m,&recv_len);
	/* handler recv msg */
	if ((ret >= 0)&&(recv_len >0))
	{
	    recv_m[recv_len] = 0;
	    __log("recv message len %d <%s> ",recv_len,recv_m);
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
		
            __log(" I will reboot!");
			__reboot();
		break;
		case 2:
            __log(" I will dail up again!");
			__reset_dail_up();
		break;
		case 3:
            __log(" I will get new vpn list!");
			__vpn_renew();
		break;
		case 4:
            __log(" I will request new little work!");
		    __opration_res_new_task();
		break;
		default:
			break;
	}
	return 0;
}

unsigned long __get_lan_rx_traffic(void)/* client tx and route rx from lan. */
{

    static unsigned long rx_pkts = 0;
    struct ifinfo ifc;
    unsigned long traffic = 0;
    int ret = get_net_dev_stat("br-lan",&ifc);
    if(ret >=0)
    {
        traffic = ifc.r_pkt - rx_pkts;
        rx_pkts = ifc.r_pkt;
    }
    else
        return 0xffffffff;
        
    return traffic;
    
}
int task_get_lan_rx(struct thread* th)
{

	struct thread_master* m = th->arg;
	unsigned long ret=0;
	ret = __get_lan_rx_traffic();
    if(ret == 0xffffffff)
    {
        __err_log("get lan rx_traffic failed!");
    }
    else
    {
        if(ret <= 100)
            g_wtp_ctx.lan_low_traffic = 1;
        else
            g_wtp_ctx.lan_low_traffic = 0;
    }
    
	thread_add_timer(m,task_get_lan_rx,m, 1*60);
	return 0;
}
unsigned long __get_wan_rx_traffic_usage(void)/* client tx and route rx from lan. */
{

    static unsigned long r_bytes = 0;
    struct ifinfo ifc;
    
    int ret = 0;
    unsigned long traffic = 0;
    char* wan_port[32];
   
    ret = get_wan_port(wan_port);
    if(ret < 0)
    {
        return 0;
    }
    ret = get_net_dev_stat(wan_port,&ifc);
    if(ret >= 0)
    {
        traffic = ifc.r_bytes - r_bytes;
        r_bytes = ifc.r_bytes;
    }
    else
        return 0;
        
    return traffic;
    
}
int task_get_wan_rx(struct thread* th)
{

	struct thread_master* m = th->arg;
	unsigned long ret=0;
	ret = __get_wan_rx_traffic_usage();
	int base = 100*1000*1000;
	
    if(ret == 0)
    {
        __err_log("get lan rx_traffic failed!");
    }
    else
    {
        g_wtp_ctx.wan_usage = (ret*8)/base;
    }
    
	thread_add_timer(m,task_get_wan_rx,m, 1*60);
	return 0;
}
int _del_vpn(char* vpn_user)
{
    char path[128];
    
    FILE* fp;
   char line[1024] = {0};
   char ifname[32];
    char user[64];
    char localip [20];
    char dailup_ip[20];
    int pid;
    int fpid;
    sprintf(path,"/tmp/pptpd/%s",vpn_user);
    fp = fopen(path,"r");
    if( fp == 0)
    {
        __err_log("open <%s> failed",path);
       // return -1;
       goto del_user;
    }
   if ( 0> (fgets(line,1024,fp)))
   {
    
        __err_log("read <%s> failed",path);
       // fclose(fp);
       // return -2;
   }
    fclose(fp);
    //remove(path);
   __log("%s's content: %s",line);  
   sscanf(line,"%s %s %s %s %d %d\n",ifname,user,localip,dailup_ip,&pid,&fpid);
  
   __log("ifname %s, user %s ,localip %s , dailup %s pid %d fpid %d",
   ifname,user,localip,dailup_ip,pid,fpid); 
   if(fpid)
        kill(fpid,9);
   
del_user:
    __log("I will del user form chap");
   {
        char del_chap[128];
        sprintf(del_chap,"sed -i /^%s/d /etc/ppp/chap-secrets",vpn_user);
        __system(del_chap);
        
   }
   return 0;

}

 int _del_vpns(char* vpnlist)
 {
    char* p;
    char* vpn_user;
    p = vpnlist;
    
    char* q;
    while(1)
    {
        q = strchr(p,',');
        if(q != 0)
            *q = 0;
        vpn_user = skip_str_prefix(p,' ');
        
        __log("will delete: <%s>", vpn_user);
        if(strlen(vpn_user) == 0)
        {
            __log("vpn user is empty!");
        }
        else
            _del_vpn(vpn_user);
            
        if(q != 0)
            p =q+1;
        else
            break;
    }
 }
 del_vpn_handler(json_object* jsobj)
 {
    
    char* delVpn_j=0;
    json_object* val;
    char* delVpn_v = 0;
   
    enum json_type type;
    
    val  = find_value_from_json_object_by_key(jsobj,"delvpn");
    if(!val)
        return;
    type = json_object_get_type(val);
    if(type == json_type_string)
    {
        delVpn_j = json_object_get_string(val);
        if(delVpn_j){
            delVpn_v =  skip_str_prefix(delVpn_j,34);
            if(strlen(delVpn_v) == 0)
            {
                __log("delvpn list is empty!");
            }
            else
            _del_vpns(delVpn_v);
        }
    }
    else if(type == json_type_array)
    {
        int arraylen = json_object_array_length(val); /*Getting the length of the array*/
        int i;
        json_object* jvalue;
        json_object* jarray = val;
        
        __log("this json array arraylen %d",arraylen);
        for(i = 0; i < arraylen; i++)
        {
            jvalue = json_object_array_get_idx(jarray, i);
            delVpn_j = json_object_get_string(jvalue);
            if(delVpn_j)
            {
                delVpn_v =  skip_str_prefix(delVpn_j,34);
                __log("will delete <%s>",delVpn_v);
                _del_vpn(delVpn_v);
            }
        }
    }
    
 }
int _report_route_stat_restult(char* str)
{
    char* rspcode_j=0;
    char* opt_j=0;
    char* rspCode_v=0;
    char* rspDesc_v=0;
    char* opt_v = 0;
    int opt_code;
    
    
    json_object* json_obj = create_sjon_from_string(str);
    rspcode_j = find_value_from_sjon_by_key2(json_obj,"rspcode");
    if(rspcode_j){
        rspCode_v = skip_str_prefix(rspcode_j,34);
    }
    //rspDesc_v = find_value_from_sjon_by_key2(json_obj,"rspDesc");
    opt_j     = find_value_from_sjon_by_key2(json_obj,"opt");
    if(opt_j){
        opt_v =  skip_str_prefix(opt_j,34);
        opt_code = atoi(opt_v);
        _report_route_stat_operation(opt_code);
    }
   del_vpn_handler(json_obj);
   
    free_json(json_obj);
    if(rspcode_j)
        free(rspcode_j);
    if(opt_j)
        free(opt_j);
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
	int nettype;
	int vpncount;

	ret = get_wan_port(wan_port);
	if(ret != 0)
	{
	    __err_log("get wan port  failed!");
	    return -1;
	}
	else
	{
	    __log(" wan port is %s ",wan_port);
	}
	ret = get_iface_ip(wan_port,&addr);
	if(ret != 0)
	{
	    __err_log("get %s ip failed!",wan_port);
	    return -1;
	}

	
	if(g_wtp_ctx.binfo.wanip.s_addr != addr.s_addr)
	{
	    __log("wan ip is change!");
	    //thread_add_timer(g_wtp_ctx.m,get_vpnlist,g_wtp_ctx.m,5);// 5 sec
	    g_wtp_ctx.binfo.wanip.s_addr = addr.s_addr;
	}
	
	ret = get_iface_mac("eth0",mac);
	if(ret != 0)
	{
	    __err_log("get %s mac failed!",wan_port);
	    return -1;
	}
	else
	{
	    sprintf(mac_str,"%02X:%02X:%02X:%02X:%02X:%02X",
	        mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
	}
	//////////////////////////////////////////////////////
	vpncount = file_line_num("/etc/ppp/chap-secrets");
	__log("/etc/ppp/chap-secrets file num %d",vpncount);
	if(vpncount <=1)
	    vpncount = 0;
	else
	    vpncount = vpncount-1;
	if(vpncount == 0 
	    && g_wtp_ctx.routetype == ROUTE_PURPOSE_VPN_SERVER
	    && g_wtp_ctx.binfo.nettype == 1) //public
	{
	    __vpn_renew();
	}
    ///////////////////////////////////////////////////////
    
	nettype = g_wtp_ctx.binfo.nettype;
	
	sprintf(send_m,"{\"ip\":\"%s\",\"mac\":\"%s\", \"cpuinfo\":\"%d\" ,\"meminfo\":\"%d\",\"waninfo\":\"%d\", \"nettype\":\"%d\",\"vpncount\":\"%d\"}",
        inet_ntoa(addr),mac_str,get_cpu_usage(),get_memory_usage(),g_wtp_ctx.wan_usage,nettype,vpncount);
        
    __log("send  message<%s>",send_m);
	ret = send_msg(MSG_TYPE_PUTROUTESTATE,send_m,strlen(send_m)+1,recv_m,&recv_len);
	/* handler recv msg */
	if ((ret >= 0)&&(recv_len >0))
	{
	    recv_m[recv_len] = 0;
	    __log("recv message len %d <%s>",recv_len,recv_m);
	    _report_route_stat_restult(recv_m);
	}
	return 0;
}
int report_route_stat(struct thread *th)
{
	int ret;
	
	struct thread_master* m = th->arg;
	__log("enter report_route_stat:");
	ret = _report_route_stat();
	if(ret != 0)
	{
		__err_log("failed and errorcode %d, and enter init state",ret);
		
    	__log("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");
    	__log("^^report state fail enter init:^^");
    	__log("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");
		route_wtp_init(m);//to init state
	}
	else
	{
	    __log("report_route_stat success");
		thread_add_timer(m,report_route_stat,m,5*60);// 5 minutes
	}
	return 0;
}



int _get_vpnlist(void)
{
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
	    __err_log("get wan port  failed, return -1");
	    return -1;
	}
	else
	{
	    __log(" wan port is %s",wan_port);
	}
	ret = get_iface_ip(wan_port,&addr);
	if(ret != 0)
	{
	    __err_log("get %s ip failed, return -1",wan_port);
	    return -1;
	}
	
	ret = get_iface_mac("eth0",mac);
	if(ret != 0)
	{
	    __err_log("get_ %s mac failed!","eth0");
	    return -1;
	}
	else
	{
	    sprintf(mac_str,"%02X:%02X:%02X:%02X:%02X:%02X",
	        mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
	}

	sprintf(send_m,"{\"ip\":\"%s\",\"mac\":\"%s\",\"nettype\":\"%d\"}",
	    inet_ntoa(addr),mac_str,g_wtp_ctx.binfo.nettype);
	
    __log(" send  message<%s>",send_m);
	ret = send_msg(MSG_TYPE_GETVPN,send_m,strlen(send_m)+1,recv_m,&recv_len);
	if ((ret >= 0)&&(recv_len >0))
	{
	    recv_m[recv_len] = 0;
	    __log("recv message len %d <%s> ",recv_len,recv_m);
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
	
    __log("  enter task get_vpnlist:");
    if(g_wtp_ctx.binfo.nettype == 0)// public
    {
        __log("this ap has not public ip,so do't get vpnlist");
        return 0;
    }
    g_wtp_ctx.routetype = ROUTE_PURPOSE_VPN_SERVER;
	ret = _get_vpnlist();
	if(ret!=0)
	{
		//error
        __err_log("get vpnlist failed and errorcode %d",ret);
		
		thread_add_timer(m,get_vpnlist,m,3*60);// 3 minutes
	}
	else
	{
        __log("get vpn list  is success.");
		__system("/usr/sbin/set_pptpd_dns.sh &");
	}
	return 0;
}

int _get_base_info(struct wtp_base_info* binfo)
{
    char            wan_port[64]={0};
	struct in_addr  addr;
	int             ret;
	int             recv_len;
	u8              mac[6];
	char            mac_str[32];
	
		
	ret = get_wan_port(wan_port);
	if(ret != 0)
	{
	    __err_log("get wan port  failed!");
	    return -1;
	}
	else
	{
	    __log(" wan port is %s ",wan_port);
    	strncpy(binfo->wanport,wan_port,strlen(wan_port));
	}
	
	ret = get_iface_ip(wan_port,&addr);
	if(ret != 0)
	{
	    __err_log("get %s ip failed!",wan_port);
	    return -1;
	}
    binfo->wanip.s_addr = addr.s_addr;
	
	ret = get_iface_mac("eth0",mac);
	if(ret != 0)
	{
	    __err_log("get %s mac failed!","eth0");
	    return -1;
	}
	else
	{
	    
    	memcpy(binfo->mac,mac,sizeof(mac));
    	
	    sprintf(mac_str,"%02X:%02X:%02X:%02X:%02X:%02X",
	        mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
	}
	binfo->nettype = check_private_ip(addr);
	return 0;
}

int task_get_baseinfo(struct thread* th)
{
    
	struct thread_master* m = th->arg;
	__log("  enter task get_baseinfo:");
	if(0 !=_get_base_info(&g_wtp_ctx.binfo))
	{
	    
    	__err_log("  task get_baseinfo failed");
    	thread_add_timer(m,task_get_baseinfo,m,60);// 60 sec
	}
	else
	{
	
    	__log("task get_baseinfo success; and next get_vpnlist,task_get_lan_rx,task_get_wan_tx");
    	
		g_wtp_ctx.state = 2;
	    thread_add_timer(m,get_vpnlist,m,3);// 3 sec
	    
		thread_add_timer(m,report_route_stat,m,1*5);// 5 minutes
		thread_add_timer(m,check_version,m,2*5);// 10 minutes
		
        thread_add_timer(m,task_get_lan_rx,m,1);        
	    thread_add_timer(m,task_get_wan_rx,m, 1*60);  
	}
}
int route_wtp_init(struct thread_master* m)
{
	g_wtp_ctx.m = m;
	if(g_wtp_ctx.state == 1){
	    __log("route has been init state, return here");
	    return 0 ;
	}
	g_wtp_ctx.state = 1;
	__init_my_version();
	__init_my_board_name();
	__log("wtp verion %s board_type %s",g_wtp_ctx.curr_ver,g_wtp_ctx.board_type);
	thread_add_timer(m,task_get_baseinfo,m,3);// 3 sec
	//thread_add_timer(m,get_vpnlist,m,3);// 3 sec
    //test_json_vpnlists(NULL);
	return 0;
		
}



