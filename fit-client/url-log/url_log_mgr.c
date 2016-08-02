

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libipulog/libipulog.h>
#include <unistd.h>
#include <stdio.h>  
#include <sys/types.h>  

#include <sys/un.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/time.h>

#include <string.h>
#include <pthread.h>


#include <sys/queue.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "outlog.h"
#include "_u_log.h"
#include "url_log.h"
#include "pptp_user_mgr.h"

#include "linux-utils.h"


#define MYBUFSIZ 2048
typedef char s8;
typedef unsigned char u8;


char* strstr_in_uchar(u8* src,int len,s8* key)
{
    u8* end = src+len-1;
    u8* p = src;
    int key_len = strlen(key);
    int i;
    u8* q;
    while(p <end)
    {
        if(*p != (u8)key[0])
        {
            p++;
            continue;
        }
        q = p;
        for(i=0;i<key_len;i++)
        {
            if((u8)key[i] != q[i]){
                goto t1;
            }
            
        }
        break;
        t1:
        continue;
    }
    return (char*)p;
}
int __get_full_request_url(void* src,int len,char* ret_url)
{
    char* endp = NULL;
    char* p = NULL;
    char* item_GET = NULL;
    char* uri;
    char* host=NULL;
    
    endp = src;
    endp += len - 1;
    
    item_GET = strstr_in_uchar(src,len,"GET ");
    if(item_GET == NULL)
        return -1;
    uri = item_GET+4;


    p = uri;
    while( p <endp && (*p != ' ' && *p != '\t')){
        p++;
    };
    *p++='\0';  //set str's end; set url's end.
    if(strstr(uri,".png")
        ||strstr(uri,".jpg")
        ||strstr(uri,".jpeg")
        ||strstr(uri,".css")
        ||strstr(uri,".js")
        ||strstr(uri,".jsp")
        ||strstr(uri,".gif")
        ||strstr(uri,".swf")
        ||strstr(uri,".inc"))
        {
            return -3;
        }

    while(p < endp)
    {
        while(p < endp && (*p != '\r' && *(p+1) !='\n')) //not enter key.
        {
            p++;
        }
        if( p > endp)
            break;
        if(*p == '\r' && *(p+1) == '\n')
        {
            *p = '\0';
            p+=2;
            if (host) //find it .so byby
                break;
            if(strncasecmp(p,"Host:",5) == 0)
            {
                p +=5+1;
                host = p;
            }
        }
        p++;
    }
    if(host == NULL)
        return -2;

    sprintf(ret_url,"http://%s%s",host,uri);
    return  0;
    
}
int _url_send_msg_to_outlog(char* url,char* indevname)
{
    char time_str[64];
	time_t a;
    char syslog_msg[2048];
    struct in_addr  addr;
	unsigned char mac[6];
	char mac_str[32];

    struct pptp_msg p;
    if(get_pptp_user_info_by_port(indevname,&p))
    {
        _u_err_log("get user by port <%s> info failed!",indevname);
        return -1;
    }
	time(&a);
    ctime_r(&a,time_str);
    time_str[strlen(time_str)-1] = '\0';

    if(get_wan_ip(&addr)){
        _u_err_log("get wan ip failed!");
        return -1;
    }
    if(get_iface_mac("eth0",mac)){
        _u_err_log("get id(eth0) mac failed");
        return -1;
    }
    else
    {
	    sprintf(mac_str,"%02X:%02X:%02X:%02X:%02X:%02X",
	        mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    }
    
	///_u_log("handle_msg: <%s>",(char*)buf);
    sprintf(syslog_msg,"LOGON_OFF %s %s %s %s %s %s",
            time_str, inet_ntoa(addr),mac_str,
            p.username,p.peerip,p.action == PPTP_USER_ACTION_LOGON?"LOGON":"LOGOFF");
                
	_u_log("push msg <%s>",syslog_msg);
	push_msg_to_log_list(LOGON_OFF_MSG_TYPE,syslog_msg,strlen(syslog_msg));
	return 0;
	
}
void handle_packet2(ulog_packet_msg_t *pkt)
{

//	unsigned char *p;
//	int i;
	int ret;
	char ret_url[1024];
	char indevname = pkt->indev_name;
	printf("indev %s outdev %s \n",pkt->indev_name,pkt->outdev_name);
	memset(ret_url,0,sizeof(ret_url));
	ret = __get_full_request_url(pkt->payload,pkt->data_len,ret_url);
	if(ret == 0)
	{
	    _url_send_msg_to_outlog(ret_url,indevname);
	    
	}

}

/* prints some logging about a single packet */
void handle_packet(ulog_packet_msg_t *pkt)
{
	unsigned char *p;
	int i;
	int ret;
	char ret_url[1024];
	printf("Hook=%u Mark=%lu len=%zu ",
	       pkt->hook, pkt->mark, pkt->data_len);
	if (strlen(pkt->prefix))
		printf("Prefix=%s ", pkt->prefix);
	
	if (pkt->mac_len)
	{
		printf("mac=");
		p = pkt->mac;
		for (i = 0; i < pkt->mac_len; i++, p++)
			printf("%02x%c", *p, i==pkt->mac_len-1 ? ' ':':');
	}
	printf("indev %s outdev %s \n",pkt->indev_name,pkt->outdev_name);
#if 0
	for(i = 0;i<pkt->data_len;i++)
	{
	    printf("%02x ",pkt->payload[i]);
	}
	printf("----\n");
	for(i = 0;i<pkt->data_len;i++)
	{
	    printf("%c ",(char)pkt->payload[i]);
	}
#endif
	memset(ret_url,0,sizeof(ret_url));
	ret = __get_full_request_url(pkt->payload,pkt->data_len,ret_url);
	if(ret == 0)
	    printf("url is <%s>\n",ret_url);
    else
        printf("__get_full_request_url is ret  %d\n",ret);
	printf("+++++++++++++++++++++++++++++++\n");

}

//	alarm(atoi(argv[3]));
void* url_pkt_pthread(void* arg)
{

	struct ipulog_handle *h = arg;

    unsigned char* buf;
    int len;
    ulog_packet_msg_t *upkt;

	/* allocate a receive buffer */
	buf = malloc(MYBUFSIZ);
	if (!buf)
	    return 0;
	

	/* loop receiving packets and handling them over to handle_packet */
	while(1){
		len = ipulog_read(h, buf, MYBUFSIZ, 1);
		if (len <= 0) {
			ipulog_perror("ulog_test: short read");
			
		}
		while ((upkt = ipulog_get_packet(h, buf, len)) != NULL) {
			handle_packet2(upkt);
		}
	}
	
	/* just to give it a cleaner look */
	ipulog_destroy_handle(h);
}



int  url_log_start(void)
{
	struct ipulog_handle *h;
	
	pthread_t tid;

	/* create ipulog handle */
	h = ipulog_create_handle(ipulog_group2gmask(0)); // group is 0 ,
	if (!h)
	{
		/* if some error occurrs, print it to stderr */
		ipulog_perror(NULL);
		return -1;
	}
		
	if(pthread_create(&tid,NULL,url_pkt_pthread,(void*)h)){
		printf("Create url_pkt_pthread fail!\n");
		return -1;
	}
	return tid;
}

