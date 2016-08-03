

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libnetfilter_log/libipulog.h>
#include <unistd.h>
#include <stdio.h>  
#include <sys/types.h>  

#include <sys/un.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/time.h>

#include <string.h>
#include <pthread.h>

#include <linux/ip.h>
#include <linux/tcp.h>
#include <arpa/inet.h>

#include <sys/queue.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "outlog.h"
#include "_u_log.h"
#include "url_log.h"
#include "pptp_user_mgr.h"

#include "linux-utils.h"



#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>

#include <libnetfilter_log/libnetfilter_log.h>

#define MYBUFSIZ 2048

#define URL_MAX_SIZE 1600
typedef char s8;
typedef unsigned char u8;


char* strstr_in_uchar(u8* src,int len,s8* key)
{
    u8* end = src+len-1;
    u8* p = src;
//    int key_len = strlen(key);
  //  int i;
    u8* q;
   // printf("p %s\n",p);
    while(p <end)
    {
        if(*p != (u8)key[0])
        {
            p++;
            continue;
        }
        q = (u8*)strstr(p,key);
        if(q != NULL)
            return (char*)q;
        p +=strlen((char*)p);
        //p++;
        continue;
    }
    if(p >=end)
        return NULL;
        
    return (char*)p;
}
int __get_full_request_url(void* src,int len,char* sret_url)
{
    char* endp = NULL;
    char* p = NULL;
    char* item_GET = NULL;
    char* uri;
    char* host=NULL;
    int l;
    
    endp = (char*)src;
    endp += len - 1;
    item_GET = strstr_in_uchar(src,len,"GET");
    //printf("Item get %p \n",item_GET);
    if(item_GET == NULL)
        return -1;
    uri = item_GET+4;//skop "GET "

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
        if( p >= endp){
            break;
        }
        if(*p == '\r' && *(p+1) == '\n')
        {
            *p = '\0';
            p+=2;
            if (host){ //find it .so byby
            
              //  printf("%s:%d host %s \n",__func__,__LINE__,host);
                goto out;
            }
            if(strncasecmp(p,"Host:",5) == 0)
            {
                p +=5+1;
                host = p;
                continue;
                //printf("%s:%d host %p \n",__func__,__LINE__,host);
                //break;
            }
        }
        p++;
    }

    if(host == NULL)
        return -2;
out:
    l = sprintf(sret_url,"http://%s",host);
    strncpy(sret_url+l,uri,URL_MAX_SIZE - l);
    return 0;
    
}
char* syslog_msg;
#define MAX_SYSLOG_MSG 2048
int _url_send_msg_to_outlog(char* url,int ip)
{
    char time_str[64];
	time_t a;
    struct in_addr  addr;
	unsigned char mac[6];
	char mac_str[32];
    int ret;
    struct in_addr srcip;
    struct pptp_msg p;
    int len;
    srcip.s_addr = ip;


    //printf("%s:%d\n",__func__,__LINE__);
    if(get_pptp_user_info_by_srcip(&srcip,&p))
    {
        _u_err_log("get user by srcip <%s> info failed!",inet_ntoa(srcip));
        return -1;
    }
    //printf("%s:%d\n",__func__,__LINE__);
    if(syslog_msg == NULL){
    	syslog_msg = malloc(MAX_SYSLOG_MSG);
    	if(syslog_msg == NULL){
    	    _u_err_log(" malloc ret_url failed ");    
    	    return -1;
    	}
	}
	memset(syslog_msg,0,MAX_SYSLOG_MSG);
	time(&a);
    ctime_r(&a,time_str);
    time_str[strlen(time_str)-1] = '\0';

    //printf("%s:%d\n",__func__,__LINE__);
    if(get_wan_ip(&addr)){
        _u_err_log("get wan ip failed!");
        ret = -1;
        goto err;
    }
    if(get_iface_mac("eth0",mac)){
        _u_err_log("get id(eth0) mac failed");
        ret = -1;
        goto err;
    }
    else
    {
	    sprintf(mac_str,"%02X:%02X:%02X:%02X:%02X:%02X",
	        mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    }
    
    //printf("%s:%d\n",__func__,__LINE__);
	///_u_log("handle_msg: <%s>",(char*)buf);
    len = sprintf(syslog_msg,"URL, %s, %s, %s, %s, %s, ",
            time_str, inet_ntoa(addr),mac_str,
            p.username,p.peerip);
            
    //printf("%s:%d\n",__func__,__LINE__);
    strncpy(syslog_msg+len,url,MAX_SYSLOG_MSG - len);
	_u_log("push msg <%.*s>",MAX_SYSLOG_MSG,syslog_msg);
	push_msg_to_log_list(URL_MSG_TYPE,syslog_msg,strlen(syslog_msg));
	ret = 0;
err:
   // free(syslog_msg);
    return ret;
	
}
char* ret_url;
void handle_packet2(ulog_packet_msg_t *pkt)
{

//	unsigned char *p;
//	int i;
    unsigned char* http_hdr;
	int ret;
	struct iphdr* iphd;
	//struct tcphdr* tcphd;
	if(ret_url == NULL){
	ret_url = malloc(URL_MAX_SIZE);
	if(ret_url == NULL){
	    _u_err_log(" malloc ret_url failed ");    
	    return;
	}
	}
	memset(ret_url,0,URL_MAX_SIZE);
	//printf("pkt->date_len %d\n",pkt->data_len);
	
	iphd = (struct iphdr*)pkt->payload;
	//tcphd = ((struct iphdr)*)(pkt->payload+sizeof(struct iphdr));
	//printf(" srcip %x dest ip %x \n", iphd->saddr,iphd->daddr);
	http_hdr = pkt->payload+sizeof(struct iphdr)+sizeof(struct tcphdr);
	
	ret = __get_full_request_url(http_hdr,pkt->data_len,ret_url);
	if(ret == 0)
	{
	    _u_log("uri : %.*s  ",URL_MAX_SIZE,ret_url);
	    //printf("uri : %.*s\n",URL_MAX_SIZE,ret_url);
	    _url_send_msg_to_outlog(ret_url,iphd->saddr);
	    
	}
	//free(ret_url);

}
#if 0
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
#if 1
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
#endif
void* url_pkt_pthread(void* arg)
{

	struct ipulog_handle *h = arg;

	//struct nflog_handle *hd = h->nfulh;
    unsigned char* buf;
    int len;
    ulog_packet_msg_t *upkt;


	/* allocate a receive buffer */
	buf = malloc(MYBUFSIZ);
	if (!buf)
	    return 0;
	
    _u_log("------------");
	/* loop receiving packets and handling them over to handle_packet */
	while(1){
		len = ipulog_read(h, buf, MYBUFSIZ, 1);
		if (len <= 0) {
			ipulog_perror("ulog_test: short read");
			continue;
			
		}
		while (1) {
		upkt = ipulog_get_packet(h, buf, len);
		    if(upkt != NULL){
            //handle_packet(upkt);
			handle_packet2(upkt);
			}
			else
			{
			    break;
			}
			
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
	h = ipulog_create_handle(ipulog_group2gmask(2),65535); // group is 0 ,
	if (!h)
	{
		/* if some error occurrs, print it to stderr */
		_u_err_log("ipulog_create_handle");
		return -1;
	}
		
	if(pthread_create(&tid,NULL,url_pkt_pthread,(void*)h)){
		_u_err_log("Create url_pkt_pthread fail!\n");
		return -1;
	}
	return tid;
}


int  url_log_start2(void)
{
   
	struct ipulog_handle *h;
	/* create ipulog handle */
	h = ipulog_create_handle(ipulog_group2gmask(2),65535); // group is 0 ,
	if (!h)
	{
		/* if some error occurrs, print it to stderr */
		_u_err_log("ipulog_create_handle");
		return -1;
	} 
	//if (nflog_set_mode(h->nful_gh,NFULNL_COPY_PACKET, 0xffff) < 0) {
	//	fprintf(stderr, "can't set packet copy mode\n");
	//	exit(1);
	//}
	url_pkt_pthread(h);
	return 0;
	
}




