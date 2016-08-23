//s_unix.c  
#include <unistd.h>
#include <stdio.h>  
#include <sys/types.h>  
#include <sys/socket.h>  
#include <sys/un.h> 
#include <fcntl.h>
#include <sys/select.h>
#include <sys/time.h>
//#include <sys/quenue.h>
#include <signal.h>
#include <errno.h>
#include <dirent.h>
#include <pthread.h>
#include "outlog.h"
#include "_u_log.h"
#include "pptp_user_mgr.h"


#include "linux-utils.h"



typedef struct __pptp_entry
{
    TAILQ_ENTRY(__pptp_entry) node;
    struct pptp_msg pptp_info;
}__pptp_entry;

typedef TAILQ_HEAD(__pptp_list,__pptp_entry) pptp_list_t;
struct pptp_ctx_st
{
    int             _num;
    pptp_list_t     _head;
    pthread_mutex_t mutex;  //sync
};
static struct pptp_ctx_st pptp_ctx;
#define UNIX_DOMAIN "/tmp/.pptpd_url.log"  
//return socket fd
int setup_unix_server()
{

    struct sockaddr_un srv_addr;  
    int listen_fd;
    int ret;
    listen_fd=socket(AF_UNIX,SOCK_DGRAM,0);  
    if(listen_fd<0)  
    {  
        _u_log("cannot create communication socket : %s",strerror(errno));  
        return -1;  
    }    
    
    //set server addr_param  
    srv_addr.sun_family=AF_UNIX;  
    strncpy(srv_addr.sun_path,UNIX_DOMAIN,sizeof(srv_addr.sun_path)-1);  
    unlink(UNIX_DOMAIN);  
    //bind sockfd & addr  
    ret=bind(listen_fd,(struct sockaddr*)&srv_addr,sizeof(srv_addr));  
    if(ret==-1)  
    {  
        _u_log("cannot bind server socket: %s",strerror(errno));  
        close(listen_fd);  
        unlink(UNIX_DOMAIN);  
        return -1;  
    }
    return listen_fd;
}
int get_pptp_user_info_by_srcip(struct in_addr* ip,struct pptp_msg* pptp_info)
{

    __pptp_entry* entry = NULL;
    __pptp_entry* entry_next = NULL;
    struct pptp_ctx_st* _ctx = &pptp_ctx;
    struct in_addr localip;
    //find it

   // printf("%s:%d\n",__func__,__LINE__);
    pthread_mutex_lock(&_ctx->mutex);
    TAILQ_FOREACH_SAFE(entry,&_ctx->_head,node,entry_next)
    {
       // printf("%s:%d entry %p  localip %s \n",__func__,__LINE__,entry,entry->pptp_info.localip);
        if(inet_aton(entry->pptp_info.localip,&localip)) //OK
        {
         //   printf("%s: %d  locaip %x, dest ip %x",__func__,__LINE__,localip.s_addr,ip->s_addr);
            if(localip.s_addr == ip->s_addr)
            {
                memcpy(pptp_info,&entry->pptp_info,sizeof(struct pptp_msg));//return it;
                goto found_it;
            }
        }
    }

   // printf("%s:%d\n",__func__,__LINE__);
    pthread_mutex_unlock(&_ctx->mutex);
    return -1;// not find it
found_it:
    pthread_mutex_unlock(&_ctx->mutex);
    return 0;
}
int get_pptp_user_info_by_port(char* ifname,
    struct pptp_msg* pptp_info)
{

    __pptp_entry* entry = NULL;
    __pptp_entry* entry_next = NULL;
    struct pptp_ctx_st* _ctx = &pptp_ctx;
    //find it
    pthread_mutex_lock(&_ctx->mutex);
    TAILQ_FOREACH_SAFE(entry,&_ctx->_head,node,entry_next)
    {
        if (!strncmp(entry->pptp_info.port,ifname,
                sizeof(entry->pptp_info.port)))
        {
            memcpy(pptp_info,&entry->pptp_info,sizeof(struct pptp_msg));//return it;
            goto found_it;
        }
    }

    return -1;// not find it
found_it:
    pthread_mutex_unlock(&_ctx->mutex);
	return 0;
}
int get_pptp_user_info_by_name(char* name,
	struct pptp_msg* pptp_info)
{
	
	__pptp_entry* entry = NULL;
	__pptp_entry* entry_next = NULL;
	struct pptp_ctx_st* _ctx = &pptp_ctx;
	//find it
	pthread_mutex_lock(&_ctx->mutex);
    TAILQ_FOREACH_SAFE(entry,&_ctx->_head,node,entry_next)
	{
	    if (!strncmp(entry->pptp_info.username,name,
	            sizeof(entry->pptp_info.username)))
	    {
	        memcpy(pptp_info,&entry->pptp_info,sizeof(struct pptp_msg));//return it;
	        goto found_it;
	    }
	}
	
    return -1;// not find it
found_it:
    pthread_mutex_unlock(&_ctx->mutex);
	return 0;
}
int __insert_new_pptp_user( struct pptp_msg* p)
{

    struct pptp_ctx_st* _ctx = &pptp_ctx;

    __pptp_entry* entry = NULL;
    entry = malloc(sizeof(__pptp_entry));
    if(entry == NULL){
        _u_err_log("malloc __pptp_entry is failed!");
        return -1;
    }
    memcpy(&entry->pptp_info,p,sizeof(struct pptp_msg));
    pthread_mutex_lock(&_ctx->mutex);
    _u_log(" add entry %p user: %s lcoal ip %s",entry,p->username,p->localip);
    TAILQ_INSERT_TAIL(&_ctx->_head, entry, node);
    pthread_mutex_unlock(&_ctx->mutex);
    return 0;

}
int update_pptp_user_info( struct pptp_msg* p)
{
    __pptp_entry* entry = NULL;
    __pptp_entry* entry_next = NULL;
    struct pptp_ctx_st* _ctx = &pptp_ctx;

    //find it
    pthread_mutex_lock(&_ctx->mutex);
    TAILQ_FOREACH_SAFE(entry,&_ctx->_head,node,entry_next)
    {
        if (!strncmp(entry->pptp_info.username,p->username,sizeof(p->username)))
        {
            //found it;
            if(p->action == PPTP_USER_ACTION_LOGOFF)
            {
                
                _u_log("I found %s, and delete it!",p->username);
                TAILQ_REMOVE(&_ctx->_head,entry,node);
                free(entry);  
                
            }
            else
            {
                _u_log("I found %s, and update it!, this log should not be happend",p->username);            
                memcpy(&entry->pptp_info,p,sizeof(struct pptp_msg));//update it;
            }
            goto found_it;
            
        }
    }

    pthread_mutex_unlock(&_ctx->mutex);
//not found it 
    //new it;
    if(p->action != PPTP_USER_ACTION_LOGOFF){
        _u_log("<%s> logon,so create it at userlist!",p->username);
        __insert_new_pptp_user(p);
    }

    return 0;
found_it:
    pthread_mutex_unlock(&_ctx->mutex);
    _u_log("%s has been exist!",p->username);
    return 0;

}

int _pptp_send_msg_to_outlog(struct pptp_msg* p)
{
    char time_str[80];
    struct tm *tinfo;
    time_t a;
    char syslog_msg[256];
    struct in_addr  addr;
    unsigned char mac[6];
    char mac_str[32];

    
    time(&a);
    tinfo = localtime(&a);
    strftime(time_str,80,"%F %H",tinfo);
    //ctime_r(&a,time_str);
    //time_str[strlen(time_str)-1] = '\0';

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
    sprintf(syslog_msg,"LOGON_OFF, %s, %s, %s, %s, %s, %s",
            time_str, inet_ntoa(addr),mac_str,
            p->username,p->peerip,p->action == PPTP_USER_ACTION_LOGON?"LOGON":"LOGOFF");
                
	_u_log("push msg <%s>",syslog_msg);
	push_msg_to_log_list(LOGON_OFF_MSG_TYPE,syslog_msg,strlen(syslog_msg)+1);
	return 0;
	
}

int handle_msg(void* buf)
{
    struct pptp_msg* p = buf;
    
	
	update_pptp_user_info(p);
	_pptp_send_msg_to_outlog(p);
	return 0;
}


unsigned char buf[1024];
void* pptp_user_mgr(void* arg)
{
    struct timeval timerout;
    fd_set fds;
    int r;
    int fd=(int)arg;

    while(1)
    {
        timerout.tv_sec = 10;
        timerout.tv_usec = 0;
        FD_ZERO(&fds);
        FD_SET(fd,&fds);
        r = select(fd+1, &fds, NULL,NULL,&timerout);
        if(r > 0){
            if(recv(fd,buf,sizeof(buf),MSG_DONTWAIT) > 0){
                handle_msg(buf); //buf is struct pptp_msg.
            }
        }
    } 
}
int get_pptp_user_from_file(char* path)
{
    FILE* fp;
    char* line = NULL;
    size_t len = 0;
    ssize_t read;
    struct pptp_msg p;
    
    fp = fopen(path,"r");
    if(fp == 0)
    {
        _u_err_log("read %s failed",path);
        return -1;
    }
    read = getline(&line, &len, fp);
    if(read != -1)
    {
       sscanf(line,"%s %s %s %s %d %d\n",
       p.port,p.username,p.localip,
       p.peerip,&p.pppd_pid,&p.pptp_pid);
       _u_log("will insert this %s to list",p.username);
       p.action = PPTP_USER_ACTION_LOGON;
        update_pptp_user_info(&p);
    }
    return 0;
}
int customFilter(const struct dirent *pDir)
{
    if (
            strcmp(pDir->d_name, ".")
            && pDir->d_type & 0x08
            && strcmp(pDir->d_name, ".."))
    {
        return 1;
    }
    return 0;
}
int pptp_user_from_dir()
{
    struct dirent **namelist;
    int n;
    int i;
    n = scandir("/tmp/pptpd/", &namelist, customFilter, alphasort);
    if (n < 0)
    {
        perror("scandir");
        _u_err_log("scandir failed %s",strerror(errno));
    }
    else
    {
        _u_log("get user num %d",n);
        for (i = 0; i < n; i++)
        {
            _u_log("get user file %s",namelist[i]->d_name);
            get_pptp_user_from_file(namelist[i]->d_name);
            free(namelist[i]);
        }
        free(namelist);
    }
    return 0;
}

pthread_t pptp_user_mgr_start()
{
    pthread_t tid;
    int fd = setup_unix_server();
    if(fd <=0)
        return -1;
    chdir("/tmp/pptpd/");
    
    TAILQ_INIT(&pptp_ctx._head);
    pptp_ctx._num = 0;
    pptp_user_from_dir();
    
    _u_log("Create pptp_user_mgr start!");
    fcntl(fd,F_SETFD,FD_CLOEXEC);
    if(pthread_create(&tid,NULL,pptp_user_mgr,(void*)fd)){
        _u_log("Create pptp_user_mgr fail!");
        return -1;
    }
    return tid;
}
