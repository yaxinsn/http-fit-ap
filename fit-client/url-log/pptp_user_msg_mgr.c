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
#include <pthread.h>
#include "url_log.h"

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
        perror("cannot create communication socket");  
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
        perror("cannot bind server socket");  
        close(listen_fd);  
        unlink(UNIX_DOMAIN);  
        return -1;  
    }
    return listen_fd;
}
int handle_msg(unsigned char* buf)
{
	printf("handle_msg: <%s>\n",(char*)buf);
	push_msg_to_log_list(LOGON_OFF_MSG_TYPE,buf,strlen(buf));
	return 0;
}


void* pptp_user_mgr(void* arg)
{
	unsigned char buf[1024];
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
				//todo
				handle_msg(buf);
			}
		}
	} 
}

pthread_t pptp_user_mgr_start()
{
    pthread_t tid;
	int fd = setup_unix_server();
	if(fd <=0)
		return -1;
		
    fcntl(fd,F_SETFD,FD_CLOEXEC);
	if(pthread_create(&tid,NULL,pptp_user_mgr,(void*)fd)){
		printf("Create pptp_user_mgr fail!\n");
		return -1;
	}
	return tid;
}
