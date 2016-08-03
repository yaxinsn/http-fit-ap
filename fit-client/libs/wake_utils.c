#include <unistd.h>
#include <stdio.h>  
#include <sys/types.h>  
#include <sys/socket.h>  
#include <sys/un.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/time.h>
#include "wake_utils.h"




int wake_init(_wake_* w)
{
	//init 
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, w->sockfd)){
	    //error
	    perror("socketpair :");
	    return -1;
	}
	fcntl(w->sockfd[0],F_SETFD,FD_CLOEXEC);
	fcntl(w->sockfd[1],F_SETFD,FD_CLOEXEC);
	file_set_block(w->sockfd[0]);
	file_set_block(w->sockfd[1]);
	return 0;

}

void wake_up(_wake_* w)
{
    int c;
	if(w->waiting)
	    write(w->sockfd[0],&c,sizeof(c));

}
void sleep_down(_wake_* w)
{
    char buf[16];
    fd_set fds;
    int fd =  w->sockfd[1];
    int r;
    struct timeval timerout;

	timerout.tv_sec = 10; //10s
	timerout.tv_usec = 0;
	FD_ZERO(&fds);
	FD_SET(fd,&fds);
	w->waiting = 1;// go to waiting
	while(1){
    	r = select(fd+1, &fds, NULL,NULL,&timerout);
    	if(r > 0){
    		recv(fd,buf,sizeof(buf),MSG_DONTWAIT);
            w->waiting = 0;  //go to work.
            break;
    	}
#if 1    	
    	else{
    	    w->waiting = 0; //go to work.
    	    break;
    	}
#endif    	    
	}
	return; 
}
//

