#include <stdio.h>  
#include <sys/types.h>  
#include <sys/socket.h>  
#include <sys/un.h> 
#include <fcntl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <syslog.h>
#include <errno.h>
#include <sys/queue.h>
#include <signal.h>
#include <pthread.h>

#include "outlog.h"
#include "url_log.h"
#include "pptp_user_mgr.h"
#include "_u_log.h"

	

//extern pthread_t pptp_user_mgr_start();
int main(void)
{
	pthread_t pptp_pid;
	pthread_t log_pid;
	pthread_t url_pid;


	_u_log("I am url-log!");
	pptp_pid = pptp_user_mgr_start();
    printf("pptd_pid %d \n",pptp_pid);
	log_pid = log_mgr_start();
	printf("log_pid %d \n",log_pid);
	url_pid = url_log_start();
	printf("url_pid %d \n",url_pid);
	
	_u_log("I am url-log!");
	pthread_join(pptp_pid,NULL);
	pthread_join(log_pid,NULL);
	pthread_join(url_pid,NULL);

	printf("exit!!!\n");
	return 0;
}

