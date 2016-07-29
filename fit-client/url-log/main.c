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


extern pthread_t pptp_user_mgr_start();
int main(void)
{
	pthread_t pptp_pid;
	pptp_pid = pptp_user_mgr_start();
	pthread_join(pptp_pid,NULL);
	printf("exit!!!\n");
	return 0;
}

