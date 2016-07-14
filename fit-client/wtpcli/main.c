#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <debug_pub.h>

#include <utils/utils.h>
#include <utils/vty.h>
#include <utils/thread.h>
#include <utils/command.h>
#include <utils/log.h>
#include <utils/vector.h>
#include <utils/network.h>
#include <time.h>
#include "local.h"

#define WORKDIR "/tmp" 

struct vty * console = NULL ;
struct thread_master * master = NULL ;
static char workdir[32] = {0,} ;
#if 0
#define __log(fmt,...)  __z_log("%s:"fmt,...)
int _z_log(const char *format, ...)
{
  va_list args;
  int len;
  char buf[2000];
  	time_t a;
	time(&a);
	
	len = sprintf(buf,"%s: ",ctime(&a));
	
  va_start(args, format);
  fprintf(stderr,format,buf, args);//
  va_end (args);
}
#endif

static void __destroy__(void)
{
	char   cmd[256];
	char   dir[128];
	struct stat st; 
    int i;
	snprintf(dir, sizeof(dir), "%s/%u", WORKDIR, getpid());

	if( *dir && 0 == strncmp(dir, workdir, sizeof(dir)) && 0 == stat(dir, &st) ) {
		if( S_ISDIR(st.st_mode) ) {
			snprintf(cmd, sizeof(cmd), "rm -rf %s/%u", WORKDIR, getpid());
			chdir("/");
            setuid(0);
            setgid(0);
			system(cmd) ;
		}
	}
	/* socket file decribtion */	
	for(i= sysconf(_SC_OPEN_MAX); i>=3; i--)
	{
	    close(i);
    }
}
int  show_time(struct thread *th)
{	
	struct thread_master* m = th->arg;
	time_t a;
	time(&a);
	fprintf(stdout,"time:%s",ctime(&a));
	thread_add_timer(m,show_time,m,5*60);
}
int route_wtp_init_d(struct thread_master* m)
{
	thread_add_timer(m,show_time,m,5);
	return 0;
		
}
int main(int ac, char * av[])
{
	int i;
	vpipe_t * def = NULL ;
	struct thread current;
	//const char * name = ttyname(0) ;
	errno = 0 ;
	/* thread master */
	master = thread_master_create();

	/* creating vty */	
	//if( NULL != name ) { /* Have ttyname(), valid login */
	 
		/* working directory */
		snprintf(workdir, sizeof(workdir), "%s/%u", WORKDIR, getpid());
		mkdir(workdir, 0755) ;
		atexit(__destroy__);
		if( 0 != chdir(workdir) ) {
			printf("%% Failed to enter working path.");
			return -2 ;
		}
	// main 
	route_wtp_init_d(master);
	route_wtp_init(master);
	while( thread_fetch(master, &current) )
		thread_call(&current) ;

	return 0 ;
}
