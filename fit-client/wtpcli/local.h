#ifndef __ABLOOMY_CLI_LOCAL_H__
#define __ABLOOMY_CLI_LOCAL_H__

#include <utils/thread.h>
#include <utils/vty.h>
#include <utils/command.h>
#include <buffer.h>

typedef struct __v_pipe__ vpipe_t ;
struct __v_pipe__ {

	enum { PIPE_DAEMON, PIPE_EXECUTE, PIPE_REMOTE, } type;
	
	int fd ;
	pid_t pid;
	struct vty * vty;
	void * index_sub;
	
	struct thread * t_read; 
	struct thread * t_expr;
	struct thread * t_live;
	struct thread * t_comp;

	// vcsd | vamd 
	int  vni_tech;
	int  count;
	char addr[32];
	char motd[64];
	char company[64];
	char prefix[64] ;
	char serial[64];

	struct buffer * b ;

	// callback 
	int (*prompt)(vpipe_t *);
	int (*close) (vpipe_t *);
} ;
void vpipe_close(vpipe_t * pipe);

int ioswap(int in, int out);


#define CLI_PATH_VCSD "/tmp/vcsd.console.sock", "Control Access Manager (CSP)"
#define CLI_PATH_VAMD "/tmp/vamd.console.sock", "Virtual security Share Manager (VSM)"

extern void tmpl_init(void) ;
extern void local_init(struct thread_master *);

extern int vty_read (struct thread *thread);
extern int vty_flush (struct thread *thread) ;
extern int vty_timeout (struct thread *thread);


#endif
