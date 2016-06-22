#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>

#include <utils/utils.h>
#include <utils/vty.h>
#include <utils/command.h>
#include <utils/thread.h>
#include <utils/buffer.h>
#include <utils/network.h>

#include "local.h"


extern struct thread_master * master  ;
static vector files = NULL ;

#define VTY_GET_HOST(_name,_var,_max,_str) do { \
    char * eptr = NULL ; \
    struct in_addr addr = { 0,} ; \
    int len_ = snprintf(_var, _max, "%s", _str) ;\
    if( len_ >= _max ) { \
        vty_out(vty, "%% %s length overflow: %s%s", _name, _str, VTY_NEWLINE);\
        return CMD_WARNING; \
    } \
    if( inet_aton(_var, &addr) != 0 ) { \
        strtok_r(_var, "\"\'|,;$(){}#%*-", &eptr) ; \
        if( eptr && *eptr ) { \
            vty_out(vty, "%% Invalid %s : %s%s", _name, _str, VTY_NEWLINE); \
            return CMD_WARNING; \
        } \
    } \
}while(0)
#define VTY_GET_USER(_name,_var,_max,_str) do { \
    char * eptr = NULL ; \
    int len_ = snprintf(_var, _max, "%s", _str) ;\
    if( len_ >= _max ) { \
        vty_out(vty, "%% %s length overflow: %s%s", _name, _str, VTY_NEWLINE);\
        return CMD_WARNING; \
    } \
    strtok_r(_var, "\"\'|,;$(){}#%*", &eptr) ; \
    if( eptr && *eptr ) { \
        vty_out(vty, "%% Invalid %s : %s%s", _name, _str, VTY_NEWLINE); \
        return CMD_WARNING; \
    } \
}while(0)
#define VTY_GET_PASS(_name,_var,_max,_str) do { \
    char * eptr = NULL ; \
    int len_ = snprintf(_var, _max, "%s", _str) ;\
    if( len_ >= _max ) { \
        vty_out(vty, "%% %s length overflow: %s%s", _name, _str, VTY_NEWLINE);\
        return CMD_WARNING; \
    } \
    strtok_r(_var, "\"\'|", &eptr) ; \
    if( eptr && *eptr ) { \
        vty_out(vty, "%% Invalid %s : %s%s", _name, _str, VTY_NEWLINE); \
        return CMD_WARNING; \
    } \
}while(0)

int ioswap(int in, int out)
{
	int  ret;
	int  wlen;
	int  rlen;
	int  sum;
	char buf[1024] ;

	sum = 0 ;
	while(1) {
		rlen = read(in, buf, sizeof(buf)) ;
		if( rlen <= 0 ) {
			if( rlen < 0 ) {
				if( EINTR == errno ) continue ;
				if( EAGAIN== errno ) break ;
			}
			return -2 ;
		}

		for(wlen=0; wlen<rlen; ) {
			ret = write(out, buf+wlen, rlen-wlen) ;
			if( ret <= 0 ) {
				if( ret < 0 ) {
					if( EINTR == errno ) continue;
					if( EAGAIN== errno ) { usleep(50); continue;} 
				}

				return -3 ;
			}

			wlen+= ret ;
		}

		sum += wlen ;
	}

	return sum ;
}

void __vpipe_close(vpipe_t * pipe)
{
	int status;
	vpipe_t * old = NULL;
	struct vty * vty= pipe->vty;

	// return vty 
	THREAD_READ_OFF(vty->t_read);
	THREAD_WRITE_OFF(vty->t_write);
	THREAD_READ_ON(master , vty->t_read, vty_read, vty, vty->fd);
	THREAD_WRITE_ON(master,vty->t_write,vty_flush, vty, vty->fd);
	vty->index_sub = pipe->index_sub;
	if( NULL != (old=vty->index_sub) ) {
		old->vty = vty ;
	}

	if( pipe->type == PIPE_REMOTE ) {
		vty_out(vty, "Press 'Enter' return console : ");
	}
	
	// close pipe 
	THREAD_TIMER_OFF(pipe->t_comp);
	THREAD_TIMER_OFF(pipe->t_expr);
	THREAD_READ_OFF(pipe->t_read);
	THREAD_TIMER_OFF(pipe->t_live);
	
	close(pipe->fd);
	if( pipe->pid > 0 ) {
		if( 0 == kill(pipe->pid, 0) ) {
			kill(pipe->pid, SIGKILL);
		}
		waitpid(pipe->pid, &status, WNOHANG);
	}
	XFREE(MTYPE_TMP, pipe);

}
static int __vpipe_expire(struct thread *t)
{
	vpipe_t * pipe = THREAD_ARG(t);

	pipe->t_expr = NULL ;
	__vpipe_close(pipe);

	return 0;
}

static int __vpipe_read(struct thread *t)
{
	int ret ;
	vpipe_t * pipe = THREAD_ARG(t);
	struct vty * vty= pipe->vty ;

	pipe->t_read = NULL ;
	THREAD_TIMER_OFF(pipe->t_expr);
	THREAD_READ_ON(master, pipe->t_read, __vpipe_read,   pipe, pipe->fd);

	ret = ioswap(pipe->fd, vty->fd);
	if( ret < 0 ) {
		__vpipe_close(pipe);
		return -1;
	}
	return 0;
}
static int __vty_read(struct thread *t)
{
	int ret;
	struct vty * vty = THREAD_ARG(t);
	vpipe_t *pipe    = vty->index_sub;
	vty->t_read = NULL ;
	THREAD_READ_ON(master, vty->t_read, __vty_read, vty, vty->fd);

	ret = ioswap(vty->fd, pipe->fd);
	if( ret < 0 ) {
		// return console 
		__vpipe_close(pipe);
		return -1 ;
	}

	// RESET VTY TIMEOUT
	vty_alive(vty);

	return 0;
}

/* hidden prompt output */
static int __vty_write(struct thread *t)
{
	struct vty * vty = THREAD_ARG(t);
	vty->t_write = NULL ;
	return 0;
}

int vpipe_run(struct vty * vty, char * cmd)
{
	int fd ;
	pid_t pid;
	vpipe_t * old ;
	vpipe_t * pipe;

	pid = forkpty(&fd, NULL, NULL, NULL) ;
	if( pid < 0 ) {
		vty_out(vty, "Can not execute command%s", VTY_NEWLINE);
		return -1 ;
	}

	// child 
	if( 0 == pid ) {
		setuid(0); 
		setenv("PATH","/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin",1);
		printf("\r\n");
		execl("/bin/sh", "sh", "-c" , cmd, NULL) ;
		exit(0) ;
	}

	// parent 
	pipe = XCALLOC(1, sizeof(vpipe_t));
	if( NULL == pipe ) {
		close(fd); 
		waitpid(pid, &fd, WNOHANG) ;
		vty_out(vty, "Can not alloc memory%s", VTY_NEWLINE);
		return -2;
	}

	// bind to
	set_nonblocking(fd);
	pipe->type = PIPE_EXECUTE;
	pipe->fd = fd ;
	pipe->vty= vty;
	pipe->pid= pid;
	pipe->index_sub = vty->index_sub;
	vty->index_sub  = pipe ;
	if( NULL != (old = pipe->index_sub) ) {
		old->vty = NULL;
	}
	
	THREAD_READ_OFF(vty->t_read);
	THREAD_WRITE_OFF(vty->t_write);
	vty_alive(vty);
	
	THREAD_READ_ON(master, vty->t_read,  __vty_read,  vty, vty->fd);
	THREAD_WRITE_ON(master,vty->t_write, __vty_write, vty, vty->fd);
	THREAD_READ_ON(master, pipe->t_read, __vpipe_read,  pipe, pipe->fd);
	THREAD_TIMER_ON(master,pipe->t_expr, __vpipe_expire,  pipe, 120);

	return 0;
}
#define __LOCAL_PING__
DEFUN(local_ping,
      local_ping_host_cmd,
      "ping A.B.C.D",
      "Network ping\nHost IP address\n")
{
	char cmd[128] ;

	if( argc == 2 ) {
		snprintf(cmd, sizeof(cmd), "ping -c %s %s", argv[0], argv[1]) ;
	} else {
		if( self == &local_ping_host_cmd )
			snprintf(cmd, sizeof(cmd), "ping -c 4 %s", argv[0]) ;
		else
			snprintf(cmd, sizeof(cmd), "ping %s", argv[0]);
	}

	vpipe_run(vty, cmd);
	
	return CMD_SUCCESS ;
}
ALIAS(local_ping,
      local_ping_long_host_cmd,
      "ping -t A.B.C.D",
      "Network ping\nLong ping option\nHost IP address\n");

ALIAS(local_ping,
      local_ping_count_host_cmd,
      "ping -c <1-65535> A.B.C.D",
	  "Network ping\n"
	  "Packet number option\nNumber of packets\nHost IP address\n");



#define __LOCAL_TCPDUMP__ 
DEFUN(local_tcpdump,
      local_tcpdump_cmd,
      "tcpdump",
      "Dumpping packet infomation\n")
{
	vpipe_run(vty, "tcpdump -i any -nvvv -s0") ;

	return CMD_SUCCESS;
}
DEFUN(local_tcpdump_expression,
      local_tcpdump_expression_cmd,
      "tcpdump .WORD",
      "Dumpping packet infomation\nExpressions (eg. tcp port 80)\n")
{
	int  len;
	int  n,i,sl ;
	char cmd[256] ;
	time_t now = 0;

	if( argc <= 0 ) 
		return CMD_WARNING ;

	// base command 
	len = snprintf(cmd, sizeof(cmd), "tcpdump -i any -nvvv -s0");

	// special filename 
	if( &local_tcpdump_expression_cmd != self ) {
		now = time(NULL);
		len += snprintf(cmd+len, sizeof(cmd)-len, " -w %lu.pcap", (uptr_t)now);
	}
	
	// expression checking 
	for(n=0; n<argc; n++) {
		sl = strlen(argv[n]) ;
		for( i=0; i<sl; i++) {
			if( ! (isalpha((int)argv[n][i])||isdigit((int)argv[n][i])) ) {
				vty_out(vty, "%% Bad expression name: %s%s", argv[n], VTY_NEWLINE);
				return CMD_WARNING;
			}
		}
		len += snprintf(cmd+len, sizeof(cmd)-len," %s", argv[n]) ;
	}
	if( len >= sizeof(cmd) ) {
		vty_out(vty, "%% Too many expressions.%s", VTY_NEWLINE);
		return CMD_WARNING ;
	}

	vpipe_run(vty, cmd);

	if( now > 0 ){
		struct desc * dc ;
		char name[32] ;
		char help[128];

		snprintf(name, sizeof(name), "%lu.pcap", (uptr_t)now);
		snprintf(help, sizeof(help), "Capture file at %s", ctime(&now));
		len = strnlen(help, sizeof(help)) ;
		if( len > 0 && len <128 && help[len-1] == '\n') {
			help[len-1] = 0 ;
		}
		
		vty_out(vty, "%% Saving as %u.pcap (tips, using 'scp' command to get this file) %s", (u32)now, VTY_NEWLINE);
		
		/* make up desc for scp/ftp command */
		dc = (struct desc*)XCALLOC(MTYPE_TMP, sizeof(struct desc));
		if( dc ) {
			dc->cmd = XSTRDUP(MTYPE_TMP, name);
			dc->str = XSTRDUP(MTYPE_TMP, help);
			vector_set(files, dc);
		}
	}

	return CMD_SUCCESS;
}
ALIAS(local_tcpdump_expression,
      local_tcpdump_save_expression_cmd,
      "tcpdump -w .WORD",
      "Dumpping packet infomation\nFile output option\nExpressions (eg. tcp port 80)\n") ;

/* file with XSTRDUP(MTYPE_TMP, xxx) */
int __file_complete(struct cmd_element*cmd, struct desc *dc, vector vec, char *str)
{
	int i ;
	int cnt ;
	struct desc *f ;
	if( !dc || !dc->cmd || 0 != strcmp(dc->cmd, "FILE") )
		return 0 ;

	for(i=0, cnt=0; i<vector_active(files); i++) {
		f = vector_slot(files, i) ;
		if( !f || !f->cmd || !f->str )
			continue ;

		if( NULL != str && 0 != strncmp(str, f->cmd, strlen(str)) )
			continue ;

		vector_set(vec, XSTRDUP (MTYPE_TMP, f->cmd)) ;
		cnt ++ ;
	}
	
	return ( cnt != 0 );
}
/* fill with desc */
int __file_describe(struct cmd_element*cmd, struct desc *dc, vector vec, char *str)
{
	int i ;
	int cnt ;
	struct desc *f ;
	if( !dc || !dc->cmd || 0 != strcmp(dc->cmd, "FILE") )
		return 0 ;

	for(i=0, cnt=0; i<vector_active(files); i++) {
		f = vector_slot(files, i) ;
		if( !f || !f->cmd || !f->str )
			continue ;

		if( NULL != str && 0 != strncmp(str, f->cmd, strlen(str)) )
			continue ;

		vector_set(vec, f) ;
		cnt ++ ;
	}
	
	return ( cnt != 0 );
}

#define __LOCAL_SCP__
DEFUN_FULL(local_scp, 
      local_scp_cmd, 
      __file_describe, __file_complete,
      "scp A.B.C.D USER FILE",
      "Special Containment Procedures\nServer IP address\nUser name on server\nFile name\n")
{
	int i;
    struct desc * f ;
	char cmd[256] ;
    char user[64] ;

	VTY_GET_USER("Username", user, sizeof(user), argv[1]);

	// check filename
    for(i=0; i<vector_active(files); i++) {
        f = vector_slot(files, i) ;
        if( !f || !f->cmd ) continue ;
        if( 0 == strcmp(argv[2], f->cmd) ) {
            break ;
        }
    }
    if( (i == vector_active(files)) || (0!=access(argv[2],F_OK)) ) {
		vty_out(vty, "%% File[%s] not exist%s", argv[2], VTY_NEWLINE);
		return CMD_WARNING;
	}

	snprintf(cmd, sizeof(cmd), "scp %s %s@%s:~/", argv[2], user, argv[0]); 
	vpipe_run(vty, cmd);

	return CMD_SUCCESS ;
}

#define __LOCAL_TIMEOUT__
DEFUN(local_timeout,
      local_timeout_cmd,
      "timeout <0-35791> <0-2147483>",
      "Configure terminal timeout\nMinutes of timeout\nSecond of timeout\n")
{
	unsigned long min =0, sec=0 ;

	VTY_GET_INTEGER_RANGE("minutes",min,argv[0],0,35791) ;
	if( argc >= 2 ) {
		VTY_GET_INTEGER_RANGE("second",sec,argv[1],0,2147483) ;
	}

	vty->v_timeout = min * 60 + sec ;
	
	vty_alive(vty);

	return CMD_SUCCESS;
}
ALIAS(local_timeout,
      local_timeout_min_cmd,
      "timeout <0-35791>",
      "Configure terminal timeout\nMinutes of timeout\n");

DEFUN(local_show_timeout,
      local_show_timeout_cmd,
      "show timeout",
      SHOW_STR "Configure terminal timeout\n")
{
	vty_out(vty, "Current terminal timeout: %lu:%02lu (%lu)%s",
		vty->v_timeout/60, vty->v_timeout%60, vty->v_timeout , VTY_NEWLINE ) ;
	return CMD_SUCCESS ;
}

#define __LOCAL_NSLOOKUP
DEFUN(local_nslookup,
      local_nslookup_cmd,
      "nslookup (A.B.C.D|DOMAIN)",
      "Query Internet name servers interactively\n"
      "Internet address\nInternet domain\n")
{
	char cmd[128];
    char host[64] ;

    VTY_GET_HOST("HOST", host, sizeof(host), argv[0]);
    snprintf(cmd, sizeof(cmd), "nslookup %s", host);
    vpipe_run(vty, cmd);

	return CMD_SUCCESS ;
}

#define __LOCAL_TRACEROUTE
DEFUN(local_traceroute,
      local_traceroute_cmd,
      "traceroute (A.B.C.D|DOMAIN)",
      "Network trace route\n"
      "Internet address\nInternet domain\n")
{
    int  ol, i ;
    char host[64] = {0, };
	char opts[32] = {0, };
	char cmd[128] 	= {'\0'};
    
	// arguments 
    for(i=0, ol=0; i<argc; i++) {
        if( argv[i][0] == '-' ) {
            ol += snprintf(opts+ol, sizeof(opts)-ol, "%s ", argv[i]);
        } else {
            VTY_GET_HOST("Host", host, sizeof(host), argv[i]) ;
        }
    } 

    i = snprintf(cmd, sizeof(cmd), "traceroute -w 3 -m 18 %s %s", opts, host) ;
    if( i >= sizeof(cmd) ) {
        vty_out(vty, "%% Length overflow: %s%s", argv[0], VTY_NEWLINE);
        return CMD_WARNING;
    }
	
	vpipe_run(vty, cmd);
	
	return CMD_SUCCESS;
}
ALIAS(local_traceroute,
      local_traceroute_options_cmd,
      "traceroute (-n|-I|-T) (A.B.C.D|DOMAIN)",
      "Network trace route\n"
      "Do not resolve IP address to their domain names\n""Use ICMP ECHO for tracerouting\nUse TCP SYN for tracerouting\n"
      "Internet address\nInternet domain\n");

#define __LOCAL_RADTEST
DEFUN(local_radtest,
      local_radtest_cmd,
      "radtest (-4|-6) (pap|chap|mschap|eap-md5) USERNAME PASSWORD (A.B.C.D|DOMAIN) <0-2147483647> SECRET",
      "RADIUS server test program\n"
      "Use IPv4 for the NAS address\nUse IPV6 for the NAS address\n"
      "Authentication type pap\nAuthentication type chap\nAuthentication type mschap\nAuthentication type eap-md5\n"
      "Specify a username\nSpecify a password\n"
      "Radius-server IP[:port]\nRadius server domain[:port]\n"
      "NAS port number\n"
      "Specifies the secret key to use\n")
{
    char user[64];
    char pass[64];
    char host[64];
    char secr[64];
    u32  port ;

	char cmd[256] 	= {'\0'};
	unsigned int len= 0;
	unsigned int off= 0;

	//default
	if(self == &local_radtest_cmd) {
        off = 2 ;
		len = snprintf(cmd, sizeof(cmd), "radtest %s -t %s ", argv[0], argv[1]) ; 
	} else {	
		len = snprintf(cmd, sizeof(cmd), "radtest ");
	}

	VTY_GET_USER("Username", user, sizeof(user), argv[off+0]);
    VTY_GET_PASS("Password", pass, sizeof(pass), argv[off+1]);
    VTY_GET_HOST("Host",     host, sizeof(host), argv[off+2]);
    VTY_GET_INTEGER_RANGE("NAS port number", port, argv[off+3],1,2147483647) ;
    VTY_GET_PASS("Secret",   secr, sizeof(secr), argv[off+4]);
	len += snprintf(cmd+len, sizeof(cmd)-len, "%s \'%s\' %s %u \'%s\'", user, pass, host, port, secr);
	
	if(len >= sizeof(cmd))
	{
		vty_out(vty, "%% Length overflow: %s%s", cmd, VTY_NEWLINE);
		return CMD_WARNING;
	}
	
	vpipe_run(vty, cmd);
	return CMD_SUCCESS;
}

ALIAS(local_radtest,
      local_radtest_simple_cmd,
      "radtest WORD WORD (A.B.C.D|DOMAIN) <0-2147483647> WORD",
      "RADIUS server test program\n"
      "Specify a username\nSpecify a password\n"
      "Radius-server IP[:port]\nRadius server domain[:port]\n"
      "NAS port number\n"
      "Specifies the secret key to use\n")


#define __LOCAL_SSH__
DEFUN(local_ssh_user_host,
      local_ssh_user_host_cmd,
      "ssh USER (HOST|A.B.C.D)",
      "Start SSH connection\nSSH username\nSSH server domain\nSSH server address\n")
{
    char user[64] ;
    char host[64] ;
	char cmd[256] ;

	VTY_GET_USER("SSH-user",   user, sizeof(user), argv[0]);
    VTY_GET_HOST("SSH-server", host, sizeof(host), argv[1]);
    
	if( argc == 3 ) {
		snprintf(cmd, sizeof(cmd), "ssh -l %s -p %s %s", user, argv[2], host) ;
	} else {
		snprintf(cmd, sizeof(cmd), "ssh -l %s %s", user, host) ;
    }

    vpipe_run(vty, cmd);

    return CMD_SUCCESS ;
}
ALIAS(local_ssh_user_host,
      local_ssh_user_host_port_cmd,
      "ssh USER (HOST|A.B.C.D) <1-65535>",
      "Start SSH connection\nSSH username\nSSH server domain\nSSH server address\nSSH server port\n")

#define __LOCAL_TELNET__
DEFUN(local_telnet_host,
      local_telnet_host_cmd,
      "telnet (HOST|A.B.C.D)",
      "Start telnet connection\nTelnet server domain\nTelnet server address\n")
{
    int  len ;
    u32 port = 23 ;
    char host[64] ;
    char cmd[256] ;

    VTY_GET_HOST("Telnet-server", host, sizeof(host), argv[0]); 
    if( 2 == argc ) {
        VTY_GET_INTEGER_RANGE("Port", port, argv[1], 1, 65535) ;
    }
    
    snprintf(cmd, sizeof(cmd), "telnet %s %u", host, port) ;
    vpipe_run(vty, cmd) ;

    return CMD_SUCCESS ;
}
ALIAS(local_telnet_host,
      local_telnet_host_port_cmd,
      "telnet (HOST|A.B.C.D) <1-65535>",
      "Start telnet connection\nTelnet server domain\nTelnet server address\nTelnet server port\n") ;

#define __LOCAL_SHOW_KERNEL_CLIENT
DEFUN(local_show_kernel_client,
	local_show_kernel_client_cmd,
	"show client X:X:X:X:X:X",
	SHOW_STR "Show kernel information\nKernel client information\nMAC format 00:00:00:00:00:00\n")
{
	char line[512]={0};
	FILE *fp=NULL;
	int len=0;
	char cmd[128]={0};

	sprintf(cmd,"echo %s > /proc/fpp/client/mac",argv[0]);
	system(cmd);
		
	fp = fopen("/proc/fpp/client/mac","r");
	if(fp != NULL)
	{
		while(fgets(line,sizeof(line)-1,fp)!=NULL)
		{
			vty_out(vty,"%s%s",line,VTY_NEWLINE);
		}
		fclose(fp);
	}
	
	return CMD_SUCCESS;
}

/* NODE switch daemon */
DEFUN_HIDDEN(vni_tech,
      vni_tech_cmd,
      "vni tech",
      "VNI commands\nTech mode\n")
{

	vty_auth(vty, 0, host.enable, ENABLE_NODE, NULL, NULL, NULL);

	return CMD_SUCCESS ;
}

void local_init(struct thread_master *m)
{
	int i;
	int nodes[] = {VIEW_NODE, 0} ;

	master = m;

	files = vector_init(VECTOR_MIN_SIZE);

	/* commands install to : VIEW_NODE only*/
	for(i=0; nodes[i] > 0 ; i++) {
		install_element(nodes[i], &local_ping_host_cmd);
		install_element(nodes[i], &local_ping_count_host_cmd);
		install_element(nodes[i], &local_ping_long_host_cmd);
		
		install_element(nodes[i], &local_tcpdump_cmd);
		install_element(nodes[i], &local_tcpdump_expression_cmd);
		install_element(nodes[i], &local_tcpdump_save_expression_cmd);

		install_element(nodes[i], &local_scp_cmd);

		install_element(nodes[i], &local_timeout_cmd);
		install_element(nodes[i], &local_timeout_min_cmd);
		install_element(nodes[i], &local_show_timeout_cmd);

		install_element(nodes[i], &local_nslookup_cmd);

		install_element(nodes[i], &local_traceroute_cmd);
		install_element(nodes[i], &local_traceroute_options_cmd);

		install_element(nodes[i], &local_radtest_cmd);
		install_element(nodes[i], &local_radtest_simple_cmd);

		install_element(nodes[i], &local_show_kernel_client_cmd);

		install_element(nodes[i], &local_ssh_user_host_cmd);
		install_element(nodes[i], &local_ssh_user_host_port_cmd);

        install_element(nodes[i], &local_telnet_host_cmd);
        install_element(nodes[i], &local_telnet_host_port_cmd);


        /* daemon for hidden command: swith to ENABLE mode */
        install_element(nodes[i], &vni_tech_cmd);
	}

}

void local_exit(void)
{
	return ;
}
