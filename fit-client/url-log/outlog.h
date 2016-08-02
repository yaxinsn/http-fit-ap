
#ifndef OUT_LOG_H 
#define OUT_LOG_H


#include <stdio.h>
#include <unistd.h>
#include <sys/un.h> 
#include <fcntl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <pthread.h>

#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var,head,field,tvar)           \
    for((var) = TAILQ_FIRST((head));                    \
        (var) &&((tvar) = TAILQ_NEXT((var),field),1);   \
        (var) = (tvar))
#endif
#if 0
typedef struct url_log_msg_st
{
	char usrname[64];
	struct in_addr ip;
	time_t time;
	int url_len;
	char url_data[];
}url_msg_t;

typedef struct logon_off_msg_st
{
	char usrname[64];
	struct in_addr ip;
	time_t time;
	int on_off; //  * 1 is on; 0 is off/
}logon_msg_t;
#endif

#define 	URL_MSG_TYPE 1
#define     LOGON_OFF_MSG_TYPE  2

typedef struct __msg_entry
{
	TAILQ_ENTRY(__msg_entry) node;
	long	time;
	int 	len;
	int  msg_type;
	int 	msg_len; //len is len of data
	char	msg[0];
}__msg_entry_t;

typedef TAILQ_HEAD(__msg_list,__msg_entry) msg_list_t;


int log_mgr_start(void);
int push_msg_to_log_list(int type,void* msg,int len);

#endif