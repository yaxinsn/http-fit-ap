
#ifndef URL_LOG_H url_log.h
#define URL_LOG_H


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


enum enum_msg_type{
	URL_MSG_TYPE = 1,
	LOGON_OFF_MSG_TYPE = 2,
};
typedef struct __msg_entry
{
	TAILQ_ENTRY(__msg_entry) node;
	long	time_stamp;
	int 	len;
	enum	enum_msg_type;
	int 	msg_len; //len is len of data
	char	msg[0];
}__msg_entry_t

typedef TAILQ_HEAD(__msg_list,__msg_entry) msg_list_t;


int outlog(void);
pthread_t pptp_user_mgr_start();


#endif