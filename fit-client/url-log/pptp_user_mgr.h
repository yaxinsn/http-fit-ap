
#ifndef PPTP_USER_MSG_H
#define PPTP_USER_MSG_H
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>  
#include <sys/un.h> 
#include <fcntl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <pthread.h>

pthread_t pptp_user_mgr_start();

#define PPTP_USER_ACTION_LOGON  0
#define PPTP_USER_ACTION_LOGOFF 1
struct pptp_msg{
    char username[64];
    char port[32];
    char peerip[32];
    char localip[32];
    int pptp_pid;
    int pppd_pid;
    int action;// 0 logon 1 logoff
};

int get_pptp_user_info_by_port(char* ifname,
	struct pptp_msg* pptp_info);
#endif

