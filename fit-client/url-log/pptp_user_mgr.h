
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

#endif

