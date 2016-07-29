
#ifndef CONNECTION_H
#define CONNECTION_H

enum msg_type {
MSG_TYPE_GETVER=0,
MSG_TYPE_GETVPN,
MSG_TYPE_PUTROUTESTATE, //  == getcmd.

MSG_TYPE_GETTASK,
MSG_TYPE_PUT_USER_SEARCH_KEYS,	
};

int send_msg(int type,char* msg,int len,char* recv,int* recvlen);
#endif


