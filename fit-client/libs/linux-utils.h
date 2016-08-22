#ifndef  __LINUX_UTILS_H
#define  __LINUX_UTILS_H
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
int get_iface_ip(char* name,struct in_addr* ip);
int get_iface_mac(char* name,unsigned char* macaddr);
int send_msg(int type,char* msg,int len,char* recv,int* recvlen);

int get_wan_port(char* ret_port_name);
int get_wan_ip(struct in_addr*  addr);

/* this strings function */
char* skip_str_prefix(char* src,char c);

/**************status info *************************/
struct ifinfo
{
    unsigned long r_bytes,r_pkt,r_err,r_drop,r_fifo,r_frame;
    unsigned long r_compr,r_mcast;
    unsigned long t_bytes,t_pkt,t_err,t_drop,t_fifo,t_coll;
    unsigned long t_corrier,t_compr;
};
int get_net_dev_stat(char* name,struct ifinfo* ifc);
uint8_t get_memory_usage(void);
int get_cpu_usage(void);


/* fcntl fuction */
int file_set_block(int fd);
int file_line_num(char* path);

#endif //__LINUX_UTILS_H
