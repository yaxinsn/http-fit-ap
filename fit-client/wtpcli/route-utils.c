

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include <sys/types.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/ioctl.h>
#include <net/if.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <utils/utils.h>
#include <utils/vty.h>
#include <utils/thread.h>
#include <utils/command.h>
#include <utils/log.h>
#include <utils/vector.h>
#include <utils/network.h>

#include <net/route.h>
#include <net/if.h>
#include "route.h"
int read_route(char* ret_port_name)

{
	char devname[64], flags[16], *sdest, *sgw;
	unsigned long d, g, m;
	int flgs, ref, use, metric, mtu, win, ir;
	struct sockaddr_in s_addr;
	struct in_addr mask;
	int ret;

	FILE *fp = fopen("/proc/net/route","r");

	//printf("Kernel IP routing table\n"
	  //     "Destination     Gateway         Genmask         Flags %s Iface\n",
		//	netstatfmt ? "  MSS Window  irtt" : "Metric Ref    Use");

	if (fscanf(fp, "%*[^\n]\n") < 0) { /* Skip the first line. */
		goto ERROR;		   /* Empty or missing line, or read error. */
	}
	while (1) {
		int r;
		r = fscanf(fp, "%63s%lx%lx%X%d%d%d%lx%d%d%d\n",
				   ret_port_name, &d, &g, &flgs, &ref, &use, &metric, &m,
				   &mtu, &win, &ir);
		if (r != 11) {
			if ((r < 0) && feof(fp)) { /* EOF with no (nonspace) chars read. */
				break;
			}
		}
		if (!(flgs & RTF_UP)) { /* Skip interfaces that are down. */
			continue;
		}
		
        if(d == 0) // i get it.
        {
           // printf(" ---- ret_port_name <%s> ret_port_name %p\n",ret_port_name,ret_port_name);
           // strncpy(ret_port_name,devname,32);
            //sprintf(ret_port_name,"%s",devname);
            fclose(fp);
            return 0;
        }
	}
ERROR:
    fclose(fp);
    return -1;
}
int get_wan_port(char* ret_port_name)
{

    int ret;
            
    ret = read_route(ret_port_name);
    return ret;
}
int get_iface_ip(char* name,struct in_addr* ip)
{
    struct sockaddr_in *addr;
    struct ifreq ifr;
    char* address;
    int sockfd;


    sockfd = socket(AF_INET,SOCK_DGRAM,0);
    strncpy(ifr.ifr_name,name,IFNAMSIZ-1);

    if(ioctl(sockfd,SIOCGIFADDR,&ifr) == -1)
    	{
	perror("ioctl error");
		return -1;
    	}
    addr = (struct sockaddr_in *)&(ifr.ifr_addr);
    address = inet_ntoa(addr->sin_addr);
	memcpy(ip,&addr->sin_addr,sizeof(struct in_addr));
	return 0;
	
    //printf("inet addr: %s ",address);
#if 0
    if(ioctl(sockfd,SIOCGIFBRDADDR,&ifr) == -1)
            perror("ioctl error"),exit(1);
    addr = (struct sockaddr_in *)&ifr.ifr_broadaddr; 
    address = inet_ntoa(addr->sin_addr);
    printf("broad addr: %s ",address);

    if(ioctl(sockfd,SIOCGIFNETMASK,&ifr) == -1)
            perror("ioctl error"),exit(1);
    addr = (struct sockaddr_in *)&ifr.ifr_addr;
    address = inet_ntoa(addr->sin_addr);
    printf("inet mask: %s ",address);

    printf("\n");
    exit(0);
#endif
}



int get_iface_mac(char* name,char* macaddr)
{
    struct ifreq ifr;
    int sockfd;


    sockfd = socket(AF_INET,SOCK_DGRAM,0);
	if(sockfd == 0)
		return -2;
	
    strncpy(ifr.ifr_name,name,IFNAMSIZ-1);

    if(ioctl(sockfd,SIOCGIFHWADDR,&ifr) == -1)
    	{
			perror("ioctl error");
		return -1;
    	}
	
	memcpy(macaddr,&ifr.ifr_hwaddr.sa_data,6);
	return 0;
	

}


/****************************sjon**********************************/


json_object* create_sjon_from_string(char* str)
{
    json_object *new_obj = json_tokener_parse(str);
    return new_obj;
    
}

const char* find_value_from_sjon_by_key(json_object* obj,char* skey)
{
   //return json_object_to_json_string(json_object_object_get(obj,skey));
   #if 1
      json_object_object_foreach(obj, key, val) {
        if(!strcmp(skey,key))
            return json_object_to_json_string(val);

            
   // printf("\t%s: %s\n", key, json_object_to_json_string(val));
  }
  return NULL;
  #endif
}

void free_json(json_object* obj)
{
    json_object_put(obj);
}