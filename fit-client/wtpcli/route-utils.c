

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

char* find_value_from_sjon_by_key2(json_object* obj,char* skey)
{
    char* v_b=0;
    const char* v_j;
    
  json_object_object_foreach(obj, key, val) {
      if(!strcmp(skey,key)){
          v_j = json_object_to_json_string(val);            
          v_b = malloc(strlen(v_j)+1);
          if(v_b){
            memset(v_b,0,strlen(v_j)+1);
            strncpy(v_b,v_j,strlen(v_j));
          }
          return v_b;
      }
  }
  return NULL;
  
}


char* skip_str_prefix(char* src,char c)
{
    char* data = src;
    char* tail = src+strlen(src)-1;
    while(*data == c)
        data++;
        
    while(*tail == c )
        tail--;
		
    *(tail+1)=0;
    return data;
}




int get_net_dev_stat(char* name,struct ifinfo* ifc)
{
    FILE* fp = NULL;
    char line[200];
    size_t len = 200;
    char sname[32];

    if((!name) || (!ifc))
        return -1;
    fp = fopen("/proc/net/dev",
"r");
    if(fp == NULL)
        return -1;
    /* skip 2 line */
    fgets(line,len,fp);
    fgets(line,len,fp);
    
    while(fgets(line,len,fp) != NULL)
    {
        sscanf(line,"%16[^:]:%lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
            (char*)&sname,
            &ifc->r_bytes,&ifc->r_pkt,&ifc->r_err,&ifc->r_drop,
            &ifc->r_fifo,&ifc->r_frame,&ifc->r_compr,&ifc->r_mcast,
            &ifc->t_bytes,&ifc->t_pkt,&ifc->t_err,&ifc->t_drop,
            &ifc->t_fifo,&ifc->t_coll,&ifc->t_corrier,&ifc->t_compr);
        if(strcmp(sname,name) == 0)
        {
            fclose(fp);
            return 0;
        }
    }
    fclose(fp);
    return -1;
    
}

uint8_t get_memory_usage(void)
{
    FILE* fp = NULL;
    char line[200];
    size_t len = 200;
    int mem_free = 0;
    int mem_total = 0;
    uint8_t usage;

    fp = fopen("/proc/meminfo","r");
    if(fp == NULL)
    {
        return -1;
    }
    fgets(line,len,fp);
    sscanf(line,"MemTotal:%d kB", &mem_total);

    
    fgets(line,len,fp);
    sscanf(line,"MemFree:%d kB", &mem_free);

	//printf("tttt mem_free  %d mem_total %d \n",mem_free,mem_total);
    usage = (uint8_t)(100*(mem_total - mem_free)/mem_total);
    //*remain = mem_free;
    fclose(fp);
    return usage;
}
int get_cpu_usage(void)
{
	FILE* fp = NULL;
	char line[200];
	size_t len=200;
	int ret;	

	static unsigned long old_all=0;
	static unsigned long old_idle=0;
	unsigned long user = 0;
	unsigned long nice = 0;
	unsigned long system = 0;
	unsigned long idle = 0;
	unsigned long iowait = 0;
	unsigned long irq = 0;
	unsigned long softirq = 0;

	unsigned long all = 0;
	fp = fopen("/proc/stat", "r");
	if(fp == NULL)
	{
		perror("fopen /proc/stat");
		return -1;
	}
	fgets(line,len,fp);
	sscanf(line,"cpu %lu %lu %lu %lu %lu %lu %lu", 
		&user,&nice,&system,&idle,&iowait,&irq,&softirq);
	all = user+nice+system+iowait+irq+softirq+idle;
	//printf("all %lu ,idle %lu old_all %lu old_idle %lu\n",all,idle,old_all,old_idle);

    ret = 100 - (int)(((idle - old_idle)*100)/(all - old_all));
  
	old_idle = idle;
	old_all = all;
	fclose(fp);
	return ret;
}
