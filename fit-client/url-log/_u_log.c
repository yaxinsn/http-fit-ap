#ifndef _U_LOG_H
#define _U_LOG_H
#include <stdio.h>  
#include <sys/types.h>  

#include <time.h>
#include <stdarg.h>
#include "_u_log.h"
#include <stdarg.h>


static pthread_mutex_t __mutex;  //sync



int _p_log(const char* func,int line,const char* fmt,...)
{
	va_list args;
	int l;
	static FILE* log_fp = 0;
	static int log_line = 0;
	int fd;
	char buf[1024]={0};

	pthread_mutex_lock(&__mutex); 
	if(log_fp == NULL)
	{
	    log_fp = fopen("/tmp/url_logd.log","w");
	}
	
	time_t a;
	time(&a);
	va_start(args,fmt);
	l = sprintf(buf,"%s",ctime(&a));
	l -=1;
	l += sprintf(buf+l,"|%s|%d|  ",func,line);
	vsprintf(buf+l,fmt,args);
	va_end(args);
	
	if(log_fp == NULL)
	    fprintf(stderr,"%s",buf);
	else 
	{
	    log_line++;
	    fprintf(log_fp,"%s",buf);
	    fflush(log_fp);
	}
	if(log_line >=2048)
	{
	    fd = fileno(log_fp);
	    ftruncate(fd, 0);
	    lseek(fd, 0, SEEK_SET);
	    log_line = 0;
	}
	pthread_mutex_unlock(&__mutex); 
	return 0;
}
#if 0
int ___p_log(const char* func,int line,const char* fmt,...)
{
   
	pthread_mutex_lock(&__mutex); 
	__p_log(func,line,fmt, ##__VA_ARGS__);
	pthread_mutex_unlock(&__mutex); 
	return 0;
    
}
#endif
#endif  

