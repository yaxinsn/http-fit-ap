
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>

int _p_log(const char* func,int line,const char* fmt,...);
#define _deloger(fmt,...) \
	_p_log(__func__,__LINE__,fmt"\n", ##__VA_ARGS__)

int _p_log(const char* func,int line,const char* fmt,...)
{
	va_list args;
	int l;
	char buf[1024];
	va_start(args,fmt);
	l = sprintf(buf,"%s:%d",func,line);
	vsprintf(buf+l,fmt,args);
	printf("%s",buf);
	va_end(args);
}

int main()
{
	_deloger("-------------%s","dddd");
	_deloger("-------------%s","ddaadd");
}
