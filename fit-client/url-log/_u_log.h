#ifndef _U_LOG_H
#define _U_LOG_H
#include <stdio.h>  
#include <sys/types.h>  

#include <time.h>
#include <stdarg.h>
#include <pthread.h>

int _p_log(const char* func,int line,const char* fmt,...);
#if 1
#define _u_log(fmt,...) \
	_p_log(__func__,__LINE__,fmt"\n", ##__VA_ARGS__);

#define _u_err_log(fmt,...) \
	_p_log(__func__,__LINE__,"ERROR|"fmt"\n", ##__VA_ARGS__);
#else
#define _u_log printf
#define _u_err_log printf
#endif
#endif  

