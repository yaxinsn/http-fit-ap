#ifndef _U_LOG_H
#define _U_LOG_H
#include <stdio.h>  
#include <sys/types.h>  

#include <time.h>
#include <stdarg.h>



int _p_log(const char* func,int line,const char* fmt,...);

#define _u_log(fmt,...) \
	_p_log(__func__,__LINE__,fmt"\n", ##__VA_ARGS__)

#define _u_err_log(fmt,...) \
	_p_log(__func__,__LINE__,"ERROR|"fmt"\n", ##__VA_ARGS__)

#endif  

