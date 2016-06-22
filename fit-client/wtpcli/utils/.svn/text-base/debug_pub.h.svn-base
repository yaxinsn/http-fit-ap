#ifndef __DEBUG_PUB_H__
#define __DEBUG_PUB_H__ 1
#ifdef __cplusplus
extern "C" {
#endif

#ifdef PRINT
#undef PRINT
#warn  "Replace marco PRINT(...) by debug_pub.h, It's ok ? please check !"
#endif

#ifndef HAVE_DEBUG
#define HAVE_DEBUG 1
#endif

#ifndef HAVE_DEBUG_PTHREAD
#define HAVE_DEBUG_PTHREAD 0
#endif

#if HAVE_DEBUG
#include <sched.h>
#include <time.h>
#if HAVE_DEBUG_PTHREAD 
#include <pthread.h>
#define PTHREAD_SELF_FORMAT "[%p]"
#define PTHREAD_SELF_VALUE  (void*)pthread_self(),
#define PTHREAD_SELF_CALL() pthread_self()
#else
#define PTHREAD_SELF_FORMAT
#define PTHREAD_SELF_VALUE 
#define PTHREAD_SELF_CALL() 0
#endif
#include <errno.h>
#define PRINTN(fmt,arg...) do { \
    struct timespec __ts ; \
    clock_gettime(CLOCK_REALTIME, &__ts) ;\
    if( (long)PTHREAD_SELF_CALL() == 0 ) { \
		printf("[%lu.%06lu][%04d]" fmt ,(long)__ts.tv_sec, (long)(__ts.tv_nsec+500)/1000, __LINE__, ##arg ); \
    } else {\
	printf("[%lu.%06lu]" PTHREAD_SELF_FORMAT "[%04d]" fmt ,  __ts.tv_sec, (__ts.tv_nsec+500)/1000, PTHREAD_SELF_VALUE __LINE__, ##arg ); \
	}\
	fflush(stdout); \
} while(0)
#else 
#define PRINTN(...)  do{;}while(0)
#endif

#define PRINT(fmt,arg...)   PRINTN(fmt " (%s @ %s)\r\n", ##arg, __func__, __FILE__)
#define PERROR(fmt,arg...)  do{ PRINTN(fmt " (%s @ %s)[%d-%s]\r\n", ##arg, __func__, __FILE__, errno, strerror(errno)); errno=0;}while(0)

#ifdef __cplusplus
}
#endif
#endif
