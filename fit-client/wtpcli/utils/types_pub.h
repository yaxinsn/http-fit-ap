#ifndef __TYPES_PUB_H__
#define __TYPES_PUB_H__ 1

typedef   signed  char   s8 ;
typedef unsigned  char   u8 ;
typedef   signed  short  s16;
typedef unsigned  short  u16;
typedef   signed  int    s32;
typedef unsigned  int    u32;
typedef   signed  long  long  s64;
typedef unsigned  long  long  u64;

typedef   signed  long   sptr_t;
typedef unsigned  long   uptr_t; 

#define HAVE_TYPEDEF_U8   1
#define HAVE_TYPEDEF_U16  1
#define HAVE_TYPEDEF_U32  1
#define HAVE_TYPEDEF_U64  1


/* utils */

#ifndef __KERNEL__ /* !KERNEL */

/* likely/unlikely */
#ifndef likely
#define likely(x)    __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x)  __builtin_expect(!!(x), 0)
#endif

/* INITCALL/EXITCALL */
#define INITCALL    __attribute__ ((constructor))
#define EXITCALL    __attribute__ ((destructor))
#define UNUSED      __attribute__ ((unused))
#define ALIGNED(n)  __attribute__ ((aligned(n)))


#endif /* !__KERNEL__ */


#endif
