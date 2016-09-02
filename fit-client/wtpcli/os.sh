#!/bin/bash
#
##help
#
#
##version
#
#
##

CC=${CROSS_COMPILE}gcc
LD=${CROSS_COMPILE}ld
echo -e  \
"/* CC=$CC
 * LD=$LD
 * CFLAGS =${CFLAGS}
 * LDFLAGS=${LDFLAGS} 
 */\n"

TMP=./var/run/tmp
INC=$TMP/inc.h
LIB=$TMP/lib.a
SRC=$TMP/src.c
OBJ=$TMP/obj.o
OUT=$TMP/a.out

CFLAGS="-D_ALL_SOURCE=1 -D_GNU_SOURCE=1 $CFLAGS"

mkdir -p $TMP || exit 1
trap "rm -rf $TMP; exit ;" EXIT QUIT INT TERM
rm -f $TMP/* ;

# args   = xxx.h 
# result = #define HAVE_XXX_H 1   or  /* #undef HAVE_XXX_H */ 
function check_include()
{
	local N=""
	for H in $@ 
	do
		N=$(echo ${H//[\.\/]/_}| tr [:lower:] [:upper:])
		echo -e "/* Define to 1 if you have the <$H> header file */" 
		$CC $CFLAGS -include $H -o $OBJ -c -x c /dev/null 2>/dev/null >/dev/null
		[ $? -ne 0 ] && echo -e "/* #undef HAVE_$N */\n" && continue ;
		echo -e "#define HAVE_$N 1\n" 
		echo "#include <$H>" >> $INC
		rm -f $OBJ
	done
}

function check_library()
{
	echo "int main(int ac, char*av[]){ return 0; }" > $SRC
	for L in $@
	do
		N=$(echo $L | tr [:lower:] [:upper:]);
		echo -e "/* Define to 1 if you have the \`$L\` library */" ;
		$CC $CFLAGS $LDFLAGS -o $OUT $SRC -l$L 2>/dev/null >>/dev/null ;
		[ $? -ne 0 ] && echo -e "/* #undef HAVE_LIB$N */\n" && continue ;
		echo -e "#define HAVE_LIB$N 1\n"
		echo "-l$L" >> $LIB 
	done
	return 0 ;
}

function check_defined()
{
	$CC $CFLAGS -include $INC -x c /dev/null -E -dM -o $SRC
	for M in $@
	do
		echo -e "/* Define to 1 if you have the \`$M\` defined */" ;
		grep -a "^#define $M *" $SRC 2>/dev/null >/dev/null && \
			echo -e "#define HAVE_$M 1\n"    || \
			echo -e "/* #undef HAVE_$M */\n";
	done
	rm -f $SRC
	return 0 ;
}

function check_function()
{
	$CC $CFLAGS -include $INC -x c /dev/null -E -o $SRC
	for F in $@
	do
		N=$(echo $F | tr [:lower:] [:upper:])
		echo -e "/* Define to 1 if you have the \`$F()\` function */" ;
		grep -a "\<$F\>" $SRC 2>/dev/null >/dev/null && \
			echo -e "#define HAVE_$N 1\n" || \
			echo -e "/* #undef HAVE_$N */\n" ;
	done
	return 0 ;
}

function check_struct() 
{
	$CC $CFLAGS -include $INC -x c /dev/null -E -o $SRC
	for F in $@
	do
		N=$(echo $F | tr [:lower:] [:upper:])
		echo -e "/* Define to 1 if you have the type \`struct $F\` */" ;
		grep -a "struct[ \t]*$F" $SRC 2>/dev/null >/dev/null && \
			echo -e "#define HAVE_STRUCT_$N 1\n" || \
			echo -e "/* #undef HAVE_STRUCT_$N */\n" ;
	done
	return 0 ;
}

check_include stdio.h stddef.h stdlib.h string.h stdint.h stdarg.h unistd.h  \
	sys/types.h sys/time.h sys/param.h sys/clock.h sys/time.h sys/socket.h sys/un.h \
	sys/capability.h sys/cdefs.h sys/conf.h sys/fcntl.h sys/ioctl.h sys/ksym.h \
	sys/prctl.h sys/queue.h sys/resource.h sys/stat.h sys/utsname.h \
	netinet/in.h netinet/tcp.h netinet/ether.h arpa/inet.h netinet/udp.h \
	netinet/ip_icmp.h netinet/in_systm.h \
	netinet6/in6.h netinet6/in6_var.h netinet6/nd6.h netinet/icmp6.h \
	net/if.h net/if_var.h net/if_dl.h inet/nd.h \
	time.h fcntl.h execinfo.h assert.h ctype.h errno.h limits.h netdb.h \
	pty.h pwd.h signal.h strings.h stropts.h pthread.h \
	dlfcn.h syslog.h

check_defined CLOCK_MONOTONIC TCP_MD5SIG SUN_LEN AF_NETLINK AF_INET AF_INET6

check_struct icmphdr if6_aliasreq if6_aliasreq ifaliasreq ifmediareq \
	if_data in6_aliasreq in_pktinfo ip_mreqn nd_opt_adv_interval \
	nd_opt_homeagent_info rt_addrinfo \
	sockaddr sockaddr_dl sockaddr_in sockaddr_in6 sockaddr_un

check_function clock_gettime backtrace backtrace_symbols \
	pthread_condattr_setclock pthread_condattr_getclock \
   	pthread_setname_np pthread_getattr_np \
	daemon fork fcntl ioctl getaddrinfo ftruncate gethostbyname \
	getifaddrs getpagesize gettimeofday \
	if_indextoname if_nametoindex \
	inet_ntoa inet_aton inet_ntop inet_pton \
	snprintf vsnprintf \
	strftime strerror strlcat strlcpy strnlen strndup strncasecmp\
	strrchr strchr strtoul strtoull 

check_library crypt pthread rt dl m z


