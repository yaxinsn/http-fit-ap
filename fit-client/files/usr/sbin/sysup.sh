#!/bin/sh


bin_info=`hexdump -s 32 -n 32 -e '4/1 "%c"' $1`
bin_info=`echo $bin_info|cut -c1-$((${#bin_info}-1))`     
echo "bininfo :$bin_info:"

board_info=`cat /proc/cpuinfo | awk '/machine/{print $4}'`
board_info=$(echo $board_info | tr '[A-Z]' '[a-z]')
echo "board_info :$board_info:"
 
    if [ "$bin_info" = "$board_info" ];then
	echo "the bin will be allowed to upgrade this ap!"
	/sbin/sysupgrade $1 &
    else
	echo "the bin can't upgrade this ap!!"
	exit
    fi

