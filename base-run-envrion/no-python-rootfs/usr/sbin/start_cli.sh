#!/bin/sh


/usr/sbin/cli &

while [ 1 ];do

	sleep 60;
	pid=`pidof cli`
	if [ -z "$pid" ];then
		/usr/sbin/cli &
	fi

done
