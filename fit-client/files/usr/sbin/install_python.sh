#!/bin/sh


type=`cat /tmp/sysinf/board_name`

while [ 1 ];do

if [ "$type" == "zbt-wa052" ];then

	python -V;
	if [ "$?" != 0 ];then
		opkg update && opkg install python && exit 0;
		
	else
		exit;
	fi
	
else
	exit;
fi

done