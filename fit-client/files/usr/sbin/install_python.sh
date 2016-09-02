#!/bin/sh


type=`cat /tmp/sysinfo/board_name`

while [ 1 ];do

if [ "$type" == "zbt-wa052" -o "$type" == "zbt-wa053" ];then

	python -V;
	if [ "$?" != "0" ];then
		opkg update && opkg install python && exit 0;
		
	else
		exit;
	fi
	
else
	exit;
fi
sleep 600;
done
