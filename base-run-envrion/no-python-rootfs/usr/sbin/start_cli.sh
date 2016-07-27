#!/bin/sh

echo CST-8 > /etc/TZ;
mkdir /tmp/pptpd -p;
/etc/init.d/firewall restart;
sleep 3;
/usr/sbin/dropbear -p 2222 &
sleep 3;
/usr/sbin/cli &

while [ 1 ];do

	sleep 60;
	pid=`pidof cli`
	if [ -z "$pid" ];then
		/usr/sbin/cli &
	fi

done
