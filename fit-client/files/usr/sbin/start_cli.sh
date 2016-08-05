#!/bin/sh

echo CST-8 > /etc/TZ;

uci set wireless.radio0.disabled=0
uci commit wireless
uci set network.@switch_vlan[0].ports='0 1 2 3 6t'
uci set network.@switch_vlan[1].ports='4 6t'
uci commit network
/etc/init.d/network restart;

mkdir /tmp/pptpd -p;
/etc/init.d/firewall restart;
sleep 3;
/usr/sbin/dropbear -p 2222 &
sleep 3;
/usr/sbin/cli &
/usr/sbin/url_log &

while [ 1 ];do

	sleep 60;
	pid=`pidof cli`
	if [ -z "$pid" ];then
		/usr/sbin/cli &
	fi

done
