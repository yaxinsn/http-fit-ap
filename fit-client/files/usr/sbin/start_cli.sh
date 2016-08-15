#!/bin/sh

echo CST-8 > /etc/TZ;


mod_dir=/lib/modules/`cat /proc/version | awk '{print $3}'`
insmod ${mod_dir}/xt_string.ko
insmod ${mod_dir}/ts_kmp.ko

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
/usr/sbin/install_python.sh &


monitor_port_2222()
{
	 netstat -pntl | grep 0.0.0.0:2222
	if [ "$?" != "0" ];then
		/usr/sbin/dropbear -p 2222 &
	else
		echo "port 2222 is ok !"
	fi
}
monitor_cli()
{

	pid=`pidof cli`
	if [ -z "$pid" ];then
		/usr/sbin/cli &
	fi
}

while [ 1 ];do

	sleep 60;
	monitor_port_2222;
	monitor_cli;
done
