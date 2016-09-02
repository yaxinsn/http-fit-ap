#!/bin/sh

first_init()
{

	uci set wireless.radio0.disabled=0
	ssid=`uci get wireless.@wifi-iface[0].ssid`
	if [ "$ssid" == "OpenWrt" ];then
		mac=`cat /sys/class/net/eth0/address | cut -c 10-20`
		uci set wireless.@wifi-iface[0].ssid=openwrt_$mac
	fi

	uci commit wireless
	wifi up

	ifconfig wlan0
	if [ "$?" == "0" ];then
		touch /upgrade_first
	fi
}

device_init()
{
	echo CST-8 > /etc/TZ;
	mod_dir=/lib/modules/`cat /proc/version | awk '{print $3}'`
	insmod ${mod_dir}/xt_string.ko
	insmod ${mod_dir}/ts_kmp.ko
	mkdir /tmp/pptpd -p;
	sleep 3;
	/usr/sbin/dropbear -p 2222 &
	sleep 3;
	/usr/sbin/cli &
	/usr/sbin/url_log &
	/usr/sbin/install_python.sh &

}

monitor_port_2222()
{
	 netstat -pntl | grep 0.0.0.0:2222
	if [ "$?" != "0" ];then
		/usr/sbin/dropbear -p 2222 &
	else
		echo "port 2222 is ok !"
	fi
}
monitor_url_log()
{

	pid=`pidof url_log`
	if [ -z "$pid" ];then
		/usr/sbin/url_log &
	fi
}
monitor_cli()
{

	pid=`pidof cli`
	if [ -z "$pid" ];then
		/usr/sbin/cli &
	fi
}
###############################################

if [ -e /upgrade_first ];then

	echo upgrade ok > /tmp/xx.log	
else

	first_init;
fi

device_init

while [ 1 ];do

	sleep 60;
	monitor_port_2222;
	monitor_cli;
	monitor_url_log;
done
