#!/bin/sh

get_dns_server()
{
	local n=`awk '/nameserver/{print $2}' /tmp/resolv.conf.auto `
	local b=`echo $n`
	echo "$b"
}

set_pptpd_dns()
{
	local file="/etc/ppp/options.pptpd"
	echo " all server: $@ "
	sed -i '/ms-dns/d' $file
	for i in "$@";
	do
		echo "$i   ---- "
		echo  "ms-dns $i"  >>$file
	done
}


a=`get_dns_server`
echo "get dns server $a from resolv.conf.auto"
if [ -n "$a" ]; then
set_pptpd_dns $a
exit
fi
echo "not dns server at resolv.conf.auto"
