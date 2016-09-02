
svn_r=${shell ./svn_ver.sh}
time=$(shell date +%F_%H-%M-%S)
version=${shell cat fit-client/files/etc/.cli_version}
all:show build release

show:
	echo $(version)   "${svn_r}"

build:
	cp openwrt/zbt-wa53.config ../openwrt.bb/.config -f
	cd ../openwrt.bb && make V=s;
release:
	mkdir ../release_version/$(version)/ -p
	cd ../openwrt.bb && cp bin/ramips/openwrt-ramips-mt7620a-zbt-wa053-squashfs-sysupgrade.bin ../release_version/$(version)/zbt-wa053-$(version)_r${svn_r}-$(time).bin
