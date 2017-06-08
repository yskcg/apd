#!/bin/sh

#get the device mac address from flash

dd bs=1 skip=0 count=6 if=/dev/mtd1 | hexdump -v -n 6 -e '1/1 "%02x:" ' | sed -e 's/.$//' >/tmp/mac_address

#get the wireless 5G mac address
phy_num=`iw dev | grep "addr" | cut -d " " -f 2 | wc -l`

if [ $phy_num -ge 2 ];then
	iw dev | grep "addr" | cut -d " " -f 2 | sort -r | sed -e ${phy_num}d >/tmp/mac_address_5G
fi
exit 0
