#!/bin/sh

#get the device mac address from flash

dd bs=1 skip=0 count=6 if=/dev/mtd1 | hexdump -v -n 6 -e '1/1 "%02x:" ' | sed -e 's/.$//' >/tmp/mac_address

exit 0
