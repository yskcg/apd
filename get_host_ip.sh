#!/bin/sh
ip -4 addr show dev br-lan | grep inet | awk '{print$2}' | sed -e 's/\/.*//g' | sed -e '/192.168.33.111/d' >/tmp/host_ip
