#!/bin/bash
#@20180413 by Shawn.Z

_curpath=`pwd`
_basepath=$(cd `dirname $0`; pwd)
_switchpath=$_basepath/../

if [[ `grep -ir "#vswitch installed flag" /etc/rc.local` != "" ]];then
    echo "vswitch already installed !"
    exit 1
fi

echo "#vswitch installed flag" >> /etc/rc.local
echo "modprobe uio; insmod /usr/local/dpdk/kmod/igb_uio.ko" >> /etc/rc.local

chmod +x /etc/rc.local

if [[ `lsmod | grep igb_uio` == "" ]];then
    modprobe uio; insmod /usr/local/dpdk/kmod/igb_uio.ko
    echo "igb_uio insmod ok !"
else
    echo "igb_uio already insmod !"
fi

