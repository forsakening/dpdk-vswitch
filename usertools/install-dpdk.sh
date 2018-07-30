#!/bin/bash
#@20180407 by Shawn.Z

_curpath=`pwd`
_basepath=$(cd `dirname $0`; pwd)
_dpdkpath=$_basepath/../dpdk/

function _exit()
{
    echo "Exit: Bye!"
    cd $_curpath
    exit 1
}

#check dpdk install
if [ -d "/usr/local/dpdk" ];then
    echo "Warn: Seems dpdk already installed , Remove /usr/local/dpdk manually !"
    _exit
fi

#check kernels
_kernel_v=`uname -r`
if [ ! -d "/usr/src/kernels/$_kernel_v" ];then
    echo "Failed: Kernel $_kernel_v is not exist!"
    _exit
else
    echo "[Step] Checking Kernels ..."
    export RTE_KERNELDIR=/usr/src/kernels/$_kernel_v/
fi

#decompress
cd $_dpdkpath
rm -rf ./dpdk-18.02
if [ -f dpdk-18.02.tar ];then
    echo "[Step] Decompressing DPDK 1802 ..."
    tar xf dpdk-18.02.tar 
else
    echo "Failed: dpdk-18.02.tar is not exist!"
    _exit
fi

#change configuration and make install etc.
cd ./dpdk-18.02
export prefix="/usr/local/dpdk/"
sed -i "s/pci_intx_mask_supported(udev->pdev)/pci_intx_mask_supported(udev->pdev)||true/g" lib/librte_eal/linuxapp/igb_uio/igb_uio.c
make config T=x86_64-native-linuxapp-gcc
make
make install
sudo cp -rf ./build/kmod /usr/local/dpdk/

#insert dpdk uio kmod
_mod=`lsmod | grep igb_uio`
if [[ $_mod != "" ]];then
    modprobe uio
    insmod /usr/local/dpdk/kmod/igb_uio.ko
fi

echo "Install DPDK-1802 Success !"
_exit
