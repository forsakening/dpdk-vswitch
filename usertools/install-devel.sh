#!/bin/bash
#@20180407 by Shawn.Z
#@20180512 by Shawn.Z support Hyperscan-4.5.0

_curpath=`pwd`
_basepath=$(cd `dirname $0`; pwd)
_repo=$_basepath/devel-packages/

rm -rf /etc/yum.repos.d/vswitch.repo
echo "[vswitch]" >> /etc/yum.repos.d/vswitch.repo
echo "name=vswitch" >> /etc/yum.repos.d/vswitch.repo
echo "baseurl=file://$_repo" >> /etc/yum.repos.d/vswitch.repo
echo "enabled=1" >> /etc/yum.repos.d/vswitch.repo
echo "gpgckeck=0" >> /etc/yum.repos.d/vswitch.repo

yum --disablerepo=\* --enablerepo=vswitch install -y tcpdump numactl-devel vim gdb perf cmake gcc gcc-c++ glibc-static

rm -rf /etc/yum.repos.d/vswitch.repo

_rpm=$_basepath/devel-packages/rpms
rpm -ivh $_rpm/pciutils-3.5.1-3.el7.x86_64.rpm --nodeps --force
rpm -ivh $_rpm/pciutils-libs-3.5.1-3.el7.x86_64.rpm --nodeps --force

##install hyperscan and devel
_hyper=$_basepath/../hyperscan
cd $_hyper
echo "[HY Step 1] Install ragel 6.9 ...."
if [ -e "/usr/local/bin/ragel" ];then
    echo "    Ragel already installed, skip it !"
else
    tar xzf ragel-6.9.tar.gz
    cd ragel-6.9
    ./configure > /dev/zero 
    make > /dev/zero 
    make install > /dev/zero
    echo "    Ragel install ok !"
    cd ..
    rm -rf ./ragel-6.9
fi

cd $_hyper
echo "[HY Step 2] Install Boost 1.60 ...."
rm -rf ./boost_1_60_0
if [ -d "/usr/local/include/boost/" ];then
    echo "    Boost already installed, skip it !"
else
    tar xzf boost_1_60_0.tar.gz
    cd boost_1_60_0
    ./bootstrap.sh > /dev/zero
    ./b2 > /dev/zero
    ./b2 install > /dev/zero
    echo "    Boost install ok !"
    cd ..
    rm -rf ./boost_1_60_0
fi

cd $_hyper
echo "[HY Step 3] Install Hyperscan 4.5.0 ...."
rm -rf ./hyperscan-4.5.0
if [ -d "/usr/local/include/hs/" ];then
    echo "    Hyperscan already installed, skip it !"
else
    tar xzf hyperscan-4.5.0.tar.gz
    cd hyperscan-4.5.0
    cmake ./ > /dev/zero
    make install > /dev/zero
    cd ..
    rm -rf ./hyperscan-4.5.0
    echo "    Hyperscan install ok !"
fi
#####################################################
echo ""
echo "Devel Install OK !"
cd $_curpath
