//@20180407

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

//#include "sw_console.h"
//#include "sw_log.h"
#include "sw_dpdk.h"
#include "sw_filter.h"
#include "sw_offset.h"

const char *default_conf = "../conf/vswitch.conf";
int main(int argc, char ** argv)
{
	int ret = 0;
	uint32_t dpdk_pps;
	char conf[128] = {0};
	if (2 != argc)
	{
		printf("Usage:%s pps ,default pps: %d \n", argv[0], SW_DPDK_MAX_MBUF_NUM);
		dpdk_pps = SW_DPDK_MAX_MBUF_NUM;
	}
	else
		dpdk_pps = (uint32_t)atoi(argv[1]);

	memcpy(conf, default_conf, strlen(default_conf));
	
	//初始化dpdk
	ret = sw_dpdk_init(conf, dpdk_pps);
	if (ret < 0)
	{
		printf("sw_dpdk_init error, ret=%d!", ret);
		return -1;
	}

	ret = sw_filter_init("../conf/filter.conf");
	if (ret < 0)
	{
		//sw_log(SW_LOG_ERROR, "sw_dpdk_init error, ret=%d!", ret);
		printf("sw_filter_init error, ret=%d!", ret);
		return -1;
	}

	ret = sw_offset_init("../conf/offset.conf");
	if (ret < 0)
	{
		//sw_log(SW_LOG_ERROR, "sw_dpdk_init error, ret=%d!", ret);
		printf("sw_offset_init error, ret=%d!", ret);
		return -1;
	}

	sw_dpdk_start();
	
	//初始化控制台
	//ret = sw_console_init();
	//if (ret < 0)
	//{
	//	sw_log(SW_LOG_ERROR, "sw_console_init error, ret=%d!", ret);
	//	return -1;
	//}
	
	return 0;
}
