//@20180407

#include <stdio.h>

//#include "sw_console.h"
//#include "sw_log.h"
#include "sw_dpdk.h"

int main(int argc, char ** argv)
{
	int ret = 0;
	if (2 != argc)
	{
		printf("Usage:%s conf_path ...\n", argv[0]);
		return -1;
	}

	//初始化dpdk
	ret = sw_dpdk_init(argv[1]);
	if (ret < 0)
	{
		//sw_log(SW_LOG_ERROR, "sw_dpdk_init error, ret=%d!", ret);
		printf("sw_dpdk_init error, ret=%d!", ret);
		return -1;
	}
	
	//初始化控制台
	//ret = sw_console_init();
	//if (ret < 0)
	//{
	//	sw_log(SW_LOG_ERROR, "sw_console_init error, ret=%d!", ret);
	//	return -1;
	//}
	
	return 0;
}
