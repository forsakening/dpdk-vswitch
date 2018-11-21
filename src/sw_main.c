//@20180407

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>   
#include <sys/stat.h>   
#include <fcntl.h> 
#include <errno.h>

//#include "sw_console.h"
//#include "sw_log.h"
#include "sw_dpdk.h"
#include "sw_filter.h"
#include "sw_offset.h"
#include "sw_httpserver.h"

FILE *runlogF;
#define VSWITCH_LOCK "/run/vswitch.lock"

const char *default_conf = "/home/vswitch/conf/vswitch.conf";
const char *run_log = "/home/vswitch/build/runlog";
int main(int argc, char ** argv)
{
	runlogF = fopen(run_log, "wb");
	//check and create the programme lock
	if (-1 != access(VSWITCH_LOCK, F_OK))
	{
		printf("The %s exist, maybe vswitch already running, plz check it! \n", VSWITCH_LOCK);
		fprintf(runlogF, "The %s exist, maybe vswitch already running, plz check it!", VSWITCH_LOCK);
		fclose(runlogF);
		return -1;
	}

	if (0 > open(VSWITCH_LOCK, O_CREAT))
	{
		printf("The %s create error! \n", VSWITCH_LOCK);
		fprintf(runlogF, "The %s create error! ", VSWITCH_LOCK);
		fclose(runlogF);
		return -1;
	}

	///////////////////////////////////////////////////////////////////////
	int ret = 0;
	int deamon_flag = 0;
	uint32_t dpdk_pps;
	char conf[128] = {0};
	char ppsbuf[32] = {0};
	FILE *ppsfile;
	if (2 != argc && 3 != argc)
	{
		printf("Usage: ./vswitch pps -d  or ./vswitch pps ... \n");
		fprintf(runlogF, "Usage: ./vswitch pps -d  or ./vswitch pps ... ");
		fclose(runlogF);
		goto _quit;
	}

	if (3 == argc)
	{
		if (0 == strcmp("-d", argv[2]))
			deamon_flag = 1;
		else
		{
			printf("Usage: ./vswitch pps -d  or ./vswitch pps ... \n");
			fprintf(runlogF, "Usage: ./vswitch pps -d  or ./vswitch pps ... ");
			fclose(runlogF);
			goto _quit;
		}
	}

	if (deamon_flag)
	{
		printf("Start to deamon the vswitch programme .... \n");
		if(daemon(1, 1) < 0)
		{
			printf("Deamon the vswitch programme error .... \n");
			fprintf(runlogF, "Deamon the vswitch programme error .... ");
			fclose(runlogF);
			goto _quit;
		}
	}
		
	dpdk_pps = (uint32_t)atoi(argv[1]);

	if (dpdk_pps == 0) {
		ppsfile = fopen("/home/vswitch/conf/pps.conf", "rb");
		fread(ppsbuf, 1, 32, ppsfile);
		dpdk_pps = (uint32_t)atoi(ppsbuf);
		fclose(ppsfile);
	} else {
		ppsfile = fopen("/home/vswitch/conf/pps.conf", "wb");
		fprintf(ppsfile, "%u", dpdk_pps);
		fclose(ppsfile);
	}
	memcpy(conf, default_conf, strlen(default_conf));
	
	//³õÊ¼»¯dpdk
	ret = sw_dpdk_init(conf, dpdk_pps);
	if (ret < 0)
	{
		printf("sw_dpdk_init error, ret=%d!", ret);
		fprintf(runlogF, "vswitch init error, please check \"vswitch.conf\" or \"fwd_rules.conf\" .... ");
		fclose(runlogF);
		goto _quit;
	}

	ret = sw_filter_init("/home/vswitch/conf/filter.conf");
	if (ret < 0)
	{
		//sw_log(SW_LOG_ERROR, "sw_dpdk_init error, ret=%d!", ret);
		printf("sw_filter_init error, ret=%d!", ret);
		fprintf(runlogF, "sw_filter_init error  /home/vswitch/conf/filter.conf .... ");
		fclose(runlogF);
		goto _quit;
	}

	ret = sw_offset_init(SW_OFFSET_CFG);
	if (ret < 0)
	{
		//sw_log(SW_LOG_ERROR, "sw_dpdk_init error, ret=%d!", ret);
		printf("sw_offset_init error, ret=%d!", ret);
		fprintf(runlogF, "sw_offset_init error %s .... ", SW_OFFSET_CFG);
		fclose(runlogF);
		goto _quit;
	}

	ret = sw_httpserver_init(22334);
	if (0 != ret)
	{
		printf("sw_httpserver_init error, ret=%d!", ret);
		fprintf(runlogF, "sw_httpserver_init error .... ");
		fclose(runlogF);
		goto _quit;
	}
	
	sw_dpdk_start();

_quit:
	//remove the programme lock
	if (0 != remove(VSWITCH_LOCK))
	{
		printf("Remove %s error !\n", VSWITCH_LOCK);
	}
		
	return 0;
}
