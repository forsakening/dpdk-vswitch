#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/types.h>

#include "sw_config.h"
#include "sw_dpdk.h"

static int sw_config_parse_tx_core_map(char* fmt, int* core_map)
{//[2,4,6]
	if (strlen(fmt) < 3 || fmt[0] != '[' || fmt[strlen(fmt) - 1] != ']')
		return -1;

	char trim[32] = {0};
	memcpy(trim, &fmt[1], strlen(fmt)-2);
	int i = 0;
	char* token = strtok(trim, SW_TX_MAP_SPLIT);
	while(token)
	{
		core_map[i] = atoi(token);
		if (core_map[i] < 0 || core_map[i] >= SW_DPDK_MAX_CORE)
			return -1;
		
		i++;
		if (i > SW_DPDK_MAX_TX_NUM) return -1;
		
        token = strtok(NULL, SW_TX_MAP_SPLIT);
    }

	if (i == 0)
		return -1;

	return i;
}

static int sw_config_parse(char* oneline, SW_PORT_PEER* port_peer)
{//rx_port,tx_port,rx_core,tx_core_map,delay_s
	int i = 0,ret;
	int rx_port = 0;
	int tx_port = 0;
	int delay_s = 0;
	int rx_core = 0;
	int tx_core_num = 0; 
	int tx_core_map[SW_DPDK_MAX_CORE] = {0};

	char rx_port_s[16] = {0};
	char tx_port_s[16] = {0};
	char delay_s_s[16] = {0};
	char rx_core_s[16] = {0};
	char tx_port_map_s[16] = {0};

	if (5 != (ret = sscanf(oneline, "%[^,],%[^,],%[^,],%[^,],%[^\n]", 
				rx_port_s,tx_port_s,rx_core_s,tx_port_map_s,delay_s_s)))
	{
		SW_CONFIG_Log_Error("sscanf error,ret:%d, %s-%s-%s-%s-%s \n", ret,
				rx_port_s,tx_port_s,rx_core_s,tx_port_map_s,delay_s_s);
		return -1;
	}
	
	//rx_port
	rx_port = atoi(rx_port_s);
	if (rx_port >= SW_DPDK_MAX_PORT || 0 > rx_port)
	{
		SW_CONFIG_Log_Error("rx port : %s error!\n", rx_port_s);
		return -1;
	}

	//tx_port
	tx_port = atoi(tx_port_s);
	if (tx_port >= SW_DPDK_MAX_PORT || 0 > tx_port)
	{
		SW_CONFIG_Log_Error("tx port : %s error!\n", tx_port_s);
		return -1;
	}

	//rx_core
	rx_core = atoi(rx_core_s);
	if (rx_core >= SW_DPDK_MAX_CORE || 0 > rx_core)
	{
		SW_CONFIG_Log_Error("rx core : %s error!\n", rx_core_s);
		return -1;
	}

	//tx_core_map
	tx_core_num = sw_config_parse_tx_core_map(tx_port_map_s, tx_core_map);
	if (0 > tx_core_num)
	{
		SW_CONFIG_Log_Error("tx core map: %s error!\n", tx_port_map_s);
		return -1;
	}

	//delay_s
	delay_s = atoi(delay_s_s);
	if (delay_s > SW_DPDK_MAX_DELAY || 0 > SW_DPDK_MAX_DELAY)
	{
		SW_CONFIG_Log_Error("rx core : %s error!\n", delay_s_s);
		return -1;
	}

#if 0
	char* token = strtok(oneline, ",");
	while (NULL != token)
	{
		i++;
		//printf("Token:%s \n", token);
		if (i == 1)
		{
			rx_port = atoi(token);
			if (rx_port >= SW_DPDK_MAX_PORT || 0 > rx_port)
			{
				SW_CONFIG_Log_Error("rx port : %s error!\n", token);
				return -1;
			}
		}
		else if (i == 2)
		{
			tx_port = atoi(token);
			if (tx_port >= SW_DPDK_MAX_PORT || 0 > tx_port)
			{
				SW_CONFIG_Log_Error("tx port : %s error!\n", token);
				return -1;
			}
		}
		else if (i == 3)
		{
			rx_core = atoi(token);
			if (rx_core >= SW_DPDK_MAX_CORE || 0 > rx_core)
			{
				SW_CONFIG_Log_Error("rx core : %s error!\n", token);
				return -1;
			}
		}
		else if (i == 4)
		{
			tx_core_num = sw_config_parse_tx_core_map(token, tx_core_map);
			if (0 > tx_core_num)
			{
				SW_CONFIG_Log_Error("tx core map: %s error!\n", token);
				return -1;
			}
		}		
		else if (i >= 5)
		{
			SW_CONFIG_Log_Error("Parameter Error!\n");
			return -1;
		}

		token = strtok(NULL, ",");
	}

	//last para
#endif	


	port_peer[rx_port].init = 1;
	port_peer[rx_port].rx_port = (uint16_t)rx_port;
	port_peer[rx_port].tx_port = (uint16_t)tx_port;
	port_peer[rx_port].delay_s = (uint16_t)delay_s;
	port_peer[rx_port].rx_core = (uint16_t)rx_core;
	port_peer[rx_port].tx_core_num = (uint16_t)tx_core_num;
	for (i = 0; i < tx_core_num; i++)
		port_peer[rx_port].tx_core_map[i] = (uint16_t)tx_core_map[i];

	//Conf Info
	SW_CONFIG_Log_Info("RX Port %u ==> RX Port %u\n", rx_port, port_peer[rx_port].rx_port);
	SW_CONFIG_Log_Info("RX Port %u ==> TX Port %u\n", rx_port, port_peer[rx_port].tx_port);
	SW_CONFIG_Log_Info("RX Port %u ==> Delay T %u\n", rx_port, port_peer[rx_port].delay_s);
	SW_CONFIG_Log_Info("RX Port %u ==> RX Core %u\n", rx_port, port_peer[rx_port].rx_core);
	SW_CONFIG_Log_Info("RX Port %u ==> TX Num  %u\n", rx_port, port_peer[rx_port].tx_core_num);
	SW_CONFIG_Log_Info("RX Port %u ==> TX Core: \n", rx_port);
	for (i = 0; i < tx_core_num; i++)
		SW_CONFIG_Log_Info("                  %u \n", port_peer[rx_port].tx_core_map[i]);
	
	return 0;
}

int sw_config_init(char* conf_path, void* port_peer_conf)
{
	if (NULL == conf_path)
		return -1;

	SW_PORT_PEER * port_peer = (SW_PORT_PEER *)port_peer_conf;
	FILE* fp = fopen(conf_path, "r");
	if (NULL == fp)
		return -1;

	
	char oneline[256] = {0};
	while(fgets(oneline, sizeof(oneline), fp) != NULL )
	{
		if (oneline[0] == '#' || oneline[0] == '\r' || oneline[0] == '\n')
			continue;

		printf("Parse:%s\n", oneline);
		if (0 > sw_config_parse(oneline, port_peer))
		{
			printf("Conf -- %s -- Error !\n", oneline);
			fclose(fp);
			return -1;
		}
		
	}

	fclose(fp);
	return 0;
}

