#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/types.h>

#include "sw_config.h"
#include "sw_dpdk.h"

int sw_config_parse_tx_core_map(char* fmt, int* core_map)
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
int sw_config_console_parse_tx_core_map(char* fmt, short* core_map)
{//[2,4,6]
	if (strlen(fmt) < 3 || fmt[0] != '[' || fmt[strlen(fmt) - 1] != ']')
		return -1;
	char trim[32] = {0};
	memcpy(trim, &fmt[1], strlen(fmt)-2);
	int i = 0;
	char* token = strtok(trim, ",");
	while(token)
	{
		core_map[i] = atoi(token);
		if (core_map[i] < 0 || core_map[i] >= SW_DPDK_MAX_CORE)
			return -1;
		i++;
		if (i > SW_DPDK_MAX_TX_NUM) return -1;
        token = strtok(NULL, ",");
    }

	if (i == 0)
		return -1;

	return i;
}

static int sw_config_parse(char* oneline, SW_PORT_PEER* port_peer)
{//rx_port,tx_port,rx_core,tx_core_map,delay_s,loopbak
	int i = 0,ret;
	int rx_port = 0;
	int tx_port = 0;
	int delay_s = 0;
	int rx_core = 0;
	int tx_core_num = 0; 
	int tx_core_map[SW_DPDK_MAX_CORE] = {0};
	int loopback = 0;

	char rx_port_s[16] = {0};
	char tx_port_s[16] = {0};
	char delay_s_s[16] = {0};
	char rx_core_s[16] = {0};
	char tx_port_map_s[32] = {0};
	char loopback_s[16] = {0};

	if (6 != (ret = sscanf(oneline, "%[^,],%[^,],%[^,],%[^,],%[^,],%[^\n]", 
				rx_port_s,tx_port_s,rx_core_s,tx_port_map_s,delay_s_s, loopback_s)))
	{
		SW_CONFIG_Log_Error("sscanf error,ret:%d, %s-%s-%s-%s-%s-%s \n", ret,
				rx_port_s,tx_port_s,rx_core_s,tx_port_map_s,delay_s_s, loopback_s);
		return -1;
	}

	SW_CONFIG_Log_Info("sscanf ok,ret:%d, %s-%s-%s-%s-%s-%s \n", ret,
				rx_port_s,tx_port_s,rx_core_s,tx_port_map_s,delay_s_s, loopback_s);
	
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
		SW_CONFIG_Log_Error("delay : %s error!\n", delay_s_s);
		return -1;
	}

	//loopback
	loopback = atoi(loopback_s);
	if (loopback != 0 && loopback != 1)
	{
		SW_CONFIG_Log_Error("loopback : %s error!\n", loopback_s);
		return -1;
	}

	port_peer[rx_port].init = 1;
	port_peer[rx_port].rx_port = (uint16_t)rx_port;
	port_peer[rx_port].tx_port = (uint16_t)tx_port;
	port_peer[rx_port].delay_s = (uint16_t)delay_s;
	port_peer[rx_port].loopback = (uint16_t)loopback;
	port_peer[rx_port].rx_core = (uint16_t)rx_core;
	port_peer[rx_port].tx_core_num = (uint16_t)tx_core_num;
	for (i = 0; i < tx_core_num; i++)
		port_peer[rx_port].tx_core_map[i] = (uint16_t)tx_core_map[i];

	//Conf Info
	SW_CONFIG_Log_Info("RX Port %u ==> RX Port  %u\n", rx_port, port_peer[rx_port].rx_port);
	SW_CONFIG_Log_Info("RX Port %u ==> TX Port  %u\n", rx_port, port_peer[rx_port].tx_port);
	SW_CONFIG_Log_Info("RX Port %u ==> Delay T  %u\n", rx_port, port_peer[rx_port].delay_s);
	SW_CONFIG_Log_Info("RX Port %u ==> LoopBack %u\n", rx_port, port_peer[rx_port].loopback);
	SW_CONFIG_Log_Info("RX Port %u ==> RX Core  %u\n", rx_port, port_peer[rx_port].rx_core);
	SW_CONFIG_Log_Info("RX Port %u ==> TX Num   %u\n", rx_port, port_peer[rx_port].tx_core_num);
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

static int sw_fw_rules_parse(char* oneline, SW_PORT_PEER_FWD_RULES* port_peer)
{//rx_port,len_filter_length,len_filter_mode,max_len_filter_length,max_len_filter_mode,syn_filter_mode,acl_filter_mode,offset_filter_mode,ipv6_filter_mode,vlan_offload_mode,mpls_offload_mode
	int ret;
	int rx_port = 0;
	int len_filter_length = 0;
	int len_filter_mode = 0;
    int max_len_filter_length = 0;
    int max_len_filter_mode = 0;
	int syn_filter_mode = 0;
	int acl_filter_mode = 0; 
	int offset_filter_mode = 0;
    int ipv6_filter_mode = 0; 
    int vlan_offload_mode = 0;
    int mpls_offload_mode = 0;

	char rx_port_s[16] = {0};
	char len_filter_length_s[16] = {0};
	char len_filter_mode_s[16] = {0};
    char max_len_filter_length_s[16] = {0};
	char max_len_filter_mode_s[16] = {0};
	char syn_filter_mode_s[16] = {0};
	char acl_filter_mode_s[32] = {0};
	char offset_filter_mode_s[16] = {0};
    char ipv6_filter_mode_s[16] = {0}; 
    char vlan_offload_mode_s[16] = {0};
    char mpls_offload_mode_s[16] = {0};

	if (11 != (ret = sscanf(oneline, "%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^\n]", 
				rx_port_s,len_filter_length_s,len_filter_mode_s,max_len_filter_length_s,max_len_filter_mode_s,
				syn_filter_mode_s,acl_filter_mode_s, 
				offset_filter_mode_s, ipv6_filter_mode_s, vlan_offload_mode_s, mpls_offload_mode_s)))
	{
		SW_CONFIG_Log_Error("[sw_fw_rules_parse] sscanf error,ret:%d, %s-%s-%s-%s-%s-%s-%s-%s-%s-%s \n", ret,
				rx_port_s,len_filter_length_s,len_filter_mode_s,max_len_filter_length_s, max_len_filter_mode_s, 
				syn_filter_mode_s,acl_filter_mode_s, 
				offset_filter_mode_s, ipv6_filter_mode_s, vlan_offload_mode_s, mpls_offload_mode_s);
		return -1;
	}

	SW_CONFIG_Log_Info("[sw_fw_rules_parse] sscanf ok,ret:%d, %s-%s-%s-%s-%s-%s-%s-%s-%s-%s \n", ret,
				rx_port_s,len_filter_length_s,len_filter_mode_s,max_len_filter_length_s, max_len_filter_mode_s,
				syn_filter_mode_s,acl_filter_mode_s, 
				offset_filter_mode_s, ipv6_filter_mode_s, vlan_offload_mode_s, mpls_offload_mode_s);
	
	//rx_port
	rx_port = atoi(rx_port_s);
	if (rx_port >= SW_DPDK_MAX_PORT || 0 > rx_port)
	{
		SW_CONFIG_Log_Error("rx port : %s error!\n", rx_port_s);
		return -1;
	}

	//len_filter_length
	len_filter_length = atoi(len_filter_length_s);
	if (len_filter_length < SW_DPDK_PKT_LEN_MIN || SW_DPDK_PKT_LEN_MAX < len_filter_length)
	{
		SW_CONFIG_Log_Error("len_filter_length : %s value error!\n", len_filter_length_s);
		return -1;
	}

	//len_filter_mode
	len_filter_mode = atoi(len_filter_mode_s);
	if (SW_FILTER_LEN_DISABLE > len_filter_mode && SW_FILTER_LEN_DROP < len_filter_mode)
	{
		SW_CONFIG_Log_Error("len_filter_mode : %s error!\n", len_filter_mode_s);
		return -1;
	}

    //max_len_filter_length
	max_len_filter_length = atoi(max_len_filter_length_s);
	if (max_len_filter_length < SW_DPDK_PKT_LEN_MIN || SW_DPDK_PKT_LEN_MAX < max_len_filter_length)
	{
		SW_CONFIG_Log_Error("max_len_filter_length : %s value error!\n", max_len_filter_length_s);
		return -1;
	}

	//max_len_filter_mode
	max_len_filter_mode = atoi(max_len_filter_mode_s);
	if (SW_FILTER_MAX_LEN_DISABLE > max_len_filter_mode && SW_FILTER_MAX_LEN_DROP < max_len_filter_mode)
	{
		SW_CONFIG_Log_Error("max_len_filter_mode : %s error!\n", max_len_filter_mode_s);
		return -1;
	}

    if ((SW_FILTER_LEN_DISABLE != len_filter_mode) && (SW_FILTER_MAX_LEN_DISABLE != max_len_filter_mode))
    {
        if (max_len_filter_length <= len_filter_length)
        {
            SW_CONFIG_Log_Error("max_len_filter_mode and len_filter_mode all enable, but max_len_filter_length:%d less than len_filter_length:%d !\n", 
                                max_len_filter_length, len_filter_length);
		    return -1;
        }
    }

	//syn_filter_mode
	syn_filter_mode = atoi(syn_filter_mode_s);
	if (SW_FILTER_SYN_DISABLE > syn_filter_mode && SW_FILTER_SYN_DROP < syn_filter_mode)
	{
		SW_CONFIG_Log_Error("syn_filter_mode : %s error!\n", syn_filter_mode_s);
		return -1;
	}

	//acl_filter_mode
	acl_filter_mode = atoi(acl_filter_mode_s);
	if (SW_FILTER_ACL_DISABLE > acl_filter_mode && SW_FILTER_ACL_DROP < acl_filter_mode)
	{
		SW_CONFIG_Log_Error("acl_filter_mode : %s error!\n", acl_filter_mode_s);
		return -1;
	}

	//offset_filter_mode
	offset_filter_mode = atoi(offset_filter_mode_s);
	if (SW_FILTER_OFF_DISABLE > offset_filter_mode && SW_FILTER_OFF_DROP < offset_filter_mode)
	{
		SW_CONFIG_Log_Error("offset_filter_mode : %s error!\n", offset_filter_mode_s);
		return -1;
	}

    //ipv6_filter_mode
    ipv6_filter_mode = atoi(ipv6_filter_mode_s);
    if (SW_FILTER_IP6_DISABLE > ipv6_filter_mode && SW_FILTER_IP6_DROP < ipv6_filter_mode)
	{
		SW_CONFIG_Log_Error("ipv6_filter_mode : %s error!\n", ipv6_filter_mode_s);
		return -1;
	} 

    //vlan_offload_mode
    vlan_offload_mode = atoi(vlan_offload_mode_s);
    if (SW_FILTER_VLANOFF_DISABLE > vlan_offload_mode && SW_FILTER_VLANOFF_ENABLE < vlan_offload_mode)
	{
		SW_CONFIG_Log_Error("vlan_offload_mode : %s error!\n", vlan_offload_mode_s);
		return -1;
	} 

    //mpls_offload_mode
    mpls_offload_mode = atoi(mpls_offload_mode_s);
    if (SW_FILTER_MPLSOFF_DISABLE > mpls_offload_mode && SW_FILTER_MPLSOFF_ENABLE < mpls_offload_mode)
	{
		SW_CONFIG_Log_Error("mpls_offload_mode : %s error!\n", mpls_offload_mode);
		return -1;
	} 

	port_peer[rx_port].init    = 1;
	port_peer[rx_port].len_filter_len = (uint16_t)len_filter_length;
	port_peer[rx_port].len_filter_mode = (uint16_t)len_filter_mode;
    port_peer[rx_port].max_len_filter_len = (uint16_t)max_len_filter_length;
	port_peer[rx_port].max_len_filter_mode = (uint16_t)max_len_filter_mode;
	port_peer[rx_port].syn_filter_mode = (uint16_t)syn_filter_mode;
	port_peer[rx_port].acl_filter_mode = (uint16_t)acl_filter_mode;
	port_peer[rx_port].offset_filter_mode = (uint16_t)offset_filter_mode;
    port_peer[rx_port].ipv6_filter_mode = (uint16_t)ipv6_filter_mode;
    port_peer[rx_port].vlan_offload_mode = (uint16_t)vlan_offload_mode;
    port_peer[rx_port].mpls_offload_mode = (uint16_t)mpls_offload_mode;

	//Conf Info
	SW_CONFIG_Log_Info("RX Port %u ==> LenFT    Len  %u\n", rx_port, port_peer[rx_port].len_filter_len);
	SW_CONFIG_Log_Info("RX Port %u ==> LenFT         %u\n", rx_port, port_peer[rx_port].len_filter_mode);
    SW_CONFIG_Log_Info("RX Port %u ==> MaxLenFT Len  %u\n", rx_port, port_peer[rx_port].max_len_filter_len);
	SW_CONFIG_Log_Info("RX Port %u ==> MaxLenFT      %u\n", rx_port, port_peer[rx_port].max_len_filter_mode);
	SW_CONFIG_Log_Info("RX Port %u ==> SynFT         %u\n", rx_port, port_peer[rx_port].syn_filter_mode);
	SW_CONFIG_Log_Info("RX Port %u ==> AclFT         %u\n", rx_port, port_peer[rx_port].acl_filter_mode);
	SW_CONFIG_Log_Info("RX Port %u ==> OffFT         %u\n", rx_port, port_peer[rx_port].offset_filter_mode);
    SW_CONFIG_Log_Info("RX Port %u ==> Ip6FT         %u\n", rx_port, port_peer[rx_port].ipv6_filter_mode);	
    SW_CONFIG_Log_Info("RX Port %u ==> VlanM         %u\n", rx_port, port_peer[rx_port].vlan_offload_mode);
    SW_CONFIG_Log_Info("RX Port %u ==> MplsM         %u\n", rx_port, port_peer[rx_port].vlan_offload_mode);
    
	return 0;
}

int sw_fwd_rules_init(char* conf_path, void* port_peer_conf)
{
	if (NULL == conf_path)
		return -1;

	SW_PORT_PEER_FWD_RULES * port_peer = (SW_PORT_PEER_FWD_RULES *)port_peer_conf;
	FILE* fp = fopen(conf_path, "r");
	if (NULL == fp)
		return -1;
	
	char oneline[256] = {0};
	while(fgets(oneline, sizeof(oneline), fp) != NULL )
	{
		if (oneline[0] == '#' || oneline[0] == '\r' || oneline[0] == '\n')
			continue;

		printf("Parse:%s\n", oneline);
		if (0 > sw_fw_rules_parse(oneline, port_peer))
		{
			printf("Conf -- %s -- Error !\n", oneline);
			fclose(fp);
			return -1;
		}
	}

	fclose(fp);
	return 0;
}


