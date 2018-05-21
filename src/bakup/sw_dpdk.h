#ifndef _SW_DPDK_H_
#define _SW_DPDK_H_

#include <inttypes.h>

#define SW_DPDK_MAX_CORE 128
#define SW_DPDK_MAX_PORT 24
#define SW_DPDK_MAX_DELAY 20
#define SW_DPDK_MAX_MBUF_NUM 3000000 //每秒需要的报文数目
#define SW_DPDK_MAX_TX_NUM 6
#define SW_DPDK_Log_Error(fmt,...) printf("\033[0;32;31m[SWDPDK ERROR] \033[m"fmt, ##__VA_ARGS__);
#define SW_DPDK_Log_Info(fmt,...) printf("\033[0;32;32m[SWDPDK INFO] \033[m"fmt, ##__VA_ARGS__);

#define SW_DPDK_DEFAULT_LEN_FILTER 68
#define SW_DPDK_PKT_LEN_MIN 60
#define SW_DPDK_PKT_LEN_MAX 1508

#define SW_DPDK_FWD_RULES_PATH "../conf/fwd_rules.conf"

//mode of cpu-core
typedef enum
{
	SW_CORE_RX = 1,  // only rx packets, just pmd the nic
	SW_CORE_TX,      // do parse and filter mbuf, and send the mbuf
}SW_CORE_MODE;

typedef enum
{
	SW_PORT_RX = 0,
	SW_PORT_TX,
}SW_PORT_MODE;

enum
{
	SW_FILTER_LEN_DISABLE = 0,
	SW_FILTER_LEN_RXPORT  = 1,
	SW_FILTER_LEN_TXPORT  = 2,

	SW_FILTER_SYN_DISABLE = 0,
	SW_FILTER_SYN_RXPORT  = 1,
	SW_FILTER_SYN_TXPORT  = 2,

	SW_FILTER_ACL_DISABLE = 0,
	SW_FILTER_ACL_RXPORT  = 1,
	SW_FILTER_ACL_TXPORT  = 2,

	SW_FILTER_OFF_DISABLE = 0,
	SW_FILTER_OFF_RXPORT  = 1,
	SW_FILTER_OFF_TXPORT  = 2,
};

typedef struct
{
	unsigned short init;
	
	//tx rules 
	unsigned short len_filter_len;
	unsigned short len_filter_mode;
	unsigned short syn_filter_mode;
	unsigned short acl_filter_mode;
	unsigned short offset_filter_mode;
}SW_PORT_PEER_FWD_RULES;

typedef struct
{
	unsigned short init;
	unsigned short rx_port;
	unsigned short tx_port;
	unsigned short delay_s; //delay time, seconds 
	unsigned short loopback;//回环标志
	unsigned short rx_core; //only support 1 core 
	unsigned short tx_core_num;
	unsigned short tx_core_map[SW_DPDK_MAX_TX_NUM];
	void*          rx_mempool;
	void*          cache_ring[SW_DPDK_MAX_TX_NUM];
	void*          tx_ring[SW_DPDK_MAX_TX_NUM]; //one tx core with on tx ring	
}SW_PORT_PEER;

typedef struct
{
	SW_CORE_MODE core_mode;
	union
	{
		struct
		{
			unsigned short rx_port;
			unsigned short tx_num;
			void*          cache_ring[SW_DPDK_MAX_TX_NUM]; //根据hashid 分发至各个cache_ring
			//void*          tx_ring[SW_DPDK_MAX_TX_NUM]; //根据hashid 分发至各个tx_ring
		}rx_mode_conf;

		struct
		{
			unsigned short tx_port;
			unsigned short tx_queid; //tx port的queid
			void*          cache_ring;
			void*          tx_ring;  //从该ring中收到报文并进行解析过滤,然后发送至上述的tx_queid
		}tx_mode_conf;
	};
}SW_CORE_CONF;

uint32_t sw_dpdk_enabled_rx_port_mask(void);

uint32_t sw_dpdk_enabled_port_mask(void);

uint16_t sw_dpdk_port_tx_num(uint16_t rx_port);
	
int sw_dpdk_get_port_socket(uint16_t port_id);

int sw_dpdk_start(void);

int sw_dpdk_init(char *, uint32_t);

#endif