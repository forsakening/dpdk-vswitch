#ifndef _SW_DPDK_H_
#define _SW_DPDK_H_

#define SW_DPDK_MAX_CORE 64
#define SW_DPDK_MAX_PORT 24
#define SW_DPDK_MAX_DELAY 10
#define SW_DPDK_MAX_MBUF_NUM 8192 //每秒需要的报文数目
#define SW_DPDK_MAX_TX_NUM 3
#define SW_DPDK_Log_Error(fmt,...) printf("\033[0;32;31m[SWDPDK ERROR] \033[m"fmt, ##__VA_ARGS__);
#define SW_DPDK_Log_Info(fmt,...) printf("\033[0;32;32m[SWDPDK INFO] \033[m"fmt, ##__VA_ARGS__);
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

typedef struct
{
	unsigned short init;
	unsigned short rx_port;
	unsigned short tx_port;
	unsigned short delay_s; //delay time, seconds 
	unsigned short rx_core; //only support 1 core 
	unsigned short tx_core_num;
	unsigned short tx_core_map[SW_DPDK_MAX_TX_NUM];
	void*          rx_mempool;
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
			void*          tx_ring[SW_DPDK_MAX_TX_NUM]; //根据hashid 分发至各个tx_ring
		}rx_mode_conf;

		struct
		{
			unsigned short tx_port;
			unsigned short tx_queid; //tx port的queid
			void*          tx_ring;  //从该ring中收到报文并进行解析过滤,然后发送至上述的tx_queid
		}tx_mode_conf;
	};
}SW_CORE_CONF;

int sw_dpdk_init(char *);

#endif