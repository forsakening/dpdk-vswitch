#ifndef _SW_DPDK_H_
#define _SW_DPDK_H_

#include <inttypes.h>

#define SW_DPDK_MAX_CORE 128
#define SW_DPDK_MAX_PORT 24
#define SW_DPDK_MAX_DELAY 20
#define SW_DPDK_MAX_MBUF_NUM 6000000 //ÿ����Ҫ�ı�����Ŀ
#define SW_DPDK_MAX_TX_NUM 10
#define SW_DPDK_Log_Error(fmt,...) printf("\033[0;32;31m[SWDPDK ERROR] \033[m"fmt, ##__VA_ARGS__);
#define SW_DPDK_Log_Info(fmt,...) printf("\033[0;32;32m[SWDPDK INFO] \033[m"fmt, ##__VA_ARGS__);

//#define SW_DPDK_MBUF_LEN 1664  // % 128 == 0 split header issue
#define SW_DPDK_MBUF_LEN 2048


#ifdef DEBUG_LOG
    #define SW_DPDK_Log_Debug(fmt,...) printf("\033[0;32;32m[SWDPDK DBG] \033[m"fmt, ##__VA_ARGS__);
#else
    #define SW_DPDK_Log_Debug(fmt,...)
#endif

#define SW_DPDK_DEFAULT_LEN_FILTER 68
#define SW_DPDK_PKT_LEN_MIN 60
#define SW_DPDK_PKT_LEN_MAX 1508

#define SW_DPDK_FWD_RULES_PATH "/home/vswitch/conf/fwd_rules.conf"

#define SW_DPDK_DROP_PORT 0xffff

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
	SW_FILTER_LEN_DROP    = 3,

    SW_FILTER_MAX_LEN_DISABLE = 0,
	SW_FILTER_MAX_LEN_RXPORT  = 1,
	SW_FILTER_MAX_LEN_TXPORT  = 2,
	SW_FILTER_MAX_LEN_DROP    = 3,

	SW_FILTER_SYN_DISABLE = 0,
	SW_FILTER_SYN_RXPORT  = 1,
	SW_FILTER_SYN_TXPORT  = 2,
	SW_FILTER_SYN_DROP    = 3,

	SW_FILTER_ACL_DISABLE = 0,
	SW_FILTER_ACL_RXPORT  = 1,
	SW_FILTER_ACL_TXPORT  = 2,
	SW_FILTER_ACL_DROP    = 3,
	SW_FILTER_ACL_DELAY   = 4,

	SW_FILTER_OFF_DISABLE = 0,
	SW_FILTER_OFF_RXPORT  = 1,
	SW_FILTER_OFF_TXPORT  = 2,
	SW_FILTER_OFF_DROP    = 3,
	SW_FILTER_OFF_DELAY   = 4,

    SW_FILTER_IP6_DISABLE = 0,
	SW_FILTER_IP6_RXPORT  = 1,
	SW_FILTER_IP6_TXPORT  = 2,
	SW_FILTER_IP6_DROP    = 3,

    SW_FILTER_VLANOFF_DISABLE = 0,
    SW_FILTER_VLANOFF_ENABLE  = 1,

    SW_FILTER_MPLSOFF_DISABLE = 0,
    SW_FILTER_MPLSOFF_ENABLE  = 1,
};

typedef struct
{
	unsigned short init;
	
	//tx rules 
	unsigned short len_filter_len;      //pkts shorter than this len, will do the len_filter_mode
	unsigned short len_filter_mode;
    unsigned short max_len_filter_len;  //pkts longer than this len, will do the max_len_filter_mode
	unsigned short max_len_filter_mode; //like len_filter_mode
	unsigned short syn_filter_mode;
	unsigned short acl_filter_mode;
	unsigned short offset_filter_mode;
    unsigned short ipv6_filter_mode;
    unsigned short vlan_offload_mode;
    unsigned short mpls_offload_mode;
}SW_PORT_PEER_FWD_RULES;

typedef struct
{
	unsigned short init;
	unsigned short rx_port;
	unsigned short tx_port;
	unsigned short delay_s; //delay time, seconds 
	unsigned short loopback;//�ػ���־
	unsigned short rx_core; //only support 1 core 
	unsigned short tx_core_num;
	unsigned short tx_core_map[SW_DPDK_MAX_TX_NUM];
	void*          rx_mempool;
#if 0
    void*          txport_rx_mempool; //��ʹ���հ���,�е�����Ҳ��Ҫ����rx����
#endif
	void*          cache_ring[SW_DPDK_MAX_TX_NUM];
	void*          tx_ring[SW_DPDK_MAX_TX_NUM]; //one tx core with on tx ring	
}SW_PORT_PEER;

typedef struct
{
	SW_CORE_MODE core_mode;
	int			 threadId;
	union
	{
		struct
		{
			unsigned short rx_port;
			unsigned short tx_num;
			void*          cache_ring[SW_DPDK_MAX_TX_NUM]; //����hashid �ַ�������cache_ring
			//void*          tx_ring[SW_DPDK_MAX_TX_NUM]; //����hashid �ַ�������tx_ring
		}rx_mode_conf;

		struct
		{
			unsigned short tx_port;
			unsigned short tx_queid; //tx port��queid
			void*          cache_ring;
			void*          tx_ring;  //�Ӹ�ring���յ����Ĳ����н�������,Ȼ������������tx_queid
		}tx_mode_conf;
	};
}SW_CORE_CONF;

uint32_t sw_dpdk_enabled_rx_port_mask(void);

uint32_t sw_dpdk_enabled_port_mask(void);

uint16_t sw_dpdk_port_tx_num(uint16_t rx_port);
	
int sw_dpdk_get_port_socket(uint16_t port_id);

int sw_dpdk_start(void);

int sw_dpdk_init(char *, uint32_t);

uint32_t sw_dpdk_dynamic_set_fwd(uint16_t portid,
	                      uint16_t delay_s,
	                      uint16_t loopback,
	                      uint16_t filter_len,
	                      uint16_t len_mode,
	                      uint16_t syn_mode,
	                      uint16_t acl_mode,
	                      uint16_t off_mode,
						  uint16_t ipv6_mode,
					      char* err, int err_len);

#ifdef __cplusplus
extern "C" {
#endif

//for http rest api use
typedef struct
{
	uint32_t portid;
	uint32_t running_sec;
	uint32_t mode;
	uint32_t peer_port;

	uint64_t tx;
	uint64_t rx;
	uint64_t rx_bytes;
	uint64_t tx_bytes;
	uint64_t rx_pps;				//�հ�pps���ɹ��İ�
	uint64_t tx_pps;				//����pps
	uint64_t rx_bps;				//�հ�bps,�ɹ��İ�
	uint64_t tx_bps;				//����bps
	//uint64_t rx_pps_total;			//�յ������а����������󱨵�pps
	//uint64_t rx_pps_total_average;	//ƽ��ֵ
	//uint64_t tx_pps_total;			//���͵����а�

	uint64_t filter_len;
    uint64_t filter_max_len;
	uint64_t filter_acl;
	uint64_t filter_offset;
	uint64_t filter_syn;
    uint64_t filter_ipv6;

	//cache - stat
	uint64_t vlan_pkts;
	uint64_t mpls_pkts;
	uint64_t ipv4_pkts;
	uint64_t ipv6_pkts;
	uint64_t icmp_pkts;
	uint64_t tcp_pkts;
	uint64_t udp_pkts;

	//pkts distribute
	uint64_t len_less_128;
	uint64_t len_128_256;
	uint64_t len_256_512;
	uint64_t len_512_1024;
	uint64_t len_more_1024;
}SW_DPDK_HTTP_PORT_INFO;
typedef struct {
	uint32_t portid;
	uint32_t mode;
}SW_DPDK_HTTP_PORT_SIMPLE_INFO;
typedef struct {
	SW_DPDK_HTTP_PORT_SIMPLE_INFO infos[32];
	int numofinfos;
}SW_DPDK_HTTP_ALL_PORT_INFO;
uint32_t sw_dpdk_http_show_all_port(SW_DPDK_HTTP_ALL_PORT_INFO* port_info, char* buf, int buf_len);

uint32_t sw_dpdk_http_show_port(uint32_t portid, SW_DPDK_HTTP_PORT_INFO* port_info, char* buf, int buf_len);

typedef struct
{
	uint32_t portid;
	uint16_t delay_s;
	uint16_t loopback;
	uint16_t filter_len;
	uint16_t len_mode;
    uint16_t filter_max_len;
	uint16_t max_len_mode;
	uint16_t syn_mode;
	uint16_t acl_mode;
	uint16_t off_mode;
	uint16_t ipv6_mode;
	uint16_t vlan_mode;
	uint16_t mpls_mode;
}SW_DPDK_HTTP_FWD_INFO;

uint32_t sw_dpdk_http_show_fwd(uint32_t portid, SW_DPDK_HTTP_FWD_INFO* fwd_info, char* buf, int buf_len);

uint32_t sw_dpdk_http_set_fwd(uint32_t portid, SW_DPDK_HTTP_FWD_INFO* fwd_info, char* buf, int buf_len);


#ifdef __cplusplus
}
#endif

#endif
