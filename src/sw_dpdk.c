//@20180408 by Shawn.Z v1.0 just for test 2 ports
//@20180411 by Shawn.Z v1.1 support configuration
//@20180413 by Shawn.Z v1.2 support packet parse
//@20180414 by Shawn.Z v1.3 support tuple filter
//@20180516 by Shawn.Z v1.4 support offset filter
//@20180605 by Shawn.Z v1.5 support http rest api
#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

//private 
#include "sw_dpdk.h"
#include "sw_command.h"
#include "sw_config.h"
#include "sw_parse.h"
#include "sw_filter.h"
#include "sw_offset.h"

//#define SW_DPDK_DEBUG 1

#define RTE_LOGTYPE_VSWITCH RTE_LOGTYPE_USER1

#define SW_DPDK_MBUF_TOTAL (SW_DPDK_MBUF_LEN + RTE_PKTMBUF_HEADROOM)

static volatile bool force_quit = false;
static volatile bool sw_dpdk_eal_init = false;

#define MAX_PKT_BURST 32
#define MEMPOOL_CACHE_SIZE 256

#define SW_BURST_TX_DRAIN_US 100 // us 

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 4096
#define RTE_TEST_TX_DESC_DEFAULT 2048
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/* ethernet addresses of ports */
static struct ether_addr sw_ports_eth_addr[SW_DPDK_MAX_PORT];
static uint32_t sw_enabled_port_mask = 0;
static volatile bool start_work = false;
static uint32_t sw_port_delay_init[SW_DPDK_MAX_PORT] = {0};

static uint32_t sw_port_need_update_rx[SW_DPDK_MAX_PORT] = {0};//以rx port作为索引
static uint32_t sw_port_need_update_tx[SW_DPDK_MAX_PORT][SW_DPDK_MAX_TX_NUM] = {{0}};//以tx port作为索引

static SW_PORT_PEER sw_port_peer[SW_DPDK_MAX_PORT] = {{0}}; // use rx port as the array id
static SW_PORT_PEER_FWD_RULES sw_port_peer_fwd_rules[SW_DPDK_MAX_PORT] = {{0}}; // use rx port as the array id
static uint64_t sw_used_core_mask_low = 1; // core 0 is used default  0 ~ 63
static uint64_t sw_used_core_mask_high = 0;// 64 ~ 127
static uint32_t sw_used_port_mask = 0;
static uint32_t sw_used_rx_port_mask = 0;
static uint16_t sw_dpdk_total_port = 0;
static SW_PORT_MODE sw_port_mode_map[SW_DPDK_MAX_PORT] = {0};
static SW_CORE_CONF sw_core_conf[SW_DPDK_MAX_CORE] = {{0}};
static uint32_t sw_dpdk_pps = SW_DPDK_MAX_MBUF_NUM;
static uint32_t sw_running_seconds = 0;

static uint32_t sw_idle_que_id[SW_DPDK_MAX_PORT] = {0};

//用于加速
static uint16_t sw_len_filter_tx_port[SW_DPDK_MAX_PORT] = {0};
static uint16_t sw_max_len_filter_tx_port[SW_DPDK_MAX_PORT] = {0};
static uint16_t sw_syn_filter_tx_port[SW_DPDK_MAX_PORT] = {0};
static uint16_t sw_acl_filter_tx_port[SW_DPDK_MAX_PORT] = {0};
static uint16_t sw_offset_filter_tx_port[SW_DPDK_MAX_PORT] = {0};
static uint16_t sw_ip6_filter_tx_port[SW_DPDK_MAX_PORT] = {0};
extern FILE *runlogF;

//更新配置读写锁，只有在更新配置的一瞬间会产生竞争，其余不会导致竞争
pthread_rwlock_t sw_config_rwlock[SW_DPDK_MAX_PORT];

static struct rte_eth_conf sw_nic_conf = {
	.rxmode = {
		.mq_mode = ETH_MQ_RX_RSS,
		.max_rx_pkt_len = ETHER_MAX_LEN,
		.split_hdr_size = 0,
		.ignore_offload_bitfield = 1,
		.offloads = (DEV_RX_OFFLOAD_CRC_STRIP |
			     DEV_RX_OFFLOAD_CHECKSUM),
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = ETH_RSS_TCP|ETH_RSS_UDP,
		},
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

struct sw_dpdk_port_sw_stat{
	//rx
	uint64_t drop_by_no_ring[SW_DPDK_MAX_TX_NUM];
	uint64_t enque_ring[SW_DPDK_MAX_TX_NUM];

	//cache
	uint64_t drop_by_parsed[SW_DPDK_MAX_TX_NUM];
    uint64_t drop_by_parsed_eth[SW_DPDK_MAX_TX_NUM];
    uint64_t drop_by_parsed_net[SW_DPDK_MAX_TX_NUM];
    uint64_t drop_by_parsed_trans[SW_DPDK_MAX_TX_NUM];
    
	uint64_t deque_cache_ring[SW_DPDK_MAX_TX_NUM];
	uint64_t enque_tx_ring[SW_DPDK_MAX_TX_NUM];
	uint64_t filter_len[SW_DPDK_MAX_TX_NUM];
    uint64_t filter_max_len[SW_DPDK_MAX_TX_NUM];
	uint64_t filter_acl[SW_DPDK_MAX_TX_NUM];
	uint64_t filter_offset[SW_DPDK_MAX_TX_NUM];
	uint64_t filter_syn[SW_DPDK_MAX_TX_NUM];
    uint64_t filter_ipv6[SW_DPDK_MAX_TX_NUM];
    uint64_t filter_vlan_off[SW_DPDK_MAX_TX_NUM];
    uint64_t filter_mpls_off_v4[SW_DPDK_MAX_TX_NUM];
    uint64_t filter_mpls_off_v6[SW_DPDK_MAX_TX_NUM];

	//cache - stat
	uint64_t vlan_pkts[SW_DPDK_MAX_TX_NUM];
	uint64_t mpls_pkts[SW_DPDK_MAX_TX_NUM];
	uint64_t ipv4_pkts[SW_DPDK_MAX_TX_NUM];
    uint64_t ipv6_pkts[SW_DPDK_MAX_TX_NUM];
	uint64_t icmp_pkts[SW_DPDK_MAX_TX_NUM];
	uint64_t tcp_pkts[SW_DPDK_MAX_TX_NUM];
	uint64_t udp_pkts[SW_DPDK_MAX_TX_NUM];

	//pkts distribute
	uint64_t len_less_128[SW_DPDK_MAX_TX_NUM];
	uint64_t len_128_256[SW_DPDK_MAX_TX_NUM];
	uint64_t len_256_512[SW_DPDK_MAX_TX_NUM];
	uint64_t len_512_1024[SW_DPDK_MAX_TX_NUM];
	uint64_t len_more_1024[SW_DPDK_MAX_TX_NUM];
	
	//tx -stat
	uint64_t deque_tx_ring[SW_DPDK_MAX_TX_NUM];
    uint64_t deque_tx_interface[SW_DPDK_MAX_TX_NUM];
} __rte_cache_aligned;
struct sw_dpdk_port_sw_stat port_sw_stat[SW_DPDK_MAX_PORT];

struct sw_dpdk_port_hw_stat{
	uint64_t tx;
	uint64_t rx;
	uint64_t dropped;
	uint64_t rx_pps;				//收包pps，成功的包
	uint64_t tx_pps;				//发包pps
	uint64_t rx_bps;				//收包bps,成功的包
	uint64_t tx_bps;				//发包bps
	uint64_t rx_pps_total;			//收到的所有包，包括错误报的pps
	uint64_t rx_pps_total_average;	//平均值
	uint64_t tx_pps_total;			//发送的所有包
} __rte_cache_aligned;
struct sw_dpdk_port_hw_stat port_hw_stat[SW_DPDK_MAX_PORT] = {{0}};

static struct rte_eth_dev_tx_buffer *sw_tx_buffer[SW_DPDK_MAX_PORT][SW_DPDK_MAX_TX_NUM] = {{0}};

struct sw_tx_buffer_para
{
	uint16_t port_id;
	uint16_t que_id;
};
struct sw_tx_buffer_para sw_tx_buffer_p_q[SW_DPDK_MAX_PORT][SW_DPDK_MAX_TX_NUM] = {{{0}}};

static void sw_dpdk_config_rwlock_init(void)
{
    int i = 0;
    for (; i < SW_DPDK_MAX_PORT; i++)
    {
        pthread_rwlock_init(&sw_config_rwlock[i], NULL);
    }
}
    
uint32_t sw_dpdk_enabled_rx_port_mask(void)
{
	return sw_used_rx_port_mask;
}

uint32_t sw_dpdk_enabled_port_mask(void)
{
	return sw_enabled_port_mask;
}

uint16_t sw_dpdk_port_tx_num(uint16_t rx_port)
{
	if ((sw_used_rx_port_mask & (1 << rx_port)) == 0)
		return 0;
	
	return sw_port_peer[rx_port].tx_core_num;
}

int sw_dpdk_get_port_socket(uint16_t port_id)
{
	return rte_eth_dev_socket_id(port_id);
}

static int sw_dpdk_setup_port_peer(uint16_t rx_port,
											  uint16_t tx_port,
											  uint16_t delay_s,
											  uint16_t loopback,
											  uint16_t rx_core,
											  uint16_t tx_core_num,
											  uint16_t *tx_core_map)
{
	int i = 0;
	uint64_t sw_used_core_mask;
	if (tx_core_num > SW_DPDK_MAX_TX_NUM || 0 == tx_core_num)
	{
		SW_DPDK_Log_Error("tx_core_num error, %d \n", tx_core_num);
		return -1;
	}

	if ((sw_used_port_mask & (1 << rx_port)) != 0)
	{
		SW_DPDK_Log_Error("rx port : %u already used ! \n", rx_port);
		return -1;
	}

	if ((sw_used_port_mask & (1 << tx_port)) != 0)
	{
		SW_DPDK_Log_Error("tx port : %u already used ! \n", tx_port);
		return -1;
	}

	if (rx_core >= 64)
		sw_used_core_mask = sw_used_core_mask_high;
	else
		sw_used_core_mask = sw_used_core_mask_low;
	
	if ((sw_used_core_mask & ((uint64_t)1 << (rx_core % 64))) != 0)
	{
		SW_DPDK_Log_Error("rx core : %u already used ! \n", rx_core);
		return -1;
	}

	uint16_t tx_core;
	for (i = 0; i < tx_core_num; i++)
	{
		tx_core = tx_core_map[i];
		if (tx_core >= 64)
			sw_used_core_mask = sw_used_core_mask_high;
		else
			sw_used_core_mask = sw_used_core_mask_low;
		
		if ((sw_used_core_mask & ((uint64_t)1 << (tx_core % 64))) != 0)
		{
			SW_DPDK_Log_Error("tx core : %u already used ! \n", tx_core);
			return -1;
		}
	}
	
	sw_port_peer[rx_port].rx_port = rx_port;
	sw_port_peer[rx_port].tx_port = tx_port;
	sw_port_peer[rx_port].delay_s = delay_s;
	sw_port_peer[rx_port].loopback = loopback;
	sw_port_peer[rx_port].rx_core = rx_core;
	sw_port_peer[rx_port].tx_core_num = tx_core_num;
	for (i = 0; i < tx_core_num; i++)
		sw_port_peer[rx_port].tx_core_map[i] = tx_core_map[i];

	sw_used_port_mask |= (1 << rx_port);
	sw_used_port_mask |= (1 << tx_port);

	if (rx_core >= 64)
		sw_used_core_mask_high |= ((uint64_t)1 << (rx_core % 64));
	else
		sw_used_core_mask_low |= ((uint64_t)1 << (rx_core % 64));
	
	for (i = 0; i < tx_core_num; i++)
	{
		tx_core = tx_core_map[i];

		if (tx_core >= 64)
			sw_used_core_mask_high |= ((uint64_t)1 << (tx_core % 64));
		else
			sw_used_core_mask_low |= ((uint64_t)1 << (tx_core % 64));
	}

	sw_port_mode_map[rx_port] = SW_PORT_RX;
	sw_port_mode_map[tx_port] = SW_PORT_TX;

	//设置 core
	sw_core_conf[rx_core].core_mode = SW_CORE_RX;
	sw_core_conf[rx_core].rx_mode_conf.rx_port = rx_port;
	sw_core_conf[rx_core].rx_mode_conf.tx_num = tx_core_num;

	for (i = 0; i < tx_core_num; i++)
	{
		tx_core = tx_core_map[i];
		sw_core_conf[tx_core].core_mode = SW_CORE_TX;
		sw_core_conf[tx_core].tx_mode_conf.tx_port = tx_port;
	}
	
	sw_used_rx_port_mask |= (1 << rx_port);

	SW_DPDK_Log_Info("sw_dpdk_setup_port_peer RxPort:%u TxPort:%u LoopBack:%u Delay:%u RxCore:%u TxCoreNum:%u \n",
					rx_port, tx_port, loopback, delay_s, rx_core, tx_core_num);
	
	return 0;
}

static int sw_dpdk_make_fwd_rules(void)
{
	int i ;
	for (i = 0; i < SW_DPDK_MAX_PORT; i++)
	{
		if ((sw_used_rx_port_mask & (1 << i)) == 0)
			continue;
	
		if (sw_port_peer_fwd_rules[i].len_filter_mode == SW_FILTER_LEN_RXPORT)
			sw_len_filter_tx_port[i] = i;
		else if (sw_port_peer_fwd_rules[i].len_filter_mode == SW_FILTER_LEN_TXPORT)
			sw_len_filter_tx_port[i] = sw_port_peer[i].tx_port;
        else if (sw_port_peer_fwd_rules[i].len_filter_mode == SW_FILTER_LEN_DROP)
            sw_len_filter_tx_port[i] = SW_DPDK_DROP_PORT;

        if (sw_port_peer_fwd_rules[i].max_len_filter_mode == SW_FILTER_MAX_LEN_RXPORT)
			sw_max_len_filter_tx_port[i] = i;
		else if (sw_port_peer_fwd_rules[i].max_len_filter_mode == SW_FILTER_MAX_LEN_TXPORT)
			sw_max_len_filter_tx_port[i] = sw_port_peer[i].tx_port;
        else if (sw_port_peer_fwd_rules[i].max_len_filter_mode == SW_FILTER_MAX_LEN_DROP)
            sw_max_len_filter_tx_port[i] = SW_DPDK_DROP_PORT;
		
		if (sw_port_peer_fwd_rules[i].syn_filter_mode == SW_FILTER_SYN_RXPORT)
			sw_syn_filter_tx_port[i] = i;
		else if (sw_port_peer_fwd_rules[i].syn_filter_mode == SW_FILTER_SYN_TXPORT)
			sw_syn_filter_tx_port[i] = sw_port_peer[i].tx_port;
        else if (sw_port_peer_fwd_rules[i].syn_filter_mode == SW_FILTER_SYN_DROP)
            sw_syn_filter_tx_port[i] = SW_DPDK_DROP_PORT;

		if (sw_port_peer_fwd_rules[i].acl_filter_mode == SW_FILTER_ACL_RXPORT)
			sw_acl_filter_tx_port[i] = i;
		else if (sw_port_peer_fwd_rules[i].acl_filter_mode == SW_FILTER_ACL_TXPORT)
			sw_acl_filter_tx_port[i] = sw_port_peer[i].tx_port;
        else if (sw_port_peer_fwd_rules[i].acl_filter_mode == SW_FILTER_ACL_DROP)
			sw_acl_filter_tx_port[i] = SW_DPDK_DROP_PORT;

		if (sw_port_peer_fwd_rules[i].offset_filter_mode == SW_FILTER_OFF_RXPORT)
			sw_offset_filter_tx_port[i] = i;
		else if (sw_port_peer_fwd_rules[i].offset_filter_mode == SW_FILTER_OFF_TXPORT)
			sw_offset_filter_tx_port[i] = sw_port_peer[i].tx_port;
        else if (sw_port_peer_fwd_rules[i].offset_filter_mode == SW_FILTER_OFF_DROP)
			sw_offset_filter_tx_port[i] = SW_DPDK_DROP_PORT;

        if (sw_port_peer_fwd_rules[i].ipv6_filter_mode == SW_FILTER_IP6_RXPORT)
			sw_ip6_filter_tx_port[i] = i;
		else if (sw_port_peer_fwd_rules[i].ipv6_filter_mode == SW_FILTER_IP6_TXPORT)
			sw_ip6_filter_tx_port[i] = sw_port_peer[i].tx_port;
        else if (sw_port_peer_fwd_rules[i].ipv6_filter_mode == SW_FILTER_IP6_DROP)
			sw_ip6_filter_tx_port[i] = SW_DPDK_DROP_PORT;
        

		SW_DPDK_Log_Info("FWDRULE Port:%u-%u  len:%u maxlen:%u syn:%u  acl:%u off:%u ip6:%u \n", i, sw_port_peer[i].tx_port,
			             sw_len_filter_tx_port[i], sw_max_len_filter_tx_port[i], sw_syn_filter_tx_port[i], 
			             sw_acl_filter_tx_port[i], sw_offset_filter_tx_port[i],
			             sw_ip6_filter_tx_port[i]);
	}

	return 0;
}

static int sw_dpdk_init_fwd_rules(void)
{
	int i ;
	for (i = 0; i < SW_DPDK_MAX_PORT; i++)
	{
		sw_port_peer_fwd_rules[i].len_filter_len = SW_DPDK_DEFAULT_LEN_FILTER;
		sw_port_peer_fwd_rules[i].len_filter_mode = SW_FILTER_LEN_TXPORT;
        sw_port_peer_fwd_rules[i].max_len_filter_len = SW_DPDK_PKT_LEN_MAX;
		sw_port_peer_fwd_rules[i].max_len_filter_mode = SW_FILTER_MAX_LEN_DISABLE;
		sw_port_peer_fwd_rules[i].syn_filter_mode = SW_FILTER_SYN_TXPORT;
		sw_port_peer_fwd_rules[i].acl_filter_mode = SW_FILTER_ACL_TXPORT;
		sw_port_peer_fwd_rules[i].offset_filter_mode = SW_FILTER_OFF_TXPORT;
        sw_port_peer_fwd_rules[i].ipv6_filter_mode = SW_FILTER_IP6_TXPORT;
        sw_port_peer_fwd_rules[i].vlan_offload_mode = SW_FILTER_VLANOFF_DISABLE;
        sw_port_peer_fwd_rules[i].mpls_offload_mode = SW_FILTER_MPLSOFF_DISABLE;
	}

	return 0;
}

static int sw_dpdk_setup_fwd_rules(uint16_t rx_port, SW_PORT_PEER_FWD_RULES* fwd_rules)
{
	if (sw_port_peer_fwd_rules[rx_port].init)
	{
		SW_DPDK_Log_Error("[sw_dpdk_setup_fwd_rules] RxPort:%u already init !\n", rx_port);
		return -1;
	}

	if ((sw_used_rx_port_mask & (1 << rx_port)) == 0)
	{
		SW_DPDK_Log_Error("[sw_dpdk_setup_fwd_rules] RxPort:%u not enabled !\n", rx_port);
		return -1;
	}

	uint16_t loopback = sw_port_peer[rx_port].loopback;
	if (loopback)
	{
	    //若开启了环回模式，但仍然配置过滤规则发给rx口，则可能出现rx口超过线速的情况
		if (fwd_rules->len_filter_mode == SW_FILTER_LEN_RXPORT)
		{
			SW_DPDK_Log_Error("[sw_dpdk_setup_fwd_rules] RxPort:%u is loopback, len filter mode may not be 1 !\n", rx_port);
			return -1;
		}

        if (fwd_rules->max_len_filter_mode == SW_FILTER_MAX_LEN_RXPORT)
		{
			SW_DPDK_Log_Error("[sw_dpdk_setup_fwd_rules] RxPort:%u is loopback, max len filter mode may not be 1 !\n", rx_port);
			return -1;
		}

		if (fwd_rules->syn_filter_mode == SW_FILTER_SYN_RXPORT)
		{
			SW_DPDK_Log_Error("[sw_dpdk_setup_fwd_rules] RxPort:%u is loopback, syn filter mode may not be 1 !\n", rx_port);
			return -1;
		}

		if (fwd_rules->acl_filter_mode == SW_FILTER_ACL_RXPORT)
		{
			SW_DPDK_Log_Error("[sw_dpdk_setup_fwd_rules] RxPort:%u is loopback, acl filter mode may not be 1 !\n", rx_port);
			return -1;
		}

		if (fwd_rules->offset_filter_mode == SW_FILTER_OFF_RXPORT)
		{
			SW_DPDK_Log_Error("[sw_dpdk_setup_fwd_rules] RxPort:%u is loopback, offset filter mode may not be 1 !\n", rx_port);
			return -1;
		}

        if (fwd_rules->ipv6_filter_mode == SW_FILTER_IP6_RXPORT)
		{
			SW_DPDK_Log_Error("[sw_dpdk_setup_fwd_rules] RxPort:%u is loopback, ipv6 filter mode may not be 1 !\n", rx_port);
			return -1;
		}
	}

	uint16_t tx_port = sw_port_peer[rx_port].tx_port;
	memcpy(&sw_port_peer_fwd_rules[rx_port], fwd_rules, sizeof(SW_PORT_PEER_FWD_RULES));
	memcpy(&sw_port_peer_fwd_rules[tx_port], fwd_rules, sizeof(SW_PORT_PEER_FWD_RULES));

	SW_DPDK_Log_Info("sw_dpdk_setup_fwd_rules,RxPort:%u LoopBack:%u FilterLen:%u LenMode:%u MaxFilterLen:%u MaxLenMode:%u SynMode:%u AclMode:%u OffMode:%u Ip6Mode:%u VlanMode:%u MplsMode:%u\n",
		rx_port, sw_port_peer[rx_port].loopback, sw_port_peer_fwd_rules[rx_port].len_filter_len, sw_port_peer_fwd_rules[rx_port].len_filter_mode,
		sw_port_peer_fwd_rules[rx_port].max_len_filter_len, sw_port_peer_fwd_rules[rx_port].max_len_filter_mode,
		sw_port_peer_fwd_rules[rx_port].syn_filter_mode, sw_port_peer_fwd_rules[rx_port].acl_filter_mode, 
		sw_port_peer_fwd_rules[rx_port].offset_filter_mode,sw_port_peer_fwd_rules[rx_port].ipv6_filter_mode,
		sw_port_peer_fwd_rules[rx_port].vlan_offload_mode, sw_port_peer_fwd_rules[rx_port].mpls_offload_mode);

	return 0;
}

static void sw_dpdk_tx_buffer_callback(struct rte_mbuf **pkts_burst, uint16_t pkt_num, void *userdata)
{
	uint16_t port_id = ((struct sw_tx_buffer_para *)(userdata))->port_id;
	uint16_t queue_id = ((struct sw_tx_buffer_para *)(userdata))->que_id;

#ifdef SW_DPDK_DEBUG
	printf("4) port:%u-%u start to tx callbak,still have:%u pkts need to send \n", port_id, queue_id, pkt_num);
#endif

	//发送至网卡
    int nb_tx = 0;
	int pkt_leaved = pkt_num;
	do
    {
        //可能发送不成功，循环的进行发送
        nb_tx += rte_eth_tx_burst(port_id, queue_id, &pkts_burst[nb_tx], pkt_leaved);
        pkt_leaved = pkt_num - nb_tx;
        if (pkt_leaved <= 0)
            break;

	#ifdef SW_DPDK_DEBUG
		printf("      5) port:%u-%u loop tx callbak, %d pkts send ok,leave %u \n", port_id, queue_id, nb_tx, pkt_leaved);
		usleep(1000);
	#endif
	
    }while(pkt_leaved > 0);

#ifdef SW_DPDK_DEBUG
	printf("6) port:%u-%u start to tx callbak, %u pkts send ok \n", port_id, queue_id, pkt_num);
#endif

}

static int sw_dpdk_setup_buffer(uint16_t rx_port)
{
	if (sw_port_mode_map[rx_port] != SW_PORT_RX)
	{
		SW_DPDK_Log_Error("rx port : %u not configured right ! \n", rx_port);
		return -1;
	}

	if ((sw_used_port_mask & (1 << rx_port)) == 0)
	{
		SW_DPDK_Log_Error("rx port : %u not used now ! \n", rx_port);
		return -1;
	}

	uint16_t delay = sw_port_peer[rx_port].delay_s;
	int mbuf_num = delay * sw_dpdk_pps;
	if (0 == mbuf_num)
		mbuf_num = sw_dpdk_pps;

    int socket_id = rte_eth_dev_socket_id(rx_port);
	if (socket_id < 0)
		socket_id = SOCKET_ID_ANY;
    
	char mbuf_name[32] = {0};
	sprintf(mbuf_name, "mbuf_pool_%d_core_%d", rx_port, socket_id);    
	sw_port_peer[rx_port].rx_mempool = (void *)rte_pktmbuf_pool_create(mbuf_name, mbuf_num, MEMPOOL_CACHE_SIZE, 0, 
						SW_DPDK_MBUF_TOTAL, socket_id);
	if (NULL == sw_port_peer[rx_port].rx_mempool)
	{
		SW_DPDK_Log_Error("rx port : %u init mbuf error,mbuf num %d ! \n", rx_port, mbuf_num);
		return -1;
	}

#if 0
    char txport_rx_mbuf_name[32] = {0};
    sprintf(txport_rx_mbuf_name, "txport_%d_core_%d", rx_port, socket_id); 
    sw_port_peer[rx_port].txport_rx_mempool = (void *)rte_pktmbuf_pool_create(txport_rx_mbuf_name, 4096, MEMPOOL_CACHE_SIZE, 0, 
						SW_DPDK_MBUF_TOTAL, socket_id);
    if (NULL == sw_port_peer[rx_port].txport_rx_mempool)
    {
        SW_DPDK_Log_Error("rx port : %u init peer tx-port rx mbuf error,mbuf num %d ! \n", rx_port, txport_rx_mbuf_name);
		return -1;
    }
#endif

	uint16_t tx_core;
	uint16_t tx_port = sw_port_peer[rx_port].tx_port;
	uint16_t rx_core = sw_port_peer[rx_port].rx_core;
	uint16_t i;
	uint32_t ring_num = mbuf_num;
	ring_num = rte_align32pow2(ring_num + 1);
	for (i = 0; i < sw_port_peer[rx_port].tx_core_num; i++)
	{
		char ring_name[32] = {0};
		sprintf(ring_name, "tx_ring_port%02u_%u", sw_port_peer[rx_port].tx_port, i);
		sw_port_peer[rx_port].tx_ring[i] = rte_ring_create(ring_name, ring_num, socket_id, 0);
		if (NULL == sw_port_peer[rx_port].tx_ring[i])
		{
			SW_DPDK_Log_Error("tx port : %u index %u init tx ring error ! \n", sw_port_peer[rx_port].tx_port, i);
			return -1;
		}

		//设置core
		//tx_core = sw_port_peer[rx_port].tx_core_map[i];
		//sw_core_conf[rx_core].rx_mode_conf.tx_ring[i] = sw_port_peer[rx_port].tx_ring[i];
		//sw_core_conf[tx_core].tx_mode_conf.tx_queid = i;
		//sw_core_conf[tx_core].tx_mode_conf.tx_ring = sw_port_peer[rx_port].tx_ring[i];

		memset(ring_name,0,sizeof(ring_name));
		sprintf(ring_name, "cache_ring_port%02u_%u", sw_port_peer[rx_port].tx_port, i);
		sw_port_peer[rx_port].cache_ring[i] = rte_ring_create(ring_name, ring_num, socket_id, 0);
		if (NULL == sw_port_peer[rx_port].cache_ring[i])
		{
			SW_DPDK_Log_Error("tx port : %u index %u init cache ring error ! \n", sw_port_peer[rx_port].tx_port, i);
			return -1;
		}

		//设置core
		tx_core = sw_port_peer[rx_port].tx_core_map[i];
		sw_core_conf[rx_core].rx_mode_conf.cache_ring[i] = sw_port_peer[rx_port].cache_ring[i];
		sw_core_conf[tx_core].tx_mode_conf.tx_queid = i;
		sw_core_conf[tx_core].tx_mode_conf.tx_ring = sw_port_peer[rx_port].tx_ring[i];
		sw_core_conf[tx_core].tx_mode_conf.cache_ring = sw_port_peer[rx_port].cache_ring[i];

		//设置发送缓存 并设置err callback
		//收发口都需要设置
		//发口的buffer
		sw_tx_buffer[tx_port][i] = rte_zmalloc_socket("sw_tx_buffer",
				RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
				rte_eth_dev_socket_id(tx_port));
		if (NULL == sw_tx_buffer[tx_port][i])
		{
			SW_DPDK_Log_Error("tx port: %u index %u init sw_tx_buffer error!\n", tx_port, i);
			return -1;				
		}

		sw_tx_buffer_p_q[tx_port][i].port_id = tx_port;
		sw_tx_buffer_p_q[tx_port][i].que_id = i;
		rte_eth_tx_buffer_init(sw_tx_buffer[tx_port][i], MAX_PKT_BURST);
		rte_eth_tx_buffer_set_err_callback(sw_tx_buffer[tx_port][i],
				sw_dpdk_tx_buffer_callback,
				(void *)&sw_tx_buffer_p_q[tx_port][i]);

		struct sw_tx_buffer_para* tx_para = (struct sw_tx_buffer_para*)(sw_tx_buffer[tx_port][i]->error_userdata);
		SW_DPDK_Log_Info("Tx-Port:%u-%u setup tx buffer ok %u-%u !\n", tx_port, i, tx_para->port_id, tx_para->que_id);

		//收口的buffer
		sw_tx_buffer[rx_port][i] = rte_zmalloc_socket("sw_tx_buffer",
				RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
				rte_eth_dev_socket_id(rx_port));
		if (NULL == sw_tx_buffer[rx_port][i])
		{
			SW_DPDK_Log_Error("rx port: %u index %u init sw_tx_buffer error!\n", rx_port, i);
			return -1;				
		}

		sw_tx_buffer_p_q[rx_port][i].port_id = rx_port;
		sw_tx_buffer_p_q[rx_port][i].que_id = i;
		rte_eth_tx_buffer_init(sw_tx_buffer[rx_port][i], MAX_PKT_BURST);
		rte_eth_tx_buffer_set_err_callback(sw_tx_buffer[rx_port][i],
				sw_dpdk_tx_buffer_callback,
				(void *)&sw_tx_buffer_p_q[rx_port][i]);

		tx_para = (struct sw_tx_buffer_para*)(sw_tx_buffer[rx_port][i]->error_userdata);
		SW_DPDK_Log_Info("Rx-Port:%u-%u setup tx buffer ok %u-%u !\n", rx_port, i, tx_para->port_id, tx_para->que_id);
	}

	SW_DPDK_Log_Info("Rx Port %u Setup Buffer OK !\n", rx_port);
	return 0;
}

//must be called after eal init
static int sw_dpdk_update_conf(uint16_t rx_portid)
{
	uint16_t tx_portid = sw_port_peer[rx_portid].tx_port;

	memcpy(&sw_port_peer[tx_portid], &sw_port_peer[rx_portid], sizeof(SW_PORT_PEER));
	
	SW_DPDK_Log_Info("Update Conf, Rx-Port:%u Tx-Port:%u ok \n", rx_portid, tx_portid);

	return 0;
}


//static int sw_dpdk_init_conf(void)
//{
	//uint16_t tx_core[2] = {2, 3};
	//if (0 > sw_dpdk_setup_port_peer(0,1,3,1,2,tx_core))	
//	uint16_t tx_core_map[1] = {2};
//	if (0 > sw_dpdk_setup_port_peer(0,1,3,1,1,tx_core_map))
//	{
//		rte_exit(EXIT_FAILURE, "Invalid Port Conf\n");
//		return -1;
//	}

//	return 0;
//}

static int sw_dpdk_init_eal(void)
{
	/* init EAL */
	int ret = 0;
	int argc = 0;
    char argvstr[64][32] = {{0}};
    char* argv[64] = {0};

	//根据conf配置需要初始化的core
	char core_mask[32] = {0};
	sprintf(core_mask, "%llx%llx", (long long unsigned int)sw_used_core_mask_high, (long long unsigned int)sw_used_core_mask_low);

	strcpy(argvstr[argc], "vswitch"); argv[argc] = argvstr[argc]; argc++;
    strcpy(argvstr[argc], "-c"); argv[argc] = argvstr[argc]; argc++;
    strcpy(argvstr[argc], core_mask); argv[argc] = argvstr[argc]; argc++;
	strcpy(argvstr[argc], "--master-lcore"); argv[argc] = argvstr[argc]; argc++;
	strcpy(argvstr[argc], "0"); argv[argc] = argvstr[argc]; argc++;
    strcpy(argvstr[argc], "-n"); argv[argc] = argvstr[argc]; argc++;
    strcpy(argvstr[argc], "4"); argv[argc] = argvstr[argc]; argc++;

	printf("EAL:");
	int i;
	for (i = 0;i < argc; i++)
		printf("%s ", argv[i]);
	printf("\n");

	//rte_log_set_level(RTE_LOGTYPE_EAL,RTE_LOG_DEBUG);
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
	{
		SW_DPDK_Log_Error("Invalid EAL arguments\n");
		return -1;
	}

	sw_dpdk_total_port = rte_eth_dev_count();
	if (0 == sw_dpdk_total_port)
	{
		SW_DPDK_Log_Error("Total port is zeor ! \n");
		return -1;
	}
	else
		SW_DPDK_Log_Info("Total Port is %u ...\n", sw_dpdk_total_port);
	
	sw_dpdk_eal_init = true;
	
	return 0;
}

static int sw_dpdk_init_buffer(void)
{
	uint16_t i;
	for (i = 0; i < SW_DPDK_MAX_PORT; i++)
	{
		if ((sw_used_rx_port_mask & (1 << i)) == 0)
			continue;
		
		if (0 > sw_dpdk_setup_buffer(i))
		{
			SW_DPDK_Log_Error("Port %u setup buffer error ! \n", i);
			return -1;
		}
		
		sw_dpdk_update_conf(i);
	}

	return 0;
}

static int sw_dpdk_init_port(void)
{
	int ret;
	uint16_t i,portid,tx_que_cnt;
	struct rte_mempool *mpool;
	
	for (i = 0; i < SW_DPDK_MAX_PORT; i++)
	{
		if ((sw_used_port_mask & (1 << i)) == 0)
			continue;

		struct rte_eth_rxconf rxq_conf;
		struct rte_eth_txconf txq_conf;
		struct rte_eth_dev_info dev_info;
		struct rte_eth_conf local_port_conf = sw_nic_conf;

		portid = i;
		printf("Initializing port %u... ", portid);
		fflush(stdout);
		
		rte_eth_dev_info_get(portid, &dev_info);
		if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf.txmode.offloads |=
				DEV_TX_OFFLOAD_MBUF_FAST_FREE;
		
		rte_eth_macaddr_get(portid, &sw_ports_eth_addr[portid]);

		if (sw_port_mode_map[portid] == SW_PORT_RX)
		{
			//默认收包口初始化发包模式
			tx_que_cnt = sw_port_peer[portid].tx_core_num;
			ret = rte_eth_dev_configure(portid, 1, tx_que_cnt, &local_port_conf);
			if (ret < 0)
			{
				SW_DPDK_Log_Error("Cannot configure device: err=%d, port=%u\n", ret, portid);
				return -1;
			}
			
			ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
			if (ret < 0)
			{
				SW_DPDK_Log_Error("Cannot adjust number of descriptors: err=%d, port=%u\n", ret, portid);
				return -1;
			}
		
			fflush(stdout);

			mpool = sw_port_peer[portid].rx_mempool;
			if (NULL == mpool)
			{
				SW_DPDK_Log_Error("Rx Port %u mpool null !\n", portid);
				return -1;
			}
			
			rxq_conf = dev_info.default_rxconf;
			rxq_conf.offloads = local_port_conf.rxmode.offloads;
			ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
						     rte_eth_dev_socket_id(portid),
						     &rxq_conf,
						     mpool);
			if (ret < 0)
			{
				SW_DPDK_Log_Error("rte_eth_rx_queue_setup:err=%d, port=%u\n", ret, portid);
				return -1;
			}

			txq_conf = dev_info.default_txconf;
			txq_conf.txq_flags = ETH_TXQ_FLAGS_IGNORE;
			txq_conf.offloads = local_port_conf.txmode.offloads;
			uint16_t j;
			for (j = 0; j < tx_que_cnt; j++)
			{
				ret = rte_eth_tx_queue_setup(portid, j, nb_txd, rte_eth_dev_socket_id(portid), &txq_conf);
				if (ret < 0)
				{
					SW_DPDK_Log_Error("rte_eth_tx_queue_setup:err=%d, port=%u, que=%u\n", ret, portid, j);
					return -1;
				}
			}
		}
		else if (sw_port_mode_map[portid] == SW_PORT_TX)
		{
			tx_que_cnt = sw_port_peer[portid].tx_core_num;
			ret = rte_eth_dev_configure(portid, 0, tx_que_cnt, &local_port_conf);
			if (ret < 0)
			{
				SW_DPDK_Log_Error("Cannot configure device: err=%d, port=%u\n", ret, portid);
				return -1;
			}

			ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
			if (ret < 0)
			{
				SW_DPDK_Log_Error("Cannot adjust number of descriptors: err=%d, port=%u\n", ret, portid);
				return -1;
			}
				
			fflush(stdout);

#if 0
            mpool = sw_port_peer[portid].txport_rx_mempool;
			if (NULL == mpool)
			{
				SW_DPDK_Log_Error("Tx Port %u rx-mpool null !\n", portid);
				return -1;
			}

			rxq_conf = dev_info.default_rxconf;
			rxq_conf.offloads = local_port_conf.rxmode.offloads;
			ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
						     rte_eth_dev_socket_id(portid),
						     &rxq_conf,
						     mpool);
			if (ret < 0)
			{
				SW_DPDK_Log_Error("tx port rte_eth_rx_queue_setup:err=%d, port=%u\n", ret, portid);
				return -1;
			}
#endif
            
			txq_conf = dev_info.default_txconf;
			txq_conf.txq_flags = ETH_TXQ_FLAGS_IGNORE;
			txq_conf.offloads = local_port_conf.txmode.offloads;

			uint16_t j;
			for (j = 0; j < tx_que_cnt; j++)
			{
				ret = rte_eth_tx_queue_setup(portid, j, nb_txd, rte_eth_dev_socket_id(portid), &txq_conf);
				if (ret < 0)
				{
					SW_DPDK_Log_Error("rte_eth_tx_queue_setup:err=%d, port=%u, que=%u\n", ret, portid, j);
					return -1;
				}
			}
		}

		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
		{
			SW_DPDK_Log_Error("rte_eth_dev_start:err=%d, port=%u\n", ret, portid);
			return -1;
		}

		printf("done: \n");

		rte_eth_promiscuous_enable(portid);

		printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
				portid,
				sw_ports_eth_addr[portid].addr_bytes[0],
				sw_ports_eth_addr[portid].addr_bytes[1],
				sw_ports_eth_addr[portid].addr_bytes[2],
				sw_ports_eth_addr[portid].addr_bytes[3],
				sw_ports_eth_addr[portid].addr_bytes[4],
				sw_ports_eth_addr[portid].addr_bytes[5]);

		//set port mask
		sw_enabled_port_mask |= (1 << portid);
	}

	return 0;
}

static void sw_dpdk_calc_per_second(void)
{
    static int calc_cnt = 0;
    static uint64_t last_rx_cnt[SW_DPDK_MAX_PORT], last_tx_cnt[SW_DPDK_MAX_PORT];
    static uint64_t last_rx_len[SW_DPDK_MAX_PORT], last_tx_len[SW_DPDK_MAX_PORT];
    static uint64_t last_rx_cnt_total[SW_DPDK_MAX_PORT];
    static uint64_t last_tx_cnt_total[SW_DPDK_MAX_PORT];
    uint64_t current_rx_cnt, current_tx_cnt;
    uint64_t current_rx_len, current_tx_len;
    uint64_t current_rx_cnt_total;
    uint64_t current_tx_cnt_total;
    struct rte_eth_stats stats;
    int port_id = 0;
    for (port_id = 0; port_id < SW_DPDK_MAX_PORT; port_id++)
    {
    	if ((sw_used_port_mask & (1 << port_id)) == 0)
    		continue;

    	rte_eth_stats_get(port_id, &stats);
    	current_rx_cnt = stats.ipackets;
    	current_tx_cnt = stats.opackets;
    	current_rx_len = stats.ibytes;
    	current_tx_len = stats.obytes;
    	current_rx_cnt_total = stats.ipackets + stats.ierrors + stats.imissed;
    	current_tx_cnt_total = stats.opackets + stats.oerrors;
    		
    	port_hw_stat[port_id].rx_pps = ((current_rx_cnt - last_rx_cnt[port_id]));/* * 1000) / time_leap_ms*/
    	port_hw_stat[port_id].tx_pps = ((current_tx_cnt - last_tx_cnt[port_id]));/* * 1000) / time_leap_ms*/
    	port_hw_stat[port_id].rx_bps = ((current_rx_len - last_rx_len[port_id]) * 8 + port_hw_stat[port_id].rx_pps * 160);/* * 1000 * 8) / time_leap_ms*/
    	port_hw_stat[port_id].tx_bps = ((current_tx_len - last_tx_len[port_id]) * 8 + port_hw_stat[port_id].tx_pps * 160);/* * 1000 * 8) / time_leap_ms*/
    	port_hw_stat[port_id].rx_pps_total = (current_rx_cnt_total - last_rx_cnt_total[port_id]);
    	port_hw_stat[port_id].tx_pps_total = (current_tx_cnt_total - last_tx_cnt_total[port_id]);
    	port_hw_stat[port_id].rx_pps_total_average = current_rx_cnt_total / (++calc_cnt);
    	
    	last_rx_cnt[port_id] = current_rx_cnt;
    	last_tx_cnt[port_id] = current_tx_cnt;
    	last_rx_len[port_id] = current_rx_len;
    	last_tx_len[port_id] = current_tx_len;
    	last_rx_cnt_total[port_id] = current_rx_cnt_total;
    	last_tx_cnt_total[port_id] = current_tx_cnt_total;
    }
}

static void* sw_dpdk_calc_idle_que_thread(void* parg)
{
    if (!parg)
		printf("Start to thread %s \n", __FUNCTION__);

    uint32_t port_id;
    while(1)
    {
        if (!start_work)
        {
            usleep(100);
            continue;
        }
        
        for (port_id = 0; port_id < SW_DPDK_MAX_PORT; port_id++)
        {
        	if ((sw_used_port_mask & (1 << port_id)) == 0)
        		continue;

            if (sw_port_mode_map[port_id] != SW_PORT_RX)
                continue;

            uint32_t idle_id = 0;
            uint32_t i = 0;
            unsigned cur_ring_free_cnt,max_ring_free_cnt = 0;
            struct rte_ring* pring_rx = NULL;
            struct rte_ring* pring_tx = NULL;
            for (; i < sw_port_peer[port_id].tx_core_num; i++)
            {
                pring_rx = sw_port_peer[port_id].cache_ring[i];
                pring_tx = sw_port_peer[port_id].tx_ring[i];
                cur_ring_free_cnt = rte_ring_free_count(pring_rx) + rte_ring_free_count(pring_tx);
                if (max_ring_free_cnt < cur_ring_free_cnt)
                {
                    max_ring_free_cnt = cur_ring_free_cnt;
                    idle_id = i;
                }  
            }

            sw_idle_que_id[port_id] = idle_id;
        }

        usleep(100);
    }
}

static void* sw_dpdk_calc_statistic_thread(void* parg)
{
	if (!parg)
		printf("Start to thread %s \n", __FUNCTION__);

    //当前计算统计信息默认使用0号核
    static uint64_t cur_tsc;
	static uint64_t next_tsc;
	uint64_t timer_1s_hz = rte_get_timer_hz();

	int need_calc = 1;
	while(1)
	{
		if (start_work && need_calc)
		{
			cur_tsc = rte_rdtsc();
			next_tsc = cur_tsc + timer_1s_hz;
			sw_dpdk_calc_per_second();
			need_calc = 0;
		}

		usleep(1000);
		cur_tsc = rte_rdtsc();
		if (cur_tsc >= next_tsc)
			need_calc = 1;
	}

    return NULL;
}

static int sw_dpdk_core_map(char* buf, int buf_len)
{
	uint64_t sw_used_core_mask;
	int len = 0;
	len += snprintf(buf+len, buf_len-len,"\n");
	uint16_t i;
	for (i = 0; i < SW_DPDK_MAX_CORE; i++)
	{
		if (i >= 64)
			sw_used_core_mask = sw_used_core_mask_high;
		else
			sw_used_core_mask = sw_used_core_mask_low;
	
		if ((sw_used_core_mask & ((uint64_t)1<<(i%64))) == 0)
			continue;

		if (sw_core_conf[i].core_mode == SW_CORE_RX)
			len += snprintf(buf+len, buf_len-len,"  Core:%02u  RX Mode\n", i);
		else if (sw_core_conf[i].core_mode == SW_CORE_TX)
			len += snprintf(buf+len, buf_len-len,"  Core:%02u  TX Mode\n", i);
		else
			len += snprintf(buf+len, buf_len-len,"  Core:%02u  No Mode\n", i);
	}
	
	return len;
}


static int sw_dpdk_kill_self(char* buf, int buf_len)
{
	int len = 0;
	printf("Start to kill myself ...\n");
	len += snprintf(buf, buf_len-len,"Kill Success ...\n");
	force_quit = true;

	return len;
}

static int sw_dpdk_show_fwd(uint16_t portid, char* buf, int buf_len)
{
	int len = 0;
	if ((sw_enabled_port_mask & (1 << portid)) == 0)
	{
		len += snprintf(buf+len, buf_len-len, "PortID:%u is not enabled, PortMask:%d!\n", portid, sw_enabled_port_mask);
		return len;
	}

	if ((sw_used_rx_port_mask & (1 << portid)) == 0)
	{
		len += snprintf(buf+len, buf_len-len, "PortID:%u is not rx mode, PortMask:%d!\n", portid, sw_used_rx_port_mask);
		return len;
	}

	len += snprintf(buf+len, buf_len-len, "FWD--Rule: \n");
	len += snprintf(buf+len, buf_len-len, "    LoopBack    : %u \n", sw_port_peer[portid].loopback);
	len += snprintf(buf+len, buf_len-len, "    Delay       : %u \n", sw_port_peer[portid].delay_s);
	len += snprintf(buf+len, buf_len-len, "    Len         : %u \n", sw_port_peer_fwd_rules[portid].len_filter_len);
	len += snprintf(buf+len, buf_len-len, "    Len-Mode    : %u \n", sw_port_peer_fwd_rules[portid].len_filter_mode);
    len += snprintf(buf+len, buf_len-len, "    MaxLen      : %u \n", sw_port_peer_fwd_rules[portid].max_len_filter_len);
	len += snprintf(buf+len, buf_len-len, "    MaxLen-Mode : %u \n", sw_port_peer_fwd_rules[portid].max_len_filter_mode);
	len += snprintf(buf+len, buf_len-len, "    Syn-Mode    : %u \n", sw_port_peer_fwd_rules[portid].syn_filter_mode);
	len += snprintf(buf+len, buf_len-len, "    Acl-Mode    : %u \n", sw_port_peer_fwd_rules[portid].acl_filter_mode);
	len += snprintf(buf+len, buf_len-len, "    Off-Mode    : %u \n", sw_port_peer_fwd_rules[portid].offset_filter_mode);
    len += snprintf(buf+len, buf_len-len, "    IP6-Mode    : %u \n", sw_port_peer_fwd_rules[portid].ipv6_filter_mode);
    len += snprintf(buf+len, buf_len-len, "    VLAN-Mode   : %u \n", sw_port_peer_fwd_rules[portid].vlan_offload_mode);
    len += snprintf(buf+len, buf_len-len, "    MPLS-Mode   : %u \n", sw_port_peer_fwd_rules[portid].mpls_offload_mode);
    
	return len;
}

static int sw_dpdk_set_fwd(uint16_t portid,
	                             uint16_t delay_s,
	                             uint16_t loopback,
	                             uint16_t filter_len,
	                             uint16_t len_mode,
	                             uint16_t max_filter_len,
	                             uint16_t max_len_mode,
	                             uint16_t syn_mode,
	                             uint16_t acl_mode,
	                             uint16_t off_mode,
								 uint16_t ipv6_mode,
								 uint16_t vlan_offload_mode,
								 uint16_t mpls_offload_mode,
								 char* buf, int buf_len)
{
    SW_DPDK_Log_Info("Get %d %d %d %d %d %d %d %d %d %d %d %d %d \n", 
                                  portid,
	                              delay_s,
	                              loopback,
	                              filter_len,
	                              len_mode,
	                              max_filter_len,
	                              max_len_mode,
	                              syn_mode,
	                              acl_mode,
	                              off_mode,
								  ipv6_mode,
								  vlan_offload_mode,
								  mpls_offload_mode);

	int len = 0;
	if ((sw_enabled_port_mask & (1 << portid)) == 0)
	{
		len += snprintf(buf+len, buf_len-len, "PortID:%u is not enabled, PortMask:%d!\n", portid, sw_enabled_port_mask);
		return len;
	}

	if ((sw_used_rx_port_mask & (1 << portid)) == 0)
	{
		len += snprintf(buf+len, buf_len-len, "PortID:%u is not rx mode, PortMask:%d!\n", portid, sw_used_rx_port_mask);
		return len;
	}

	if (delay_s > sw_port_delay_init[portid])
	{
		len += snprintf(buf+len, buf_len-len, "PortID:%u Init Delay is %u seconds!\n", portid, sw_port_delay_init[portid]);
		return len;
	}

	if (loopback != 0 && loopback != 1)
	{
		len += snprintf(buf+len, buf_len-len, "loopback : %u  error \n", loopback);
		return len;
	}

	if (loopback)
	{
		if (len_mode == SW_FILTER_LEN_RXPORT)
		{
			len += snprintf(buf+len, buf_len-len, "loopback, len-mode should not be 1 ... \n");
			return len;
		}

        if (max_len_mode == SW_FILTER_MAX_LEN_RXPORT)
		{
			len += snprintf(buf+len, buf_len-len, "loopback, max-len-mode should not be 1 ... \n");
			return len;
		}

		if (syn_mode == SW_FILTER_SYN_RXPORT)
		{
			len += snprintf(buf+len, buf_len-len, "loopback, syn-mode should not be 1 ... \n");
			return len;
		}

		if (off_mode == SW_FILTER_OFF_RXPORT)
		{
			len += snprintf(buf+len, buf_len-len, "loopback, offset-mode should not be 1 ... \n");
			return len;
		}

        if (ipv6_mode == SW_FILTER_IP6_RXPORT)
		{
			len += snprintf(buf+len, buf_len-len, "loopback, ipv6-mode should not be 1 ... \n");
			return len;
		}
	}

	if (filter_len < SW_DPDK_PKT_LEN_MIN || SW_DPDK_PKT_LEN_MAX < filter_len)
	{
		len += snprintf(buf+len, buf_len-len, "len : %u  error, must in [%d-%d] \n", filter_len, SW_DPDK_PKT_LEN_MIN, SW_DPDK_PKT_LEN_MAX);
		return len;
	}

	if ( SW_FILTER_LEN_DROP < len_mode)
	{
		len += snprintf(buf+len, buf_len-len, "len-mode : %u  error \n", len_mode);
		return len;
	}

    if (max_filter_len < SW_DPDK_PKT_LEN_MIN || SW_DPDK_PKT_LEN_MAX < max_filter_len)
	{
		len += snprintf(buf+len, buf_len-len, "max-len : %u  error, must in [%d-%d] \n", max_filter_len, SW_DPDK_PKT_LEN_MIN, SW_DPDK_PKT_LEN_MAX);
		return len;
	}

	if ( SW_FILTER_MAX_LEN_DROP < max_len_mode)
	{
		len += snprintf(buf+len, buf_len-len, "max-len-mode : %u  error \n", max_len_mode);
		return len;
	}

	if (SW_FILTER_SYN_DROP < syn_mode)
	{
		len += snprintf(buf+len, buf_len-len, "syn-mode : %u  error \n", syn_mode);
		return len;
	}

	if (SW_FILTER_ACL_DROP < acl_mode)
	{
		len += snprintf(buf+len, buf_len-len, "acl-mode : %u  error \n", acl_mode);
		return len;
	}
	
	if (SW_FILTER_OFF_DROP < off_mode)
	{
		len += snprintf(buf+len, buf_len-len, "off-mode : %u  error \n", off_mode);
		return len;
	}

	if (SW_FILTER_IP6_DROP < ipv6_mode) {
		len += snprintf(buf+len, buf_len-len, "ipv6-mode : %u  error \n", ipv6_mode);
		return len;
	}

	//update , maybe need to lock
    pthread_rwlock_wrlock(&sw_config_rwlock[portid]);//请求写锁
    
	uint32_t tx_port = sw_port_peer[portid].tx_port;
	sw_port_peer[portid].loopback = loopback;
	sw_port_peer[portid].delay_s = delay_s;
	sw_port_peer[tx_port].loopback = loopback;
	sw_port_peer[tx_port].delay_s = delay_s;
	
	sw_port_peer_fwd_rules[portid].len_filter_len = filter_len;
	sw_port_peer_fwd_rules[portid].len_filter_mode = len_mode;
    sw_port_peer_fwd_rules[portid].max_len_filter_len = max_filter_len;
	sw_port_peer_fwd_rules[portid].max_len_filter_mode = max_len_mode;
	sw_port_peer_fwd_rules[portid].syn_filter_mode = syn_mode;
	sw_port_peer_fwd_rules[portid].acl_filter_mode = acl_mode;
	sw_port_peer_fwd_rules[portid].offset_filter_mode = off_mode;
	sw_port_peer_fwd_rules[portid].ipv6_filter_mode = ipv6_mode;
	sw_port_peer_fwd_rules[portid].vlan_offload_mode = vlan_offload_mode;
	sw_port_peer_fwd_rules[portid].mpls_offload_mode = mpls_offload_mode;

    uint32_t i = 0;
	sw_port_need_update_rx[portid] = 1;
	for (; i < sw_port_peer[portid].tx_core_num; i++)
		sw_port_need_update_tx[tx_port][i] = 1;

    //更新加速配置
    unsigned short rx_port = portid;
    if (sw_port_peer_fwd_rules[rx_port].len_filter_mode == SW_FILTER_LEN_RXPORT)
		sw_len_filter_tx_port[rx_port] = rx_port;
	else if (sw_port_peer_fwd_rules[rx_port].len_filter_mode == SW_FILTER_LEN_TXPORT)
		sw_len_filter_tx_port[rx_port] = tx_port;
    else if (sw_port_peer_fwd_rules[rx_port].len_filter_mode == SW_FILTER_LEN_DROP)
		sw_len_filter_tx_port[rx_port] = SW_DPDK_DROP_PORT;

    if (sw_port_peer_fwd_rules[rx_port].max_len_filter_mode == SW_FILTER_MAX_LEN_RXPORT)
		sw_max_len_filter_tx_port[rx_port] = rx_port;
	else if (sw_port_peer_fwd_rules[rx_port].max_len_filter_mode == SW_FILTER_MAX_LEN_TXPORT)
		sw_max_len_filter_tx_port[rx_port] = tx_port;
    else if (sw_port_peer_fwd_rules[rx_port].max_len_filter_mode == SW_FILTER_MAX_LEN_DROP)
		sw_max_len_filter_tx_port[rx_port] = SW_DPDK_DROP_PORT;
	
	if (sw_port_peer_fwd_rules[rx_port].syn_filter_mode == SW_FILTER_SYN_RXPORT)
		sw_syn_filter_tx_port[rx_port] = rx_port;
	else if (sw_port_peer_fwd_rules[rx_port].syn_filter_mode == SW_FILTER_SYN_TXPORT)
		sw_syn_filter_tx_port[rx_port] = tx_port;
    else if (sw_port_peer_fwd_rules[rx_port].syn_filter_mode == SW_FILTER_SYN_DROP)
		sw_syn_filter_tx_port[rx_port] = SW_DPDK_DROP_PORT;

	if (sw_port_peer_fwd_rules[rx_port].acl_filter_mode == SW_FILTER_ACL_RXPORT)
		sw_acl_filter_tx_port[rx_port] = rx_port;
	else if (sw_port_peer_fwd_rules[rx_port].acl_filter_mode == SW_FILTER_ACL_TXPORT)
		sw_acl_filter_tx_port[rx_port] = tx_port;
    else if (sw_port_peer_fwd_rules[rx_port].acl_filter_mode == SW_FILTER_ACL_DROP)
		sw_acl_filter_tx_port[rx_port] = SW_DPDK_DROP_PORT;

	if (sw_port_peer_fwd_rules[rx_port].offset_filter_mode == SW_FILTER_OFF_RXPORT)
		sw_offset_filter_tx_port[rx_port] = rx_port;
	else if (sw_port_peer_fwd_rules[rx_port].offset_filter_mode == SW_FILTER_OFF_TXPORT)
		sw_offset_filter_tx_port[rx_port] = tx_port;
    else if (sw_port_peer_fwd_rules[rx_port].offset_filter_mode == SW_FILTER_OFF_DROP)
		sw_offset_filter_tx_port[rx_port] = SW_DPDK_DROP_PORT;

    if (sw_port_peer_fwd_rules[rx_port].ipv6_filter_mode == SW_FILTER_IP6_RXPORT)
		sw_ip6_filter_tx_port[rx_port] = rx_port;
	else if (sw_port_peer_fwd_rules[rx_port].ipv6_filter_mode == SW_FILTER_IP6_TXPORT)
		sw_ip6_filter_tx_port[rx_port] = tx_port;
    else if (sw_port_peer_fwd_rules[rx_port].ipv6_filter_mode == SW_FILTER_IP6_DROP)
		sw_ip6_filter_tx_port[rx_port] = SW_DPDK_DROP_PORT;

    pthread_rwlock_unlock(&sw_config_rwlock[portid]);//释放写锁

    SW_DPDK_Log_Info("CMD Start to update conf rxport:%d len-port:%d max-len-port:%d syn-port:%d acl-port:%d off-port:%d ipv6-port:%d ... \n", rx_port,
                    sw_len_filter_tx_port[rx_port], sw_max_len_filter_tx_port[rx_port], sw_syn_filter_tx_port[rx_port],
                    sw_acl_filter_tx_port[rx_port], sw_offset_filter_tx_port[rx_port], sw_ip6_filter_tx_port[rx_port]);
	
	len += snprintf(buf+len, buf_len-len, "FWD Rule: \n");
	len += snprintf(buf+len, buf_len-len, "    LoopBack   : %u \n", sw_port_peer[portid].loopback);
	len += snprintf(buf+len, buf_len-len, "    Delay      : %u \n", sw_port_peer[portid].delay_s);
	len += snprintf(buf+len, buf_len-len, "    Len        : %u \n", sw_port_peer_fwd_rules[portid].len_filter_len);
	len += snprintf(buf+len, buf_len-len, "    Len-Mode   : %u \n", sw_port_peer_fwd_rules[portid].len_filter_mode);
    len += snprintf(buf+len, buf_len-len, "    MaxLen     : %u \n", sw_port_peer_fwd_rules[portid].max_len_filter_len);
	len += snprintf(buf+len, buf_len-len, "    MaxLen-Mode: %u \n", sw_port_peer_fwd_rules[portid].max_len_filter_mode);
	len += snprintf(buf+len, buf_len-len, "    Syn-Mode   : %u \n", sw_port_peer_fwd_rules[portid].syn_filter_mode);
	len += snprintf(buf+len, buf_len-len, "    Acl-Mode   : %u \n", sw_port_peer_fwd_rules[portid].acl_filter_mode);
	len += snprintf(buf+len, buf_len-len, "    Off-Mode   : %u \n", sw_port_peer_fwd_rules[portid].offset_filter_mode);
	len += snprintf(buf+len, buf_len-len, "    Ipv6-Mode  : %u \n", sw_port_peer_fwd_rules[portid].ipv6_filter_mode);
	len += snprintf(buf+len, buf_len-len, "    Vlan-Offload-Mode: %u \n", sw_port_peer_fwd_rules[portid].vlan_offload_mode);
	len += snprintf(buf+len, buf_len-len, "    Mpls-Offload-Mode: %u \n", sw_port_peer_fwd_rules[portid].mpls_offload_mode);
	len += snprintf(buf+len, buf_len-len, "\nSet Ok ! \n");	
		
	return len;
}

static int _sw_dpdk_get_port_simpe_stat(uint16_t portid, char* buf, int buf_len) {
	int len = 0;
	uint16_t i = 0;
	if ((sw_enabled_port_mask & (1 << portid)) == 0)
	{
		len += snprintf(buf+len, buf_len-len, "PortID:%u is not enabled, PortMask:%d!\n", portid, sw_enabled_port_mask);
		return len;
	}	

	if (sw_port_mode_map[portid] == SW_PORT_RX)
	{
		len += snprintf(buf+len, buf_len-len, "Port %u RX mode, Peer Port %u :\n", portid, sw_port_peer[portid].tx_port);
	}
	else if (sw_port_mode_map[portid] == SW_PORT_TX)
	{
		len += snprintf(buf+len, buf_len-len, "Port %u TX mode, Peer Port %u :\n", portid, sw_port_peer[portid].rx_port);
	}
	len += snprintf(buf+len, buf_len-len, "MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
				sw_ports_eth_addr[portid].addr_bytes[0],
				sw_ports_eth_addr[portid].addr_bytes[1],
				sw_ports_eth_addr[portid].addr_bytes[2],
				sw_ports_eth_addr[portid].addr_bytes[3],
				sw_ports_eth_addr[portid].addr_bytes[4],
				sw_ports_eth_addr[portid].addr_bytes[5]);
	struct rte_eth_stats stats;
	rte_eth_stats_get(portid, &stats);
	if (sw_port_mode_map[portid] == SW_PORT_RX) {
		len += snprintf(buf+len, buf_len-len, "  RX-packets: %-18"PRIu64" RX-bytes:  %-18"PRIu64"\n", stats.ipackets,stats.ibytes);
    	len += snprintf(buf+len, buf_len-len, "  RX-pps:	  %-18"PRIu64"\n",port_hw_stat[portid].rx_pps);
		len += snprintf(buf+len, buf_len-len, "  RX-bps:	  %-18"PRIu64"\n",port_hw_stat[portid].rx_bps);
		len += snprintf(buf+len, buf_len-len, "  RX-pps-total:	  %-18"PRIu64"\n", port_hw_stat[portid].rx_pps_total);
	} else {
		len += snprintf(buf+len, buf_len-len, "  TX-packets: %-18"PRIu64" TX-errors: %-18"PRIu64" TX-bytes:  "
		   "%-"PRIu64"\n",
		   stats.opackets, stats.oerrors, stats.obytes);
		len += snprintf(buf+len, buf_len-len, "  TX-pps:	  %-18"PRIu64"\n", port_hw_stat[portid].tx_pps);
		len += snprintf(buf+len, buf_len-len, "  TX-bps:	  %-18"PRIu64"\n", port_hw_stat[portid].tx_bps);
		len += snprintf(buf+len, buf_len-len, "  TX-pps-total:	  %-18"PRIu64"\n", port_hw_stat[portid].tx_pps_total);
	}
	return len;
}
static int sw_dpdk_all_port_stat(char* buf, int buf_len) {
	int len = 0;
	uint16_t i = 0;
	int portid = 0;
	for (portid = 0; portid < SW_DPDK_MAX_PORT; ++portid) {
		if ((sw_enabled_port_mask & (1 << portid)) == 0)
		{
			continue;
		}
		if (sw_port_mode_map[portid] == SW_PORT_RX)
		{
			len += _sw_dpdk_get_port_simpe_stat(portid, buf + len, buf_len - len);
			len += _sw_dpdk_get_port_simpe_stat(sw_port_peer[portid].tx_port, buf + len, buf_len - len);
			len += snprintf(buf+len, buf_len-len, "================================================\n");
		}
	}
	return len;
}
static int sw_dpdk_port_stat(uint16_t portid, char* buf, int buf_len)
{
	int len = 0;
	uint16_t i = 0;
	if ((sw_enabled_port_mask & (1 << portid)) == 0)
	{
		len += snprintf(buf+len, buf_len-len, "PortID:%u is not enabled, PortMask:%d!\n", portid, sw_enabled_port_mask);
		return len;
	}

	len += snprintf(buf+len, buf_len-len, "[vSwitch Running Seconds:%u ]\n", sw_running_seconds);

	if (sw_port_mode_map[portid] == SW_PORT_RX)
	{
		len += snprintf(buf+len, buf_len-len, "Port %u RX mode, Peer Port %u :\n", portid, sw_port_peer[portid].tx_port);
	}
	else if (sw_port_mode_map[portid] == SW_PORT_TX)
	{
		len += snprintf(buf+len, buf_len-len, "Port %u TX mode, Peer Port %u :\n", portid, sw_port_peer[portid].rx_port);
	}

	len += snprintf(buf+len, buf_len-len, "MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
				sw_ports_eth_addr[portid].addr_bytes[0],
				sw_ports_eth_addr[portid].addr_bytes[1],
				sw_ports_eth_addr[portid].addr_bytes[2],
				sw_ports_eth_addr[portid].addr_bytes[3],
				sw_ports_eth_addr[portid].addr_bytes[4],
				sw_ports_eth_addr[portid].addr_bytes[5]);
	
	len += snprintf(buf+len, buf_len-len, "\nHardWare Stat:\n\n");
	
	struct rte_mempool* pmempool = NULL;
	pmempool = sw_port_peer[portid].rx_mempool;
	if (NULL != pmempool)
	{
		len += snprintf(buf+len, buf_len-len, "  Buff[%s]: count %d, size %d, available %u, alloc %u\n", 
		        pmempool->name,
		        pmempool->size,
		        pmempool->elt_size,
		        rte_mempool_avail_count(pmempool),
		        rte_mempool_in_use_count(pmempool));
	}

	struct rte_ring* pring = NULL;
	for (; i < sw_port_peer[portid].tx_core_num; i++)
	{
		pring = sw_port_peer[portid].cache_ring[i];
		if (NULL != pring)
		{
			len += snprintf(buf+len, buf_len-len, "  Ring[%s]: count %d, available %u, alloc %u\n", 
			        pring->name,
			        pring->size,
			        rte_ring_free_count(pring),
			        rte_ring_count(pring));
		}

		pring = sw_port_peer[portid].tx_ring[i];
		if (NULL != pring)
		{
			len += snprintf(buf+len, buf_len-len, "  Ring[%s]: count %d, available %u, alloc %u\n", 
			        pring->name,
			        pring->size,
			        rte_ring_free_count(pring),
			        rte_ring_count(pring));
		}
	}	

	len += snprintf(buf+len, buf_len-len, "\n");
	
	struct rte_eth_stats stats;
	rte_eth_stats_get(portid, &stats);

	len += snprintf(buf+len, buf_len-len, "  RX-packets: %-18"PRIu64" RX-bytes:  %-18"PRIu64"\n", stats.ipackets,stats.ibytes);
    len += snprintf(buf+len, buf_len-len, "  RX-error  : %-18"PRIu64"     Reason:[CRC or BadLen Error By Packet]\n",  stats.ierrors);
	len += snprintf(buf+len, buf_len-len, "  RX-nombuf : %-18"PRIu64"     Reason:[Mempool Not Enough, Not Equal To Packet Num]\n", stats.rx_nombuf);
    len += snprintf(buf+len, buf_len-len, "  RX-missed : %-18"PRIu64"     Reason:[Fwd Thread Been Scheduled or Enque Nic Que Error Happen]\n", stats.imissed);
	len += snprintf(buf+len, buf_len-len, "  TX-packets: %-18"PRIu64" TX-errors: %-18"PRIu64" TX-bytes:  "
		   "%-"PRIu64"\n",
		   stats.opackets, stats.oerrors, stats.obytes);
	len += snprintf(buf+len, buf_len-len, "  TX-dropped:  %-18"PRIu64"\n", port_hw_stat[portid].dropped);
	len += snprintf(buf+len, buf_len-len, "  RX-pps:	  %-18"PRIu64" TX-pps:	  %-18"PRIu64"\n",port_hw_stat[portid].rx_pps,port_hw_stat[portid].tx_pps);
	len += snprintf(buf+len, buf_len-len, "  RX-bps:	  %-18"PRIu64" TX-bps:	  %-18"PRIu64"\n",port_hw_stat[portid].rx_bps,port_hw_stat[portid].tx_bps);
	len += snprintf(buf+len, buf_len-len, "  RX-pps-total:	  %-18"PRIu64" TX-pps-total:	  %-18"PRIu64"\n",\
                port_hw_stat[portid].rx_pps_total, port_hw_stat[portid].tx_pps_total);

	
	len += snprintf(buf+len, buf_len-len, "\nSoftWare Stat:\n\n");
	uint16_t tx_num;
	if (sw_port_mode_map[portid] == SW_PORT_RX)
	{
		tx_num = sw_port_peer[portid].tx_core_num;
		for (i = 0; i < tx_num; i++)
		{
			len += snprintf(buf+len, buf_len-len, "  [Ring%u]Enque-Ring:  %-18"PRIu64 "  Drop-Ring:  %-18"PRIu64"\n", 
							i, port_sw_stat[portid].enque_ring[i], port_sw_stat[portid].drop_by_no_ring[i]);
		}
	}
	else if (sw_port_mode_map[portid] == SW_PORT_TX)
	{
		tx_num = sw_port_peer[portid].tx_core_num;
		for (i = 0; i < tx_num; i++)
		{
			len += snprintf(buf+len, buf_len-len, "  [Ring%02u]Deque-Cache-Ring:  %-18"PRIu64 "In-Delay-Ring:  %-18"PRIu64 "Out-Delay-Ring:  %-18"PRIu64 "Interface-Tx:  %-18"PRIu64 "\n          Err-Parse:  %-18"PRIu64"     Err-Eth:  %-18"PRIu64"     Err-NetParse:  %-18"PRIu64"     Err-TransParse:  %-18"PRIu64 "\n          Filter-Len:  %-18"PRIu64 "\n          Filter-Max-Len:  %-18"PRIu64 "\n          Filter-Syn:  %-18"PRIu64 
                                                    "\n          Filter-Acl:  %-18"PRIu64 "\n          Filter-Offset:  %-18"PRIu64"\n          Filter-Ipv6:  %-18"PRIu64"\n          Filter-VlanOff:  %-18"PRIu64"\n          Filter-MplsOv4:  %-18"PRIu64"\n          Filter-MplsOv6:  %-18"PRIu64"\n", 
							i, port_sw_stat[portid].deque_cache_ring[i], port_sw_stat[portid].enque_tx_ring[i],
							port_sw_stat[portid].deque_tx_ring[i], port_sw_stat[portid].deque_tx_interface[i],
							port_sw_stat[portid].drop_by_parsed[i], port_sw_stat[portid].drop_by_parsed_eth[i], port_sw_stat[portid].drop_by_parsed_net[i], port_sw_stat[portid].drop_by_parsed_trans[i], 
							port_sw_stat[portid].filter_len[i], port_sw_stat[portid].filter_max_len[i],
							port_sw_stat[portid].filter_syn[i], 
							port_sw_stat[portid].filter_acl[i],port_sw_stat[portid].filter_offset[i],
							port_sw_stat[portid].filter_ipv6[i],port_sw_stat[portid].filter_vlan_off[i],
							port_sw_stat[portid].filter_mpls_off_v4[i], port_sw_stat[portid].filter_mpls_off_v6[i]);
		}

		len += snprintf(buf+len, buf_len-len, "\n\nPackets Stat:\n\n");
		for (i = 0; i < tx_num; i++)
		{
			len += snprintf(buf+len, buf_len-len, "  [Ring%02u]VLAN:  %-18"PRIu64 "  MPLS:  %-18"PRIu64 "  IPv4:  %-18"PRIu64 "  IPv6:  %-18"PRIu64 "ICMP:  %-18"PRIu64 "TCP:  %-18"PRIu64 "UDP:  %-18"PRIu64"\n", 
							i, port_sw_stat[portid].vlan_pkts[i], port_sw_stat[portid].mpls_pkts[i],
							port_sw_stat[portid].ipv4_pkts[i],port_sw_stat[portid].ipv6_pkts[i], port_sw_stat[portid].icmp_pkts[i],
							port_sw_stat[portid].tcp_pkts[i], port_sw_stat[portid].udp_pkts[i]);

			len += snprintf(buf+len, buf_len-len, "          Len_Less_128 :  %-18"PRIu64 "\n", port_sw_stat[portid].len_less_128[i]);
			len += snprintf(buf+len, buf_len-len, "          Len_128_256  :  %-18"PRIu64 "\n", port_sw_stat[portid].len_128_256[i]);
			len += snprintf(buf+len, buf_len-len, "          Len_256_512  :  %-18"PRIu64 "\n", port_sw_stat[portid].len_256_512[i]);
			len += snprintf(buf+len, buf_len-len, "          Len_512_1024 :  %-18"PRIu64 "\n", port_sw_stat[portid].len_512_1024[i]);
			len += snprintf(buf+len, buf_len-len, "          Len_More_1024:  %-18"PRIu64 "\n", port_sw_stat[portid].len_more_1024[i]);
		}
	}
	
	return len;
}

/**************************************************************/
static void
sw_dpdk_tx_pkts(uint16_t port_id, uint16_t queue_id,
		 struct rte_mbuf **pkts_burst, uint16_t pkt_num)
{
#if 0
	//发送至网卡
    int nb_tx = 0;
	int pkt_leaved = pkt_num;
	do
    {
        //可能发送不成功，循环的进行发送
        nb_tx += rte_eth_tx_burst(port_id, queue_id, &pkts_burst[nb_tx], pkt_leaved);
        pkt_leaved = pkt_num - nb_tx;
        if (pkt_leaved <= 0)
            break;
    }while(pkt_leaved > 0);
#endif

    int i;
    //20181115 port_id = SW_DPDK_DROP_PORT means drop pkts
    if (port_id == SW_DPDK_DROP_PORT)
    {
        for (i = 0; i < pkt_num; i++)
            rte_pktmbuf_free(pkts_burst[i]);

        return;
    }


	struct rte_eth_dev_tx_buffer *buffer = sw_tx_buffer[port_id][queue_id];
	for (i = 0; i < pkt_num; i++)
		rte_eth_tx_buffer(port_id, queue_id, buffer, pkts_burst[i]);
}

//cache ring 进行解析
static void sw_dpdk_get_parse(struct rte_ring *cache_ring, struct rte_ring *tx_ring, uint16_t rx_port, uint16_t tx_port, uint16_t tx_queid, uint16_t loopback, unsigned lcore_id)
{
	int i;
	uint16_t pkt_len = 0;
	struct rte_mbuf *m;
	struct rte_mbuf *m_bulk[MAX_PKT_BURST];
	int threadId;
	int length;

    static int _tmp_flag = 0;

	//int num = rte_ring_dequeue_bulk(cache_ring, (void **)&m_bulk, MAX_PKT_BURST, NULL);
	int num = rte_ring_dequeue_burst(cache_ring, (void **)&m_bulk, MAX_PKT_BURST, NULL);
	if (num == 0)
		return;

	port_sw_stat[tx_port].deque_cache_ring[tx_queid] += num;

	//SW_DPDK_Log_Debug("PortID:%u-%u get %d num pkts ....\n", rx_port, tx_port, num);

	//if (loopback)
	//{
	//	sw_dpdk_tx_pkts(rx_port, tx_queid, m_bulk, num);
	//	SW_DPDK_Log_Debug("Loopback, PortID:%u-%u send %d num pkts ok ....\n", rx_port, tx_port, num);
	//}

    pthread_rwlock_rdlock(&sw_config_rwlock[rx_port]);//请求读锁
    
	uint16_t len_filter_mode = sw_port_peer_fwd_rules[rx_port].len_filter_mode;
    uint16_t max_len_filter_mode = sw_port_peer_fwd_rules[rx_port].max_len_filter_mode;
	uint16_t syn_filter_mode = sw_port_peer_fwd_rules[rx_port].syn_filter_mode;
	uint16_t acl_filter_mode = sw_port_peer_fwd_rules[rx_port].acl_filter_mode;
	uint16_t offset_filter_mode = sw_port_peer_fwd_rules[rx_port].offset_filter_mode;
    uint16_t ipv6_filter_mode = sw_port_peer_fwd_rules[rx_port].ipv6_filter_mode;
    uint16_t vlan_offload_mode = sw_port_peer_fwd_rules[rx_port].vlan_offload_mode;
    uint16_t mpls_offload_mode = sw_port_peer_fwd_rules[rx_port].mpls_offload_mode;

	uint16_t len_filter_tx_port = sw_len_filter_tx_port[rx_port];
    uint16_t max_len_filter_tx_port = sw_max_len_filter_tx_port[rx_port];
	uint16_t syn_filter_tx_port = sw_syn_filter_tx_port[rx_port];
	uint16_t acl_filter_tx_port = sw_acl_filter_tx_port[rx_port];
	uint16_t offset_filter_tx_port = sw_offset_filter_tx_port[rx_port];
    uint16_t ipv6_filter_tx_port = sw_ip6_filter_tx_port[rx_port];

    uint16_t filter_len = sw_port_peer_fwd_rules[rx_port].len_filter_len;
    uint16_t max_filter_len = sw_port_peer_fwd_rules[rx_port].max_len_filter_len;

    pthread_rwlock_unlock(&sw_config_rwlock[rx_port]);//请求读锁

	int delay_num = 0;
	struct rte_mbuf *m_delay[MAX_PKT_BURST];	
	PKT_INFO_S pkt_info;
	struct rte_mbuf **m_non_len = m_bulk;
	int len_left = num;
    int parse_ok = 0;
	
#if 0	
	//len filter
	///////////////////////////////////////////////////////////
	if (!len_filter_mode)
		goto non_len_filter;

	//uint16_t filter_len = sw_port_peer_fwd_rules[rx_port].len_filter_len;
	len_left = 0;
	int len_filter = 0;
	struct rte_mbuf *m_len_filter[MAX_PKT_BURST];
	struct rte_mbuf *m_len_left[MAX_PKT_BURST];
	
	for (i = 0; i < num; i++)
	{
		m = m_bulk[i];
		if (rte_pktmbuf_pkt_len(m) <= filter_len)
		{
			m_len_filter[len_filter++] = m;
		}
		else
		{
			m_len_left[len_left++] = m;
		}
	}

	sw_dpdk_tx_pkts(len_filter_tx_port, tx_queid, m_len_filter, len_filter);
	port_sw_stat[tx_port].filter_len[tx_queid] += len_filter;
	m_non_len = m_len_left;
	///////////////////////////////////////////////////////////
#endif
non_len_filter:
	//////////////////////////////////////////////////////////	
	//报文解包过滤  过滤出需要延时的报文
	for (i = 0; i < len_left; i++)
	{
		//对报文进行分析
		parse_ok = 0;
		m = m_non_len[i];
		pkt_info.peth_pkt = rte_pktmbuf_mtod(m, uint8_t *);
		pkt_info.pkt_len = rte_pktmbuf_pkt_len(m);
		pkt_len = rte_pktmbuf_pkt_len(m);;
		if (SW_PARSE_OK == sw_pkt_get_hdr(&pkt_info))
		{
		    parse_ok = 1;
            
			//统计信息
			if (pkt_info.vlan_flag)
				port_sw_stat[tx_port].vlan_pkts[tx_queid]++;

			if (pkt_info.mpls_flag)
				port_sw_stat[tx_port].mpls_pkts[tx_queid]++;

			if (pkt_info.ipv4_flag)
				port_sw_stat[tx_port].ipv4_pkts[tx_queid]++;
		
			if (pkt_info.ipv6_flag)
				port_sw_stat[tx_port].ipv6_pkts[tx_queid]++;

			if (pkt_info.icmp_flag)
				port_sw_stat[tx_port].icmp_pkts[tx_queid]++;

			if (pkt_info.proto == PKT_IPPROTO_TCP)
				port_sw_stat[tx_port].tcp_pkts[tx_queid]++;

			if (pkt_info.proto == PKT_IPPROTO_UDP)
				port_sw_stat[tx_port].udp_pkts[tx_queid]++;

			//统计长度分布
			if (pkt_len <= 128)
				port_sw_stat[tx_port].len_less_128[tx_queid]++;
			else if (pkt_len > 128 && pkt_len <= 256)
				port_sw_stat[tx_port].len_128_256[tx_queid]++;
			else if (pkt_len > 256 && pkt_len <= 512)
				port_sw_stat[tx_port].len_256_512[tx_queid]++;
			else if (pkt_len > 512 && pkt_len <= 1024)
				port_sw_stat[tx_port].len_512_1024[tx_queid]++;
			else if (pkt_len > 1024)
				port_sw_stat[tx_port].len_more_1024[tx_queid]++;
		}
		else
		{
			port_sw_stat[tx_port].drop_by_parsed[tx_queid]++;
            if (pkt_info.err_reason == ERR_ETH)
                port_sw_stat[tx_port].drop_by_parsed_eth[tx_queid]++;
            else if (pkt_info.err_reason == ERR_NET)
                port_sw_stat[tx_port].drop_by_parsed_net[tx_queid]++;
            else if (pkt_info.err_reason == ERR_TRANS)
                port_sw_stat[tx_port].drop_by_parsed_trans[tx_queid]++;
            
			//rte_pktmbuf_free(m);
            if (loopback && (rte_mbuf_refcnt_read(m) >= 2))
    	    {
    		    sw_dpdk_tx_pkts(rx_port, tx_queid, &m, 1);
    	    }

            //不识别的报文，直接不延迟发送
            sw_dpdk_tx_pkts(tx_port, tx_queid, &m, 1);

            continue;
		}

        if (parse_ok)
        {
            //若vlan 卸载功能打开，则需要卸载vlan
    		if ((vlan_offload_mode == SW_FILTER_VLANOFF_ENABLE) && pkt_info.vlan_flag)
            {
                char _mac[12];
                memcpy(_mac, rte_pktmbuf_mtod(m, uint8_t *), 12);
                char *new_eth = rte_pktmbuf_adj(m, pkt_info.vlan_layers * 4);
                memcpy(new_eth, _mac, 12);
                port_sw_stat[tx_port].filter_vlan_off[tx_queid]++;
            }

            //若mpls 卸载功能打开，则需要卸载mpls
    		if ((mpls_offload_mode == SW_FILTER_MPLSOFF_ENABLE) && pkt_info.mpls_flag)
            {
                //char _print = 0;
                //if (0 == _tmp_flag)
                //{
                //    _tmp_flag = 1;
                //    _print = 1;
                //    printf("=======> Before Mpls: %d \n", m->data_len);
                //    rte_pktmbuf_dump(stdout, m, m->data_len);
                //}
            
                char _head[14];
                memcpy(_head, rte_pktmbuf_mtod(m, uint8_t *), 12);
                char *new_eth = rte_pktmbuf_adj(m, pkt_info.mpls_layers * 4);
                if (pkt_info.ipv6_flag == 1)
                {
                    _head[12] = 0x86;//mpls means it is ip pkt .... ?
                    _head[13] = 0xdd;
                    port_sw_stat[tx_port].filter_mpls_off_v6[tx_queid]++;
                }
                else if (pkt_info.ipv4_flag == 1)
                {
                    _head[12] = 0x08;//mpls means it is ip pkt .... ?
                    _head[13] = 0x00;
                    port_sw_stat[tx_port].filter_mpls_off_v4[tx_queid]++;
                }
                memcpy(new_eth, _head, 14);
                

                //if (1 == _print)
                //{
                //    printf("=======> End Mpls: %d \n", m->data_len);
                //    rte_pktmbuf_dump(stdout, m, m->data_len);
                //}
            }
            
    		if (loopback && (rte_mbuf_refcnt_read(m) >= 2))
    	    {
    		    sw_dpdk_tx_pkts(rx_port, tx_queid, &m, 1);
    	    }
            
    		if (len_filter_mode && (rte_pktmbuf_pkt_len(m) <= filter_len))
            {
    	        port_sw_stat[tx_port].filter_len[tx_queid] ++;
    		    sw_dpdk_tx_pkts(len_filter_tx_port, tx_queid, &m, 1);
                continue;			
    		}

            if (max_len_filter_mode && (rte_pktmbuf_pkt_len(m) >= max_filter_len))
            {
    	        port_sw_stat[tx_port].filter_max_len[tx_queid] ++;
    		    sw_dpdk_tx_pkts(max_len_filter_tx_port, tx_queid, &m, 1);
                continue;			
    		}

            //ipv6 filter
            if (ipv6_filter_mode && pkt_info.ipv6_flag)
            { 
                port_sw_stat[tx_port].filter_ipv6[tx_queid] ++;
                sw_dpdk_tx_pkts(ipv6_filter_tx_port, tx_queid, &m, 1);
                continue;
            }
            
    		//syn 过滤
    		if (syn_filter_mode && !pkt_info.ipv6_flag)
    		{
    			if (pkt_info.proto == PKT_IPPROTO_TCP && 
    				((pkt_info.trans_info.tcp.flags & 0x0200) ||
    				 (pkt_info.trans_info.tcp.flags & 0x0100) ||
    				 (pkt_info.trans_info.tcp.flags & 0x0400)))
    			{
    				port_sw_stat[tx_port].filter_syn[tx_queid] ++;
                    SW_DPDK_Log_Debug("Syn PortID:%u-%u send %d num pkts ok to port:%u ....\n", rx_port, tx_port, 1, syn_filter_tx_port);
                    //SW_DPDK_Log_Info("Syn PortID:%u-%u send %d num pkts ok to port:%u ....\n", rx_port, tx_port, 1, syn_filter_tx_port);
    				sw_dpdk_tx_pkts(syn_filter_tx_port, tx_queid, &m, 1);				
    				continue;
    			}
    		}
    		

    		//acl 过滤
    		if (acl_filter_mode && !pkt_info.ipv6_flag)
    		{
    			if (0 == sw_filter_port(rx_port, tx_queid, &pkt_info))
    			{
    				port_sw_stat[tx_port].filter_acl[tx_queid]++;
    				sw_dpdk_tx_pkts(acl_filter_tx_port, tx_queid, &m, 1);

    				SW_DPDK_Log_Debug("Acl PortID:%u-%u send %d num pkts ok to prot:%u ....\n", rx_port, tx_port, 1, acl_filter_tx_port);
    				continue;
    			}
    		}
    				

    		//offset 过滤
    		if (offset_filter_mode && !pkt_info.ipv6_flag)
    		{
    			if (0 > sw_offset_match(rx_port, tx_queid, &pkt_info))
    			{
    				port_sw_stat[tx_port].filter_offset[tx_queid]++;
    				sw_dpdk_tx_pkts(offset_filter_tx_port, tx_queid, &m, 1);

    				SW_DPDK_Log_Debug("Offset PortID:%u-%u send %d num pkts ok to prot:%u ....\n", rx_port, tx_port, 1, offset_filter_tx_port);
    				continue;
    			}	
    		}
        }
        //else
        //{
            //解析成功，则回环的报文会去掉vlan.mpls头部，否则原生报文
        //    if (loopback && (rte_mbuf_refcnt_read(m) >= 2))
    	//    {
    	//	    sw_dpdk_tx_pkts(rx_port, tx_queid, &m, 1);
    	//    }
        //}

		//剩下的为需要delay的      
		m_delay[delay_num++] = m;
	}

	//需要延迟发送的
	if (delay_num > 0)
	{
		num = rte_ring_enqueue_bulk(tx_ring, (void **)m_delay, delay_num, NULL);
		port_sw_stat[tx_port].enque_tx_ring[tx_queid] += num;
	}			
}

static int sw_dpdk_set_pthread_affinity(unsigned cpu_id)
{
	cpu_set_t 		mask;
	unsigned		cpu_num = 0;

	//检查CPU_ID正确性
	cpu_num = sysconf(_SC_NPROCESSORS_ONLN);
	if(cpu_id >= cpu_num)
	{
		return -1;
	}

	CPU_ZERO(&mask);
	CPU_SET(cpu_id, &mask);

	if(pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask) < 0)
	{
		return -1;
	}

	return 0;
}


/* main processing loop */
static void* 
sw_dpdk_main_loop(void *arg)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *m, *send_m;
	int ret;
	unsigned lcore_id;
	unsigned i, nb_rx, nb_send;
	uint16_t rx_port, tx_port, tx_num, delay, hash_id;
	struct rte_ring* rx_push_ring[SW_DPDK_MAX_TX_NUM] = {0};
	struct rte_ring* tx_ring = NULL;
	struct rte_ring* cache_ring = NULL;
	uint64_t timeout_tsc, cur_tsc, prev_tsc, diff_tsc;
	uint64_t timer_1s_hz = rte_get_timer_hz();
	SW_CORE_CONF *core_conf = NULL;
	uint16_t tx_queid = 0;
	uint16_t rx_mode = 0;
	uint16_t tx_mode = 0;
	uint16_t loopback = 0;
	uint8_t  get_new_pkt = 1;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * SW_BURST_TX_DRAIN_US;
	uint64_t sw_used_core_mask;
	int threadId;
	int length = 0;
		
	//lcore_id = rte_lcore_id();
	lcore_id = *((unsigned *)arg);
	if (lcore_id >= 64)
		sw_used_core_mask = sw_used_core_mask_high;
	else
		sw_used_core_mask = sw_used_core_mask_low;
	
	if ((sw_used_core_mask & ((uint64_t)1 << (lcore_id % 64))) == 0 || 0 == lcore_id)
	{
		RTE_LOG(INFO, VSWITCH, "lcore %u has nothing to do \n", lcore_id);
		fprintf(runlogF, "lcore %u has nothing to do ", lcore_id);
		fclose(runlogF);
		return NULL;
	}

	core_conf = &sw_core_conf[lcore_id];
	SW_CORE_MODE core_mode = core_conf->core_mode;

	if (core_mode == SW_CORE_RX)
	{
		rx_port = core_conf->rx_mode_conf.rx_port;
		tx_num = core_conf->rx_mode_conf.tx_num;
		for (i = 0; i < tx_num; i++)
			rx_push_ring[i] = (struct rte_ring*)core_conf->rx_mode_conf.cache_ring[i];

		delay = sw_port_peer[rx_port].delay_s;
		rx_mode = 1;
		loopback = sw_port_peer[rx_port].loopback;
		tx_port = sw_port_peer[rx_port].tx_port;
	}
	else if (core_mode == SW_CORE_TX)
	{
		tx_port = core_conf->tx_mode_conf.tx_port;
		tx_queid = core_conf->tx_mode_conf.tx_queid;
		tx_ring = core_conf->tx_mode_conf.tx_ring;
		cache_ring = core_conf->tx_mode_conf.cache_ring;
		delay = sw_port_peer[tx_port].delay_s;
		tx_mode = 1;
		rx_port = sw_port_peer[tx_port].rx_port;
		tx_num = sw_port_peer[tx_port].tx_core_num;
		loopback = sw_port_peer[tx_port].loopback;
	}
	else
	{
		SW_DPDK_Log_Error("Core %u Mode error %d ...\n", lcore_id, core_mode);
		fprintf(runlogF, "Core %u Mode error %d ...", lcore_id, core_mode);
		fclose(runlogF);
		return NULL;
	}
	

	SW_DPDK_Log_Info("entering main loop on lcore %u, mode:%d \n", lcore_id, core_mode);
	sw_dpdk_set_pthread_affinity(lcore_id);

	prev_tsc = 0;
	uint16_t hash_cnt = 0;
	uint16_t check_cnt = 0;
	while (!force_quit) {

		//usleep(1000);

		//隔固定的时间检查更新配置
		if (check_cnt++ % 4096 == 0)
		{
			check_cnt = 0;
			if (rx_mode && sw_port_need_update_rx[rx_port])
			{
				sw_port_need_update_rx[rx_port] = 0;
            
				delay = sw_port_peer[rx_port].delay_s;
				loopback = sw_port_peer[rx_port].loopback;

				SW_DPDK_Log_Info("RX Core %u Start to update conf delay:%u, loopback:%u ... \n", lcore_id, delay, loopback);

            #if 0
				//放在rx核心上操作，避免tx多核心的同时处理	
				if (sw_port_peer_fwd_rules[rx_port].len_filter_mode == SW_FILTER_LEN_RXPORT)
					sw_len_filter_tx_port[rx_port] = rx_port;
				else if (sw_port_peer_fwd_rules[rx_port].len_filter_mode == SW_FILTER_LEN_TXPORT)
					sw_len_filter_tx_port[rx_port] = tx_port;
                else if (sw_port_peer_fwd_rules[rx_port].len_filter_mode == SW_FILTER_LEN_DROP)
					sw_len_filter_tx_port[rx_port] = SW_DPDK_DROP_PORT;

                if (sw_port_peer_fwd_rules[rx_port].max_len_filter_mode == SW_FILTER_MAX_LEN_RXPORT)
					sw_max_len_filter_tx_port[rx_port] = rx_port;
				else if (sw_port_peer_fwd_rules[rx_port].max_len_filter_mode == SW_FILTER_MAX_LEN_TXPORT)
					sw_max_len_filter_tx_port[rx_port] = tx_port;
                else if (sw_port_peer_fwd_rules[rx_port].max_len_filter_mode == SW_FILTER_MAX_LEN_DROP)
					sw_max_len_filter_tx_port[rx_port] = SW_DPDK_DROP_PORT;
				
				if (sw_port_peer_fwd_rules[rx_port].syn_filter_mode == SW_FILTER_SYN_RXPORT)
					sw_syn_filter_tx_port[rx_port] = rx_port;
				else if (sw_port_peer_fwd_rules[rx_port].syn_filter_mode == SW_FILTER_SYN_TXPORT)
					sw_syn_filter_tx_port[rx_port] = tx_port;
                else if (sw_port_peer_fwd_rules[rx_port].syn_filter_mode == SW_FILTER_SYN_DROP)
					sw_syn_filter_tx_port[rx_port] = SW_DPDK_DROP_PORT;

				if (sw_port_peer_fwd_rules[rx_port].acl_filter_mode == SW_FILTER_ACL_RXPORT)
					sw_acl_filter_tx_port[rx_port] = rx_port;
				else if (sw_port_peer_fwd_rules[rx_port].acl_filter_mode == SW_FILTER_ACL_TXPORT)
					sw_acl_filter_tx_port[rx_port] = tx_port;
                else if (sw_port_peer_fwd_rules[rx_port].acl_filter_mode == SW_FILTER_ACL_DROP)
					sw_acl_filter_tx_port[rx_port] = SW_DPDK_DROP_PORT;

				if (sw_port_peer_fwd_rules[rx_port].offset_filter_mode == SW_FILTER_OFF_RXPORT)
					sw_offset_filter_tx_port[rx_port] = rx_port;
				else if (sw_port_peer_fwd_rules[rx_port].offset_filter_mode == SW_FILTER_OFF_TXPORT)
					sw_offset_filter_tx_port[rx_port] = tx_port;
                else if (sw_port_peer_fwd_rules[rx_port].offset_filter_mode == SW_FILTER_OFF_DROP)
					sw_offset_filter_tx_port[rx_port] = SW_DPDK_DROP_PORT;

                if (sw_port_peer_fwd_rules[rx_port].ipv6_filter_mode == SW_FILTER_IP6_RXPORT)
					sw_ip6_filter_tx_port[rx_port] = rx_port;
				else if (sw_port_peer_fwd_rules[rx_port].ipv6_filter_mode == SW_FILTER_IP6_TXPORT)
					sw_ip6_filter_tx_port[rx_port] = tx_port;
                else if (sw_port_peer_fwd_rules[rx_port].ipv6_filter_mode == SW_FILTER_IP6_DROP)
					sw_ip6_filter_tx_port[rx_port] = SW_DPDK_DROP_PORT;

                pthread_rwlock_unlock(&sw_config_rwlock[rx_port]);//释放写锁

                SW_DPDK_Log_Info("Core %u Start to update conf rxport:%d len:%d max-len:%d syn:%d acl:%d off:%d ipv6:%d ... \n", lcore_id, rx_port,
                    sw_len_filter_tx_port[rx_port], sw_max_len_filter_tx_port[rx_port], sw_syn_filter_tx_port[rx_port],
                    sw_acl_filter_tx_port[rx_port], sw_offset_filter_tx_port[rx_port], sw_ip6_filter_tx_port[rx_port]);
            #endif
			}

			if (tx_mode && sw_port_need_update_tx[tx_port][tx_queid])
			{
				sw_port_need_update_tx[tx_port][tx_queid] = 0;
			
				delay = sw_port_peer[tx_port].delay_s;
				loopback = sw_port_peer[tx_port].loopback;
				SW_DPDK_Log_Info("Core %u Start to update conf delay:%u, loopback:%u ... \n", lcore_id, delay, loopback);
			}
		}

		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;

		if (rx_mode)
		{
			nb_rx = rte_eth_rx_burst(rx_port, 0, pkts_burst, MAX_PKT_BURST);
			if (nb_rx <= 0) 
				continue;

		#ifdef SW_DPDK_DEBUG
			//printf("1) recevice %u pkts from rx_port:%u \n", nb_rx, rx_port);
		#endif

			//时间戳
			timeout_tsc = cur_tsc + timer_1s_hz * delay;
			for (i = 0; i < nb_rx; i++)
			{
				m = pkts_burst[i];
 				rte_prefetch0(rte_pktmbuf_mtod(m, void *));				
				m->timestamp = timeout_tsc;
				if (loopback)
				{
					//设置ref cnt自增1                    
					rte_pktmbuf_refcnt_update(m, 1);      
				}
				
				//printf("Time:%18"PRIu64"Recv A pkt,timeout:%18"PRIu64"\n", cur_tsc, m->timestamp);

				//这是hash分流的方式
				//hash_id = m->hash.rss % tx_num;
				//if (0 != rte_ring_enqueue(rx_push_ring[hash_id], (void*)m))
				//{
				//	rte_pktmbuf_free(m);
				//	port_sw_stat[rx_port].drop_by_no_ring[hash_id]++;
				//}

				//port_sw_stat[rx_port].enque_ring[hash_id]++;
			}		

            // before
			//暂时hash方式采用轮询的方式 ,后续rx port也可以根据rss来分流
			//hash_id = (hash_cnt++) % tx_num;

            //from 20181116, use the most idle que
            hash_id = sw_idle_que_id[rx_port];
			if (nb_rx != (nb_send = rte_ring_enqueue_bulk(rx_push_ring[hash_id], (void**)pkts_burst, nb_rx, NULL)))
			{
				for (i = nb_send; i < nb_rx; i++)
					rte_pktmbuf_free(pkts_burst[i]);
				
				port_sw_stat[rx_port].drop_by_no_ring[hash_id]++;
			}
			else
			{
				port_sw_stat[rx_port].enque_ring[hash_id] += nb_rx;
				//SW_DPDK_Log_Debug("recevice %u pkts from rx_port:%u and Push to Ring ...\n", nb_rx, rx_port);
			}
			//只有在回还的情况下rx port才会发包
			//if (loopback)
			//{
			//	sw_dpdk_tx_pkts(rx_port, 0, pkts_burst, nb_rx);

				// flush the tx buffer
			//	if (unlikely(diff_tsc > drain_tsc)) {
			//		rte_eth_tx_buffer_flush(rx_port, 0, sw_tx_buffer[rx_port][0]);
			//		prev_tsc = cur_tsc;
			//	}
			//}
		}
		
		if (tx_mode)
		{
            // flush the tx buffer
			if (unlikely(diff_tsc > drain_tsc)) {

				//rx
				rte_eth_tx_buffer_flush(rx_port, tx_queid, sw_tx_buffer[rx_port][tx_queid]);
				//if (!loopback) 
				//	rte_eth_tx_buffer_flush(rx_port, tx_queid, sw_tx_buffer[rx_port][tx_queid]);

				//tx
				rte_eth_tx_buffer_flush(tx_port, tx_queid, sw_tx_buffer[tx_port][tx_queid]);
				
				prev_tsc = cur_tsc;
			}
        
			//cache ring 进行解析
			sw_dpdk_get_parse(cache_ring, tx_ring, rx_port, tx_port, tx_queid, loopback, lcore_id);

			//发送真实数据
			if (get_new_pkt)
			{
				ret = rte_ring_dequeue(tx_ring, (void **)&send_m);
				if (ret != 0)
				{
				    //usleep(1);
					continue;
				}
				else
					port_sw_stat[tx_port].deque_tx_ring[tx_queid]++;

			#ifdef SW_DPDK_DEBUG
				//printf("3) recevice a pkt from delay ring, tx_port :%u - %u \n", tx_port, tx_queid);
			#endif	
			}

			//等待发送
			if (cur_tsc >= send_m->timestamp)
			{
				//printf("Time:%18"PRIu64"Forward A pkt,timeout:%18"PRIu64"\n", cur_tsc,m->timestamp);
				port_sw_stat[tx_port].deque_tx_interface[tx_queid]++;
				sw_dpdk_tx_pkts(tx_port, tx_queid, &send_m, 1);
				get_new_pkt = 1;
			}
			else
				get_new_pkt = 0;			
		}
	}

	return NULL;
}

//static int
//sw_dpdk_launch_one_lcore(__attribute__((unused)) void *dummy)
//{
//	sw_dpdk_main_loop();
//	return 0;
//}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
sw_dpdk_check_all_ports_link_status(uint16_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint16_t portid;
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		if (force_quit)
			return;
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			if (force_quit)
				return;
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf(
					"Port%d Link Up. Speed %u Mbps - %s\n",
						portid, link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n", portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

static void
sw_dpdk_signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}
}

int sw_dpdk_start(void)
{	
	unsigned core_array[SW_DPDK_MAX_CORE] = {0};
	unsigned lcore_id, portid;
	
	/* launch per-lcore init on every lcore */
	start_work = true;
	//rte_eal_mp_remote_launch(sw_dpdk_launch_one_lcore, NULL, CALL_MASTER);
	//RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		//if (rte_eal_wait_lcore(lcore_id) < 0) {
		//	break;
		//}	
	//}

	pthread_t threadId;
	int ret, i=0;
	RTE_LCORE_FOREACH_SLAVE(lcore_id)
	{
		core_array[i] = lcore_id;
		sw_core_conf[lcore_id].threadId = i;
		ret = pthread_create(&threadId, NULL, sw_dpdk_main_loop, &core_array[i]);
		if (0 != ret)
		{
			SW_DPDK_Log_Error("Lcoreid:%u create thread error!\n", lcore_id);
			fprintf(runlogF, "Lcoreid:%u create thread error!", lcore_id);
			fclose(runlogF);
			return -1;
		}
		i++;
	}
	sleep(3);
	fprintf(runlogF, "vswitch start success...", lcore_id);
	fclose(runlogF);

	while (1)
	{
		if (force_quit)
		{
			sleep(1);
			break;
		}

	#if 1
		sleep(1);
		sw_running_seconds++;

	#else
		//for dynamic test
		i++;
		sleep(5);
		char off_err[64] = {0};
		char test_rule[128] = {0};
		//sprintf(test_rule, "%s_%d", "0,L4,20,GET,string,HTTP_GET", i);
		//ret = sw_offset_dynamic_add_rules(test_rule, off_err, sizeof(off_err));
		sprintf(test_rule, "%s", "0,0.0.0.0/0,0.0.0.0/0,0:65535,0:65535,0x0/0x0");
		ret = sw_filter_dynamic_add_rules(test_rule, off_err, sizeof(off_err));
		if (ret != 0)
		{
			printf("Add %s error !\n", test_rule);
		}
		else
		{
			printf("Add %s ok !\n", test_rule);
		}

		sleep(10);

		memset(off_err, 0, sizeof(off_err));
		memset(test_rule, 0, sizeof(test_rule));
		//sprintf(test_rule, "%s_%d", "0,L4,20,GET,string,HTTP_GET_P", i);
		//ret = sw_offset_dynamic_add_rules(test_rule, off_err, sizeof(off_err));
		sprintf(test_rule, "%s", "0,0.0.0.0/0,0.0.0.0/0,0:65535,0:65535,0x0/0x0");
		ret = sw_filter_dynamic_add_rules(test_rule, off_err, sizeof(off_err));
		if (ret != 0)
		{
			printf("Add %s error !\n", test_rule);
		}
		else
		{
			printf("Add %s ok !\n", test_rule);
		}

		sleep(10);

		memset(off_err, 0, sizeof(off_err));
		//ret = sw_offset_dynamic_del_rule(0, SW_OFFSET_L4, 0, off_err, sizeof(off_err));
		ret = sw_filter_dynamic_del_rule(0, 1, off_err, sizeof(off_err));
		if (ret != 0)
		{
			printf("delete %d error !\n", 1);
		}
		else
		{
			printf("Delete %d ok !\n", 1);
		} 

		sleep(10);
	#endif
	}
	
	for (portid = 0; portid < sw_dpdk_total_port; portid++) {
		if ((sw_enabled_port_mask & (1 << portid)) == 0)
			continue;
		printf("Closing port %d...", portid);
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}
	printf("Bye...\n");

	return 0;
}

int sw_dpdk_init(char* conf_path, uint32_t dpdk_pps)
{
	int i,ret;
	sw_dpdk_pps = dpdk_pps;

	//signal
	force_quit = false;
	signal(SIGINT, sw_dpdk_signal_handler);
	signal(SIGTERM, sw_dpdk_signal_handler);

	//初始化命令行
	sw_command_register_show_core_mode(sw_dpdk_core_map);
	sw_command_register_kill_self(sw_dpdk_kill_self);
	sw_command_register_show_port(sw_dpdk_port_stat);
	sw_command_register_show_portpeer_stats(sw_dpdk_all_port_stat);
	sw_command_register_show_fwd_rule(sw_dpdk_show_fwd);
	sw_command_register_set_fwd_rule(sw_dpdk_set_fwd);
	sw_command_init(CMD_ROLE_SERVER);

	//1)初始化配置
	//2)根据配置初始化DPDK eal
	//3)获得port,再调用dpdk接口获取port所在的numa,更新conf,根据conf初始化内存
	//4)初始化各个port
	//5)开始main loop

	// step 1
	/////////////////////////////////////////////////////////////////////////////////////////
	SW_PORT_PEER tmp_conf[SW_DPDK_MAX_PORT] = {{0}};
	if (0 > sw_config_init(conf_path, (void *)tmp_conf))
	{
		SW_DPDK_Log_Error("Init Conf:%s error\n", conf_path);
		return -1;
	}
	else
	{
		for (i = 0; i < SW_DPDK_MAX_PORT; i++)
		{
			if (!tmp_conf[i].init)
				continue;

			ret = sw_dpdk_setup_port_peer(tmp_conf[i].rx_port, tmp_conf[i].tx_port,
									tmp_conf[i].delay_s,tmp_conf[i].loopback,tmp_conf[i].rx_core, 
									tmp_conf[i].tx_core_num, tmp_conf[i].tx_core_map);
			if (0 > ret)
			{
				SW_DPDK_Log_Error("Setup Port %u peer error\n", i);
				return -1;
			}

			sw_port_delay_init[i] = tmp_conf[i].delay_s;
		}

		if (sw_used_port_mask == 0)
		{
			SW_DPDK_Log_Error("Wrong Conf ... \n");
			return -1;
		}
	}

	// step 2 设置转发规则
	sw_dpdk_init_fwd_rules();
	SW_PORT_PEER_FWD_RULES tmp_fwd_conf[SW_DPDK_MAX_PORT] = {{0}};
	char rules_conf[64] = {0};
	memcpy(rules_conf, SW_DPDK_FWD_RULES_PATH, strlen(SW_DPDK_FWD_RULES_PATH));
	if (0 > sw_fwd_rules_init(rules_conf, (void *)tmp_fwd_conf))
	{
		SW_DPDK_Log_Error("Init Conf:%s error\n", conf_path);
		return -1;
	}
	else
	{
		for (i = 0; i < SW_DPDK_MAX_PORT; i++)
		{
			if (!tmp_fwd_conf[i].init)
				continue;

			ret = sw_dpdk_setup_fwd_rules(i, &tmp_fwd_conf[i]);
			if (0 > ret)
			{
				SW_DPDK_Log_Error("Setup Port %u fwd rules error\n", i);
				return -1;
			}
		}
	}
	sw_dpdk_make_fwd_rules();
		
	// step 3
	ret = sw_dpdk_init_eal();
	if (0 > ret)
		return -1;
	
	// step 4
	ret = sw_dpdk_init_buffer();
	if (0 > ret)
		return -1;
	
	// step 5
	ret = sw_dpdk_init_port();
	if (0 > ret)
		return -1;
	
	// check all the links 
	sw_dpdk_check_all_ports_link_status(sw_dpdk_total_port, sw_enabled_port_mask);

	memset(port_sw_stat, 0, sizeof(port_sw_stat));

	//初始化统计线程
	pthread_t threadid;
	if (0 != pthread_create(&threadid, NULL, sw_dpdk_calc_statistic_thread, NULL))
	{
		printf("create sw_dpdk_calc_statistic_thread error!\n");
		return -1;
	}

    if (0 != pthread_create(&threadid, NULL, sw_dpdk_calc_idle_que_thread, NULL))
    {
        printf("create sw_dpdk_calc_idle_que_thread error!\n");
		return -1;
    }
    
	return 0;
}

uint32_t sw_dpdk_http_show_all_port(SW_DPDK_HTTP_ALL_PORT_INFO* port_info, char* buf, int buf_len) {
	int portid = 0;
	int numofinfos = 0;
	for (portid = 0; portid < SW_DPDK_MAX_PORT; ++portid) {
		if ((sw_enabled_port_mask & (1 << portid)) == 0) {
			continue;
		}
		port_info->infos[numofinfos].portid = portid;
		port_info->infos[numofinfos].mode = sw_port_mode_map[portid];
		++numofinfos;
	}
	port_info->numofinfos = numofinfos;
	return 0;
}

///////////////////////////////////////////////////////////////////
uint32_t sw_dpdk_http_show_port(uint32_t portid, SW_DPDK_HTTP_PORT_INFO* port_info, char* buf, int buf_len)
{
	int len = 0;
	uint16_t i = 0;
	if ((sw_enabled_port_mask & (1 << portid)) == 0)
	{
		len += snprintf(buf+len, buf_len-len, "PortID:%u is not enabled, PortMask:0x%x! ", portid, sw_enabled_port_mask);
		return len;
	}

	memset(port_info, 0, sizeof(SW_DPDK_HTTP_PORT_INFO));

	port_info->running_sec = sw_running_seconds;

	uint32_t tx_port = 0;
	if (sw_port_mode_map[portid] == SW_PORT_RX)
	{
		port_info->portid = portid;
		port_info->peer_port = sw_port_peer[portid].tx_port;
		port_info->mode = SW_PORT_RX;
		tx_port = sw_port_peer[portid].tx_port;
	}
	else if (sw_port_mode_map[portid] == SW_PORT_TX)
	{
		port_info->portid = portid;
		port_info->peer_port = sw_port_peer[portid].rx_port;
		port_info->mode = SW_PORT_TX;
		tx_port = portid;
	}
	
	//statictis
	struct rte_eth_stats stats;
	rte_eth_stats_get(portid, &stats);
	port_info->rx = stats.ipackets;
	port_info->rx_bytes = stats.ibytes;
	port_info->tx = stats.opackets;
	port_info->tx_bytes = stats.obytes;
	port_info->rx_pps = port_hw_stat[portid].rx_pps;
	port_info->tx_pps = port_hw_stat[portid].tx_pps;
	port_info->rx_bps = port_hw_stat[portid].rx_bps;
	port_info->tx_bps = port_hw_stat[portid].tx_bps;

	for (i = 0; i < sw_port_peer[tx_port].tx_core_num; i++)
	{
		port_info->filter_len += port_sw_stat[tx_port].filter_len[i];
        port_info->filter_max_len += port_sw_stat[tx_port].filter_max_len[i];
		port_info->filter_syn += port_sw_stat[tx_port].filter_syn[i];
		port_info->filter_acl += port_sw_stat[tx_port].filter_acl[i];
		port_info->filter_offset += port_sw_stat[tx_port].filter_offset[i];
        port_info->filter_ipv6 += port_sw_stat[tx_port].filter_ipv6[i];

		port_info->vlan_pkts += port_sw_stat[tx_port].vlan_pkts[i];
		port_info->mpls_pkts += port_sw_stat[tx_port].mpls_pkts[i];
		port_info->ipv4_pkts += port_sw_stat[tx_port].ipv4_pkts[i];
		port_info->ipv6_pkts += port_sw_stat[tx_port].ipv6_pkts[i];
		port_info->icmp_pkts += port_sw_stat[tx_port].icmp_pkts[i];
		port_info->tcp_pkts += port_sw_stat[tx_port].tcp_pkts[i];
		port_info->udp_pkts += port_sw_stat[tx_port].udp_pkts[i];

		port_info->len_less_128 += port_sw_stat[tx_port].len_less_128[i];
		port_info->len_128_256 += port_sw_stat[tx_port].len_128_256[i];
		port_info->len_256_512 += port_sw_stat[tx_port].len_256_512[i];
		port_info->len_512_1024 += port_sw_stat[tx_port].len_512_1024[i];
		port_info->len_more_1024 += port_sw_stat[tx_port].len_more_1024[i];
	}
		
	return len;
}

uint32_t sw_dpdk_http_show_fwd(uint32_t portid, SW_DPDK_HTTP_FWD_INFO* fwd_info, char* buf, int buf_len)
{
	uint32_t len = 0;
	if ((sw_enabled_port_mask & (1 << portid)) == 0)
	{
		len += snprintf(buf+len, buf_len-len, "PortID:%u is not enabled, PortMask:0x%x! ", portid, sw_enabled_port_mask);
		return len;
	}

	if ((sw_used_rx_port_mask & (1 << portid)) == 0)
	{
		len += snprintf(buf+len, buf_len-len, "PortID:%u is not rx mode, PortMask:0x%x! ", portid, sw_used_rx_port_mask);
		return len;
	}

	memset(fwd_info, 0, sizeof(SW_DPDK_HTTP_FWD_INFO));

	fwd_info->portid = portid;
	fwd_info->delay_s = sw_port_peer[portid].delay_s;
	fwd_info->loopback = sw_port_peer[portid].loopback;
	fwd_info->filter_len = sw_port_peer_fwd_rules[portid].len_filter_len;
	fwd_info->len_mode = sw_port_peer_fwd_rules[portid].len_filter_mode;
    fwd_info->filter_max_len = sw_port_peer_fwd_rules[portid].max_len_filter_len;
	fwd_info->max_len_mode = sw_port_peer_fwd_rules[portid].max_len_filter_mode;
	fwd_info->syn_mode = sw_port_peer_fwd_rules[portid].syn_filter_mode;
	fwd_info->acl_mode = sw_port_peer_fwd_rules[portid].acl_filter_mode;
	fwd_info->off_mode = sw_port_peer_fwd_rules[portid].offset_filter_mode;
	fwd_info->ipv6_mode = sw_port_peer_fwd_rules[portid].ipv6_filter_mode;
	fwd_info->vlan_mode = sw_port_peer_fwd_rules[portid].vlan_offload_mode;
	fwd_info->mpls_mode = sw_port_peer_fwd_rules[portid].mpls_offload_mode;

	return len;
}

uint32_t sw_dpdk_http_set_fwd(uint32_t portid, SW_DPDK_HTTP_FWD_INFO* fwd_info, char* buf, int buf_len)
{
	uint32_t len = 0;
	if ((sw_enabled_port_mask & (1 << portid)) == 0)
	{
		len += snprintf(buf+len, buf_len-len, "PortID:%u is not enabled, PortMask:0x%0x! ", portid, sw_enabled_port_mask);
		return len;
	}

	if ((sw_used_rx_port_mask & (1 << portid)) == 0)
	{
		len += snprintf(buf+len, buf_len-len, "PortID:%u is not rx mode, PortMask:0x%0x! ", portid, sw_used_rx_port_mask);
		return len;
	}

	uint16_t delay_s = fwd_info->delay_s;
	uint16_t loopback = fwd_info->loopback;
	uint16_t filter_len = fwd_info->filter_len;
	uint16_t len_mode = fwd_info->len_mode;
    uint16_t filter_max_len = fwd_info->filter_max_len;
	uint16_t max_len_mode = fwd_info->max_len_mode;
	uint16_t syn_mode = fwd_info->syn_mode;
	uint16_t acl_mode = fwd_info->acl_mode;
	uint16_t off_mode = fwd_info->off_mode;
	uint16_t ipv6_mode = fwd_info->ipv6_mode;
	uint16_t vlan_mode = fwd_info->vlan_mode;
	uint16_t mpls_mode = fwd_info->mpls_mode;

	if (delay_s > sw_port_delay_init[portid])
	{
		len += snprintf(buf+len, buf_len-len, "PortID:%u Initial Delay is %u seconds! ", portid, sw_port_delay_init[portid]);
		return len;
	}

	if (loopback != 0 && loopback != 1)
	{
		len += snprintf(buf+len, buf_len-len, "loopback : %u  error !", loopback);
		return len;
	}

	if (loopback)
	{
		if (len_mode == SW_FILTER_LEN_RXPORT)
		{
			len += snprintf(buf+len, buf_len-len, "loopback, len-mode should not be 1 ...  ");
			return len;
		}

        if (max_len_mode == SW_FILTER_MAX_LEN_RXPORT)
		{
			len += snprintf(buf+len, buf_len-len, "loopback, max-len-mode should not be 1 ...  ");
			return len;
		}

		if (syn_mode == SW_FILTER_SYN_RXPORT)
		{
			len += snprintf(buf+len, buf_len-len, "loopback, syn-mode should not be 1 ...  ");
			return len;
		}

		if (off_mode == SW_FILTER_OFF_RXPORT)
		{
			len += snprintf(buf+len, buf_len-len, "loopback, offset-mode should not be 1 ...  ");
			return len;
		}

        if (ipv6_mode == SW_FILTER_IP6_RXPORT)
		{
			len += snprintf(buf+len, buf_len-len, "loopback, ipv6-mode should not be 1 ...  ");
			return len;
		}
	}

	if (filter_len < SW_DPDK_PKT_LEN_MIN || SW_DPDK_PKT_LEN_MAX < filter_len)
	{
		len += snprintf(buf+len, buf_len-len, "len : %u  error, must in [%d-%d] !", filter_len, SW_DPDK_PKT_LEN_MIN, SW_DPDK_PKT_LEN_MAX);
		return len;
	}

	if ( SW_FILTER_LEN_DROP < len_mode)
	{
		len += snprintf(buf+len, buf_len-len, "len-mode : %u  error !", len_mode);
		return len;
	}

    if (filter_max_len < SW_DPDK_PKT_LEN_MIN || SW_DPDK_PKT_LEN_MAX < filter_max_len)
	{
		len += snprintf(buf+len, buf_len-len, "max-len : %u  error, must in [%d-%d] !", filter_max_len, SW_DPDK_PKT_LEN_MIN, SW_DPDK_PKT_LEN_MAX);
		return len;
	}

	if ( SW_FILTER_MAX_LEN_DROP < max_len_mode)
	{
		len += snprintf(buf+len, buf_len-len, "max-len-mode : %u  error !", max_len_mode);
		return len;
	}

	if (SW_FILTER_SYN_DROP < syn_mode)
	{
		len += snprintf(buf+len, buf_len-len, "syn-mode : %u  error !", syn_mode);
		return len;
	}

	if (SW_FILTER_ACL_DROP < acl_mode)
	{
		len += snprintf(buf+len, buf_len-len, "acl-mode : %u  error !", acl_mode);
		return len;
	}
	
	if (SW_FILTER_OFF_DROP < off_mode)
	{
		len += snprintf(buf+len, buf_len-len, "off-mode : %u  error !", off_mode);
		return len;
	}
	if (SW_FILTER_IP6_DROP < ipv6_mode)
	{
		len += snprintf(buf+len, buf_len-len, "ipv6-mode : %u  error !", ipv6_mode);
		return len;
	}

	//update , maybe need to lock
	pthread_rwlock_wrlock(&sw_config_rwlock[portid]);//请求写锁
	
	uint32_t tx_port = sw_port_peer[portid].tx_port;
	sw_port_peer[portid].loopback = loopback;
	sw_port_peer[portid].delay_s = delay_s;
	sw_port_peer[tx_port].loopback = loopback;
	sw_port_peer[tx_port].delay_s = delay_s;
	
	sw_port_peer_fwd_rules[portid].len_filter_len = filter_len;
	sw_port_peer_fwd_rules[portid].len_filter_mode = len_mode;
    sw_port_peer_fwd_rules[portid].max_len_filter_len = filter_max_len;
	sw_port_peer_fwd_rules[portid].max_len_filter_mode = max_len_mode;
	sw_port_peer_fwd_rules[portid].syn_filter_mode = syn_mode;
	sw_port_peer_fwd_rules[portid].acl_filter_mode = acl_mode;
	sw_port_peer_fwd_rules[portid].offset_filter_mode = off_mode;
	sw_port_peer_fwd_rules[portid].ipv6_filter_mode = ipv6_mode;
	sw_port_peer_fwd_rules[portid].vlan_offload_mode = vlan_mode;
	sw_port_peer_fwd_rules[portid].mpls_offload_mode = mpls_mode;

	uint32_t i = 0;
	sw_port_need_update_rx[portid] = 1;
	for (; i < sw_port_peer[portid].tx_core_num; i++)
		sw_port_need_update_tx[tx_port][i] = 1;

    //更新加速配置
    unsigned short rx_port = portid;
    if (sw_port_peer_fwd_rules[rx_port].len_filter_mode == SW_FILTER_LEN_RXPORT)
		sw_len_filter_tx_port[rx_port] = rx_port;
	else if (sw_port_peer_fwd_rules[rx_port].len_filter_mode == SW_FILTER_LEN_TXPORT)
		sw_len_filter_tx_port[rx_port] = tx_port;
    else if (sw_port_peer_fwd_rules[rx_port].len_filter_mode == SW_FILTER_LEN_DROP)
		sw_len_filter_tx_port[rx_port] = SW_DPDK_DROP_PORT;

    if (sw_port_peer_fwd_rules[rx_port].max_len_filter_mode == SW_FILTER_MAX_LEN_RXPORT)
		sw_max_len_filter_tx_port[rx_port] = rx_port;
	else if (sw_port_peer_fwd_rules[rx_port].max_len_filter_mode == SW_FILTER_MAX_LEN_TXPORT)
		sw_max_len_filter_tx_port[rx_port] = tx_port;
    else if (sw_port_peer_fwd_rules[rx_port].max_len_filter_mode == SW_FILTER_MAX_LEN_DROP)
		sw_max_len_filter_tx_port[rx_port] = SW_DPDK_DROP_PORT;
	
	if (sw_port_peer_fwd_rules[rx_port].syn_filter_mode == SW_FILTER_SYN_RXPORT)
		sw_syn_filter_tx_port[rx_port] = rx_port;
	else if (sw_port_peer_fwd_rules[rx_port].syn_filter_mode == SW_FILTER_SYN_TXPORT)
		sw_syn_filter_tx_port[rx_port] = tx_port;
    else if (sw_port_peer_fwd_rules[rx_port].syn_filter_mode == SW_FILTER_SYN_DROP)
		sw_syn_filter_tx_port[rx_port] = SW_DPDK_DROP_PORT;

	if (sw_port_peer_fwd_rules[rx_port].acl_filter_mode == SW_FILTER_ACL_RXPORT)
		sw_acl_filter_tx_port[rx_port] = rx_port;
	else if (sw_port_peer_fwd_rules[rx_port].acl_filter_mode == SW_FILTER_ACL_TXPORT)
		sw_acl_filter_tx_port[rx_port] = tx_port;
    else if (sw_port_peer_fwd_rules[rx_port].acl_filter_mode == SW_FILTER_ACL_DROP)
		sw_acl_filter_tx_port[rx_port] = SW_DPDK_DROP_PORT;

	if (sw_port_peer_fwd_rules[rx_port].offset_filter_mode == SW_FILTER_OFF_RXPORT)
		sw_offset_filter_tx_port[rx_port] = rx_port;
	else if (sw_port_peer_fwd_rules[rx_port].offset_filter_mode == SW_FILTER_OFF_TXPORT)
		sw_offset_filter_tx_port[rx_port] = tx_port;
    else if (sw_port_peer_fwd_rules[rx_port].offset_filter_mode == SW_FILTER_OFF_DROP)
		sw_offset_filter_tx_port[rx_port] = SW_DPDK_DROP_PORT;

    if (sw_port_peer_fwd_rules[rx_port].ipv6_filter_mode == SW_FILTER_IP6_RXPORT)
		sw_ip6_filter_tx_port[rx_port] = rx_port;
	else if (sw_port_peer_fwd_rules[rx_port].ipv6_filter_mode == SW_FILTER_IP6_TXPORT)
		sw_ip6_filter_tx_port[rx_port] = tx_port;
    else if (sw_port_peer_fwd_rules[rx_port].ipv6_filter_mode == SW_FILTER_IP6_DROP)
		sw_ip6_filter_tx_port[rx_port] = SW_DPDK_DROP_PORT;

    pthread_rwlock_wrlock(&sw_config_rwlock[portid]);//释放写锁

    SW_DPDK_Log_Info("HTTP Start to update conf rxport:%d len-port:%d max-len-port:%d syn-port:%d acl-port:%d off-port:%d ipv6-port:%d ... \n", rx_port,
                    sw_len_filter_tx_port[rx_port], sw_max_len_filter_tx_port[rx_port], sw_syn_filter_tx_port[rx_port],
                    sw_acl_filter_tx_port[rx_port], sw_offset_filter_tx_port[rx_port], sw_ip6_filter_tx_port[rx_port]);
		
	return len;
}



