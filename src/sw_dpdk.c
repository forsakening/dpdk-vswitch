//@20180408 by Shawn.Z
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

#define RTE_LOGTYPE_VSWITCH RTE_LOGTYPE_USER1

#define SW_DPDK_MAX_PORT 24
#define SW_DPDK_MAX_DELAY 10
//#define SW_DPDK_MAX_MBUF_NUM (2^27 - 1)
#define SW_DPDK_MAX_MBUF_NUM 8192

static volatile bool force_quit = false;

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define MEMPOOL_CACHE_SIZE 256

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/* ethernet addresses of ports */
static struct ether_addr sw_ports_eth_addr[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
static uint32_t sw_enabled_port_mask = 0;

static volatile bool start_work = false; 

typedef enum
{
	MODE_NONE = 0,
	MODE_RX = 1,
	MODE_TX = 2
}PORT_MODE;

struct sw_port_conf {
	uint16_t  coreid;
	uint16_t  delay_s;
	PORT_MODE portmode;
	struct rte_ring* rx_ring;
	struct rte_ring* tx_ring;
} __rte_cache_aligned;
struct sw_port_conf sw_port_conf[SW_DPDK_MAX_PORT] = {{0}};

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.split_hdr_size = 0,
		.ignore_offload_bitfield = 1,
		.offloads = DEV_RX_OFFLOAD_CRC_STRIP,
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

struct rte_mempool * pktmbuf_pool[SW_DPDK_MAX_PORT] = {0};

/* Per-port statistics struct */
struct l2fwd_port_statistics {
	uint64_t tx;
	uint64_t rx;
	uint64_t dropped;
} __rte_cache_aligned;
struct l2fwd_port_statistics port_statistics[RTE_MAX_ETHPORTS];

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
} __rte_cache_aligned;;
struct sw_dpdk_port_hw_stat port_hw_stat[SW_DPDK_MAX_PORT] = {{0}};

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
    	if ((sw_enabled_port_mask & (1 << port_id)) == 0)
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

static int sw_dpdk_kill_self(char* buf, int buf_len)
{
	int len = 0;
	printf("Start to kill myself ...\n");
	len += snprintf(buf, buf_len-len,"Kill Success ...\n");
	force_quit = true;

	return len;
}

static int sw_dpdk_port_stat(uint16_t portid, char* buf, int buf_len)
{
	int len = 0;
	if ((sw_enabled_port_mask & (1 << portid)) == 0)
	{
		len += snprintf(buf+len, buf_len-len, "PortID:%u is not enabled, PortMask:%d!\n", portid, sw_enabled_port_mask);
		return len;
	}

	if (sw_port_conf[portid].portmode == MODE_RX)
	{
		len += snprintf(buf+len, buf_len-len, "========Memory:\n");
		struct rte_mempool* pmempool = NULL;
		pmempool = pktmbuf_pool[portid];
		if (NULL != pmempool)
		{
			len += snprintf(buf+len, buf_len-len, "Buff[%s]: count %d, size %d, available %u, alloc %u\n", 
			        pmempool->name,
			        pmempool->size,
			        pmempool->elt_size,
			        rte_mempool_avail_count(pmempool),
			        rte_mempool_in_use_count(pmempool));
		}

		struct rte_ring* pring = NULL;
		if (NULL != sw_port_conf[portid].rx_ring)
		{
			pring = sw_port_conf[portid].rx_ring;
			len += snprintf(buf+len, buf_len-len, "Ring[%s]: count %d, available %u, alloc %u\n", 
			        pring->name,
			        pring->size,
			        rte_ring_free_count(pring),
			        rte_ring_count(pring));
		}		
	}

	struct rte_eth_stats stats;
	rte_eth_stats_get(portid, &stats);

	len += snprintf(buf+len, buf_len-len, "  RX-packets: %-12"PRIu64" RX-bytes:  %-12"PRIu64"\n", stats.ipackets,stats.ibytes);
    len += snprintf(buf+len, buf_len-len, "  RX-error  : %-12"PRIu64"     Reason:[CRC or BadLen Error By Packet]\n",  stats.ierrors);
	len += snprintf(buf+len, buf_len-len, "  RX-nombuf : %-12"PRIu64"     Reason:[Mempool Not Enough, Not Equal To Packet Num]\n", stats.rx_nombuf);
    len += snprintf(buf+len, buf_len-len, "  RX-missed : %-12"PRIu64"     Reason:[Fwd Thread Been Scheduled or Enque Nic Que Error Happen]\n", stats.imissed);
	len += snprintf(buf+len, buf_len-len, "  TX-packets: %-12"PRIu64" TX-errors: %-12"PRIu64" TX-bytes:  "
		   "%-"PRIu64"\n",
		   stats.opackets, stats.oerrors, stats.obytes);
	len += snprintf(buf+len, buf_len-len, "  TX-dropped:  %-12"PRIu64"\n", port_hw_stat[portid].dropped);
	len += snprintf(buf+len, buf_len-len, "  RX-pps:	  %-12"PRIu64" TX-pps:	  %-12"PRIu64"\n",port_hw_stat[portid].rx_pps,port_hw_stat[portid].tx_pps);
	len += snprintf(buf+len, buf_len-len, "  RX-bps:	  %-12"PRIu64" TX-bps:	  %-12"PRIu64"\n",port_hw_stat[portid].rx_bps,port_hw_stat[portid].tx_bps);
	len += snprintf(buf+len, buf_len-len, "  RX-pps-total:	  %-12"PRIu64" TX-pps-total:	  %-12"PRIu64"\n",\
                port_hw_stat[portid].rx_pps_total, port_hw_stat[portid].tx_pps_total);
	
	return len;
}

static void
sw_dpdk_tx_pkts(uint16_t port_id, uint16_t queue_id,
		 struct rte_mbuf **pkts_burst, uint16_t pkt_num)
{
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
}

/* main processing loop */
static void
sw_dpdk_main_loop(void)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *m;
	int ret;
	unsigned lcore_id;
	unsigned i, nb_rx;
	uint64_t timeout_tsc, cur_tsc;
	struct sw_port_conf *qconf;
	uint64_t timer_1s_hz = rte_get_timer_hz();

	lcore_id = rte_lcore_id();
	if (0 == lcore_id)
		return ;
	
	for (i = 0 ; i < SW_DPDK_MAX_PORT; i++)
	{
		if (sw_port_conf[i].coreid == lcore_id)
		{
			qconf = &sw_port_conf[i];
			break;
		}
	}

	if (i >= SW_DPDK_MAX_PORT)
	{
		RTE_LOG(INFO, VSWITCH, "lcore %u has nothing to do \n", lcore_id);
		return;
	}

	uint16_t portid = i;
	int delay = qconf->delay_s;
	int rx_mode = qconf->portmode & MODE_RX;
	int tx_mode = qconf->portmode & MODE_TX;
	struct rte_ring* rx_ring = qconf->rx_ring;
	struct rte_ring* tx_ring = qconf->tx_ring;
	
	if (rx_mode && tx_mode) {
		RTE_LOG(INFO, VSWITCH, "lcore %u has nothing to do, portid:%d \n", \
				lcore_id, portid);
		return;
	}

	RTE_LOG(INFO, VSWITCH, "entering main loop on lcore %u, rxmode:%d, txmode:%d\n", lcore_id, rx_mode, tx_mode);

	while (!force_quit) {

		cur_tsc = rte_rdtsc();

		if (rx_mode)
		{
			nb_rx = rte_eth_rx_burst(portid, 0, pkts_burst, MAX_PKT_BURST);
			if (nb_rx <= 0) 
				continue;

			//时间戳
			timeout_tsc = cur_tsc + timer_1s_hz * delay;
			for (i = 0; i < nb_rx; i++)
			{
				m = pkts_burst[i];
				m->timestamp = timeout_tsc;
				//printf("Time:%18"PRIu64"Recv A pkt,timeout:%18"PRIu64"\n", cur_tsc, m->timestamp);
			}
			
			port_statistics[portid].rx += nb_rx;
			ret = rte_ring_enqueue_bulk(rx_ring, (void **)pkts_burst, nb_rx, NULL);
			if (0 == ret)
			{
				for (i = 0; i < nb_rx; i++)
					rte_pktmbuf_free(pkts_burst[i]);

				port_statistics[portid].dropped += nb_rx;
			} 			
		}
		
		if (tx_mode)
		{
			ret = rte_ring_dequeue(tx_ring, (void **)&m);
			if (ret != 0)
			{
				continue;
			}
			else
			{
				do
				{
					if (cur_tsc >= m->timestamp)
					{
						//printf("Time:%18"PRIu64"Forward A pkt,timeout:%18"PRIu64"\n", cur_tsc,m->timestamp);
						sw_dpdk_tx_pkts(portid, 0, &m, 1);
						port_statistics[portid].tx += 1;
						break;
					}
					else
					{
						//rte_delay_us_block(1);
						usleep(5);
						cur_tsc = rte_rdtsc();
					}
				}while (1);
			}
		}
	}
}

static int
sw_dpdk_launch_one_lcore(__attribute__((unused)) void *dummy)
{
	sw_dpdk_main_loop();
	return 0;
}

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

int sw_dpdk_init(void)
{
	int ret;
	uint16_t nb_ports;
	uint16_t portid;
	unsigned lcore_id;
	unsigned int nb_mbufs;

	//signal
	force_quit = false;
	signal(SIGINT, sw_dpdk_signal_handler);
	signal(SIGTERM, sw_dpdk_signal_handler);

	/* init EAL */
	int argc = 0;
    char argvstr[64][32] = {{0}};
    char* argv[64] = {0};

	strcpy(argvstr[argc], "vswitch"); argv[argc] = argvstr[argc]; argc++;
    strcpy(argvstr[argc], "-l"); argv[argc] = argvstr[argc]; argc++;
    strcpy(argvstr[argc], "1-2"); argv[argc] = argvstr[argc]; argc++;
    strcpy(argvstr[argc], "-n"); argv[argc] = argvstr[argc]; argc++;
    strcpy(argvstr[argc], "4"); argv[argc] = argvstr[argc]; argc++;
	//strcpy(argvstr[argc], "--master-lcore"); argv[argc] = argvstr[argc]; argc++;
	//strcpy(argvstr[argc], "0"); argv[argc] = argvstr[argc]; argc++;
	
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");

	nb_ports = rte_eth_dev_count();

	//just for 2 ports @20180408
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");
	else if (nb_ports != 2)
		rte_exit(EXIT_FAILURE, "Ethernet ports Not 2 - bye\n");
	
	sw_port_conf[0].portmode = MODE_RX;
	sw_port_conf[0].coreid = 1;
	sw_port_conf[0].delay_s = 5;

	sw_port_conf[1].portmode = MODE_TX;
	sw_port_conf[1].coreid = 2;
	sw_port_conf[1].delay_s = 5;

	nb_mbufs = SW_DPDK_MAX_MBUF_NUM;

	for (portid = 0; portid < nb_ports; portid++)
	{
		if (sw_port_conf[portid].portmode == MODE_RX)
		{
			char mbuf_name[32] = {0};
			sprintf(mbuf_name, "mbuf_pool_%d", portid);
			pktmbuf_pool[portid] = rte_pktmbuf_pool_create(mbuf_name, nb_mbufs, MEMPOOL_CACHE_SIZE, 0, 
						RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

			if (pktmbuf_pool[portid] == NULL)
				rte_exit(EXIT_FAILURE, "Cannot init mbuf pool, portid = %d\n", portid);

			char rx_ring_name[32] = {0};
			sprintf(rx_ring_name, "rx_ring_%d", portid);
			sw_port_conf[portid].rx_ring = rte_ring_create(rx_ring_name, nb_mbufs, rte_socket_id(), 0);
			if (NULL == sw_port_conf[portid].rx_ring)
				rte_exit(EXIT_FAILURE, "Cannot init rx_ring, portid = %d\n", portid);
			
			printf("PortId:%d Rx mode, init buf ok!\n", portid);
		}
	}

	sw_port_conf[1].tx_ring = sw_port_conf[0].rx_ring;
	
	/* Initialise each port */
	for (portid = 0; portid < nb_ports; portid++) {
		struct rte_eth_rxconf rxq_conf;
		struct rte_eth_txconf txq_conf;
		struct rte_eth_conf local_port_conf = port_conf;
		struct rte_eth_dev_info dev_info;

		/* init port */
		printf("Initializing port %u... ", portid);
		fflush(stdout);
		rte_eth_dev_info_get(portid, &dev_info);
		if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf.txmode.offloads |=
				DEV_TX_OFFLOAD_MBUF_FAST_FREE;
		
		rte_eth_macaddr_get(portid, &sw_ports_eth_addr[portid]);

		/* init one RX queue */
		if (sw_port_conf[portid].portmode == MODE_RX)
		{
			ret = rte_eth_dev_configure(portid, 1, 0, &local_port_conf);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
					  ret, portid);

			ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd,
							       &nb_txd);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
					 "Cannot adjust number of descriptors: err=%d, port=%u\n",
					 ret, portid);
		
			fflush(stdout);
			rxq_conf = dev_info.default_rxconf;
			rxq_conf.offloads = local_port_conf.rxmode.offloads;
			ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
						     rte_eth_dev_socket_id(portid),
						     &rxq_conf,
						     pktmbuf_pool[portid]);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
					  ret, portid);
		}

		if (sw_port_conf[portid].portmode == MODE_TX)
		{
			ret = rte_eth_dev_configure(portid, 0, 1, &local_port_conf);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
					  ret, portid);

			ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd,
							       &nb_txd);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
					 "Cannot adjust number of descriptors: err=%d, port=%u\n",
					 ret, portid);
		
			/* init one TX queue on each port */
			fflush(stdout);
			txq_conf = dev_info.default_txconf;
			txq_conf.txq_flags = ETH_TXQ_FLAGS_IGNORE;
			txq_conf.offloads = local_port_conf.txmode.offloads;
			ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
					rte_eth_dev_socket_id(portid),
					&txq_conf);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
					ret, portid);
		}
		
		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
				  ret, portid);

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

		/* initialize port stats */
		memset(&port_statistics[portid], 0, sizeof(port_statistics[portid]));

		//set port mask
		sw_enabled_port_mask |= (1 << portid);
	}

	sw_dpdk_check_all_ports_link_status(nb_ports, sw_enabled_port_mask);

	//初始化统计线程
	pthread_t threadid;
	if (0 != pthread_create(&threadid, NULL, sw_dpdk_calc_statistic_thread, NULL))
	{
		printf("create sw_dpdk_calc_statistic_thread error!\n");
		return -1;
	}

	//初始化命令行
	sw_command_register_kill_self(sw_dpdk_kill_self);
	sw_command_register_show_port(sw_dpdk_port_stat);
	sw_command_init(CMD_ROLE_SERVER);

	//wait 
	ret = 0;
	/* launch per-lcore init on every lcore */
	start_work = true;
	rte_eal_mp_remote_launch(sw_dpdk_launch_one_lcore, NULL, CALL_MASTER);
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}

	for (portid = 0; portid < nb_ports; portid++) {
		if ((sw_enabled_port_mask & (1 << portid)) == 0)
			continue;
		printf("Closing port %d...", portid);
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}
	printf("Bye...\n");

	return ret;
}

