//@20180603 vSwitch http rest api by Shawn.Z
#include <sstream>
#include <cstdlib>
#include <unistd.h>
#include "simple_log.h"
#include "http_server.h"
#include "threadpool.h"
#include "sw_httpserver.h"

#include "sw_filter.h"
#include "sw_offset.h"
#include "sw_dpdk.h"

using namespace std;

static int sw_http_port = 22334;
static char* sw_http_offset_rules[SW_OFFSET_MAX_NUM];
static char* sw_http_filter_rules[SW_OFFSET_MAX_NUM];

static int malloc_offset_rule(void)
{
	int i = 0;
	for (; i < SW_OFFSET_MAX_NUM; i++)
	{
		sw_http_offset_rules[i] = (char *)malloc(SW_OFFSET_SHOW_RULE_LEN);
		if (NULL == sw_http_offset_rules[i])
			return -1;
	}

	return 0;
}

static void memset_offset_rule(void)
{
	int i = 0;
	for (; i < SW_OFFSET_MAX_NUM; i++)
		memset(sw_http_offset_rules[i], 0, SW_OFFSET_SHOW_RULE_LEN);
}

static int malloc_filter_rule(void)
{
	int i = 0;
	for (; i < MAX_ACL_RULE_NUM; i++)
	{
		sw_http_filter_rules[i] = (char *)malloc(SW_FILTER_SHOW_RULE_LEN);
		if (NULL == sw_http_filter_rules[i])
			return -1;
	}

	return 0;
}

static void memset_filter_rule(void)
{
	int i = 0;
	for (; i < MAX_ACL_RULE_NUM; i++)
		memset(sw_http_filter_rules[i], 0, SW_FILTER_SHOW_RULE_LEN);
}


void show_offset_rule(Request &request, Json::Value &root)
{
	std::string port_s = request.get_param("port");
	std::string type_s = request.get_param("type");

	if ("" == port_s)
	{
		root["error"] = "port Not Defined !";
		return;
	}

	if ("" == type_s)
	{
		root["error"] = "type Not Defined !";
		return;
	}

	int port = atoi(port_s.c_str());
	int type = atoi(type_s.c_str());

	int rule_num = 0;
	char _error[128] = {0};
	memset_offset_rule();
	uint32_t ret = sw_offset_show_rules(port, type, sw_http_offset_rules, &rule_num, _error, sizeof(_error));
	if (0 != ret)//error
	{
		root["error"] = _error;
		return;
	}

	int i;
	for (i = 0; i < rule_num; i++)
	{
		root["rules"][i] = sw_http_offset_rules[i];
	}	
}

void add_offset_rule(Request &request, Json::Value &root) {
	std::string rule_s = request.get_param("rule");
	if ("" == rule_s)
	{
		root["error"] = "rule Not Defined !";
		return;
	}

	char _error[128] = {0};
	uint32_t ret = sw_offset_dynamic_add_rules((char *)rule_s.c_str(), _error, sizeof(_error));
	if (0 != ret)//error
	{
		root["error"] = _error;
		return;
	}

	root["ret"] = "ok";	
}

void del_offset_rule(Request &request, Json::Value &root) {
	std::string port_s = request.get_param("port");
	std::string type_s = request.get_param("type");
	std::string ruleid_s = request.get_param("ruleid");

	if ("" == port_s)
	{
		root["error"] = "port Not Defined !";
		return;
	}

	if ("" == type_s)
	{
		root["error"] = "type Not Defined !";
		return;
	}

	if ("" == ruleid_s)
	{
		root["error"] = "ruleid Not Defined !";
		return;
	}
	
	int port = atoi(port_s.c_str());
	int type = atoi(type_s.c_str());
	int ruleid = atoi(ruleid_s.c_str());

	char _error[128] = {0};
	uint32_t ret = sw_offset_dynamic_del_rule(port, type, ruleid, _error, sizeof(_error));
	if (0 != ret)//error
	{
		root["error"] = _error;
		return;
	}

	root["ret"] = "ok";		
}

void show_filter_rule(Request &request, Json::Value &root)
{
	std::string port_s = request.get_param("port");
	if ("" == port_s)
	{
		root["error"] = "port Not Defined !";
		return;
	}

	uint32_t port = atoi(port_s.c_str());
	
	uint32_t rule_num = 0;
	char _error[128] = {0};
	memset_filter_rule();
	uint32_t ret = sw_filter_http_show_rules(port, sw_http_filter_rules, &rule_num, _error, sizeof(_error));
	if (0 != ret)//error
	{
		root["error"] = _error;
		return;
	}

	uint32_t i;
	for (i = 0; i < rule_num; i++)
	{
		root["rules"][i] = sw_http_filter_rules[i];
	}	
}

void add_filter_rule(Request &request, Json::Value &root) {
	std::string rule_s = request.get_param("rule");
	if ("" == rule_s)
	{
		root["error"] = "rule Not Defined !";
		return;
	}

	char _error[128] = {0};
	uint32_t ret = sw_filter_dynamic_add_rules((char *)rule_s.c_str(), _error, sizeof(_error));
	if (0 != ret)//error
	{
		root["error"] = _error;
		return;
	}

	root["ret"] = "ok";	
}

void del_filter_rule(Request &request, Json::Value &root) {
	std::string port_s = request.get_param("port");
	std::string ruleid_s = request.get_param("ruleid");

	if ("" == port_s)
	{
		root["error"] = "port Not Defined !";
		return;
	}

	if ("" == ruleid_s)
	{
		root["error"] = "ruleid Not Defined !";
		return;
	}
	
	int port = atoi(port_s.c_str());
	int ruleid = atoi(ruleid_s.c_str());

	char _error[128] = {0};
	uint32_t ret = sw_filter_dynamic_del_rule(port, ruleid, _error, sizeof(_error));
	if (0 != ret)//error
	{
		root["error"] = _error;
		return;
	}

	root["ret"] = "ok";		
}


void show_port_info(Request &request, Json::Value &root) 
{
	std::string port_s = request.get_param("port");

	if ("" == port_s)
	{
		root["error"] = "port Not Defined !";
		return;
	}

	char _error[128] = {0};
	uint32_t port = atoi(port_s.c_str());
	SW_DPDK_HTTP_PORT_INFO port_info = {0};
	uint32_t ret = sw_dpdk_http_show_port(port, &port_info, _error, sizeof(_error));
	if (0 != ret)//error
	{
		root["error"] = _error;
		return;
	}

	root["portid"] = port_info.portid;
	root["running_sec"] = port_info.running_sec;
	if (SW_PORT_RX == port_info.mode)
		root["mode"] = "RX Mode";
	else
		root["mode"] = "TX Mode";
	root["peer_port"] = port_info.peer_port;
	root["tx"] = (double)port_info.tx;
	root["rx"] = (double)port_info.rx;
	root["rx_bytes"] = (double)port_info.rx_bytes;
	root["tx_bytes"] = (double)port_info.tx_bytes;
	root["rx_pps"] = (double)port_info.rx_pps;
	root["tx_pps"] = (double)port_info.tx_pps;
	root["rx_bps"] = (double)port_info.rx_bps;
	root["tx_bps"] = (double)port_info.tx_bps;
	root["filter_len"] = (double)port_info.filter_len;
	root["filter_acl"] = (double)port_info.filter_acl;
	root["filter_offset"] = (double)port_info.filter_offset;
	root["filter_syn"] = (double)port_info.filter_syn;
	root["vlan_pkts"] = (double)port_info.vlan_pkts;
	root["mpls_pkts"] = (double)port_info.mpls_pkts;
	root["ipv4_pkts"] = (double)port_info.ipv4_pkts;
	root["icmp_pkts"] = (double)port_info.icmp_pkts;
	root["tcp_pkts"] = (double)port_info.tcp_pkts;
	root["udp_pkts"] = (double)port_info.udp_pkts;
	root["len_less_128"] = (double)port_info.len_less_128;
	root["len_128_256"] = (double)port_info.len_128_256;
	root["len_256_512"] = (double)port_info.len_256_512;
	root["len_512_1024"] = (double)port_info.len_512_1024;
	root["len_more_1024"] = (double)port_info.len_more_1024;
}

void show_fwd_rule(Request &request, Json::Value &root) 
{
	std::string port_s = request.get_param("port");

	if ("" == port_s)
	{
		root["error"] = "port Not Defined !";
		return;
	}

	char _error[128] = {0};
	uint32_t port = atoi(port_s.c_str());
	SW_DPDK_HTTP_FWD_INFO fwd_info = {0};
	uint32_t ret = sw_dpdk_http_show_fwd(port, &fwd_info, _error, sizeof(_error));
	if (0 != ret)//error
	{
		root["error"] = _error;
		return;
	}

	root["port"] = fwd_info.portid;
	root["delay"] = fwd_info.delay_s;
	root["loopback"] = fwd_info.loopback;
	root["filter_len"] = fwd_info.filter_len;
	root["len_mode"] = fwd_info.len_mode;
	root["syn_mode"] = fwd_info.syn_mode;
	root["acl_mode"] = fwd_info.acl_mode;
	root["off_mode"] = fwd_info.off_mode;
}

void set_fwd_rule(Request &request, Json::Value &root) 
{
	std::string port_s = request.get_param("port");
	std::string delay_s = request.get_param("delay");
	std::string loopback_s = request.get_param("loopback");
	std::string filter_len_s = request.get_param("filter_len");
	std::string len_mode_s = request.get_param("len_mode");
	std::string syn_mode_s = request.get_param("syn_mode");
	std::string acl_mode_s = request.get_param("acl_mode");
	std::string off_mode_s = request.get_param("off_mode");

	if ("" == port_s)
	{
		root["error"] = "port Not Defined !";
		return;
	}
	if ("" == delay_s)
	{
		root["error"] = "delay Not Defined !";
		return;
	}
	if ("" == loopback_s)
	{
		root["error"] = "loopback Not Defined !";
		return;
	}
	if ("" == filter_len_s)
	{
		root["error"] = "filter_len Not Defined !";
		return;
	}
	if ("" == len_mode_s)
	{
		root["error"] = "len_mode Not Defined !";
		return;
	}
	if ("" == syn_mode_s)
	{
		root["error"] = "syn_mode Not Defined !";
		return;
	}
	if ("" == acl_mode_s)
	{
		root["error"] = "acl_mode Not Defined !";
		return;
	}
	if ("" == off_mode_s)
	{
		root["error"] = "off_mode Not Defined !";
		return;
	}

	char _error[128] = {0};
	uint32_t port = atoi(port_s.c_str());
	SW_DPDK_HTTP_FWD_INFO fwd_info = {0};
	fwd_info.portid = port;
	fwd_info.delay_s = atoi(delay_s.c_str());
	fwd_info.loopback = atoi(loopback_s.c_str());
	fwd_info.filter_len = atoi(filter_len_s.c_str());
	fwd_info.len_mode = atoi(len_mode_s.c_str());
	fwd_info.syn_mode = atoi(syn_mode_s.c_str());
	fwd_info.acl_mode = atoi(acl_mode_s.c_str());
	fwd_info.off_mode = atoi(off_mode_s.c_str());
	uint32_t ret = sw_dpdk_http_set_fwd(port, &fwd_info, _error, sizeof(_error));
	if (0 != ret)//error
	{
		root["error"] = _error;
		return;
	}

	root["ret"] = "ok";
}

static void* sw_httpserver_start(void* arg)
{
	HttpServer http_server;

	//GET

	//offset
	//http://192.168.110.131:22334/show_offset_rule?port=0&type=4
    http_server.add_mapping("/show_offset_rule", show_offset_rule);
	http_server.add_mapping("/add_offset_rule", add_offset_rule);
	http_server.add_mapping("/del_offset_rule", del_offset_rule);

	//filter
	http_server.add_mapping("/show_acl_rule", show_filter_rule);
	http_server.add_mapping("/add_acl_rule", add_filter_rule);
	http_server.add_mapping("/del_acl_rule", del_filter_rule);
	
	//port & fwd
	http_server.add_mapping("/show_port_info", show_port_info);
	http_server.add_mapping("/show_fwd_rule", show_fwd_rule);
	http_server.add_mapping("/set_fwd_rule", set_fwd_rule);
	
    http_server.add_bind_ip("0.0.0.0");
    http_server.set_port(sw_http_port);
    http_server.set_backlog(10);
    http_server.set_max_events(10);
    http_server.start_async();
	http_server.join();

	return NULL;
}

int sw_httpserver_init(int listen_port) {
    int ret = log_init("../conf/httpserver/", "http_log.conf");
    if (ret != 0) {
        printf("log init error!");
        return -1;
    }

	if (0 > malloc_offset_rule())
	{
		printf("malloc_offset_rule error!");
        return -1;
	}

	if (0 > malloc_filter_rule())
	{
		printf("malloc_filter_rule error!");
        return -1;
	}

	sw_http_port = listen_port;

	pthread_t threadid;
	if (0 != pthread_create(&threadid, NULL, sw_httpserver_start, NULL))
	{
		printf("create sw_httpserver_start error!\n");
		return -1;
	}

	return 0;
}


