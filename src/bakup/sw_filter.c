#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <inttypes.h>
#include <pthread.h>

//socket 
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
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
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>
#include <rte_acl.h>

#include "sw_dpdk.h"
#include "sw_filter.h"

//#define SW_FILTER_DEBUG 1

#if 0
/* set acl */
struct cmd_set_acl_result {
	cmdline_fixed_string_t acl;
	cmdline_fixed_string_t port;
	uint16_t port_id;
	cmdline_ipaddr_t sip_mask;
	cmdline_ipaddr_t dip_mask;
	cmdline_portlist_t sport_range;
	cmdline_portlist_t dport_range;
	cmdline_fixed_string_t proto;
};

cmdline_parse_token_string_t cmd_set_acl_acl =
	TOKEN_STRING_INITIALIZER
		(struct cmd_set_acl_result,
		 acl, "acl");
cmdline_parse_token_string_t cmd_set_acl_port =
	TOKEN_STRING_INITIALIZER
		(struct cmd_set_acl_result,
		 port, "port");
cmdline_parse_token_num_t cmd_set_acl_portid =
	TOKEN_NUM_INITIALIZER
		(struct cmd_set_acl_result,
		 port_id, UINT16);
cmdline_parse_token_ipaddr_t cmd_set_acl_sip_mask =
	TOKEN_IPV4NET_INITIALIZER
		(struct cmd_set_acl_result, sip_mask);
cmdline_parse_token_ipaddr_t cmd_set_acl_dip_mask =
	TOKEN_IPV4NET_INITIALIZER
 		(struct cmd_set_acl_result, dip_mask);
cmdline_parse_token_portlist_t cmd_set_acl_sport_range =
	TOKEN_PORTLIST_INITIALIZER
		(struct cmd_set_acl_result, sport_range);
cmdline_parse_token_portlist_t cmd_set_acl_dport_range =
	TOKEN_PORTLIST_INITIALIZER
		(struct cmd_set_acl_result, dport_range);
cmdline_parse_token_string_t cmd_set_acl_proto =
	TOKEN_STRING_INITIALIZER
		(struct cmd_set_acl_result,
		 proto, "ip#tcp#udp");

static void
cmd_set_acl_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_set_acl_result* res = parsed_result;

	int len = 0;
	char buf[SW_CMD_BUFF_LEN] = {0};
	sw_command_client_send_and_recv(SW_CMD_TYPE_SET_ACL, res, 
									sizeof(struct cmd_set_acl_result), 
									buf, SW_CMD_BUFF_LEN, &len, SW_CMD_TIMEOUT);

	printf("%s\n", buf);
}


cmdline_parse_inst_t cmd_set_acl = {
	.f = cmd_set_acl_parsed,
	.data = NULL,
	.help_str = "acl port <port_id> sip/mask dip/mask sport-range dport-range ip/tcp/udp",
	.tokens = {
		(void *)&cmd_set_acl_acl,
		(void *)&cmd_set_acl_port,
		(void *)&cmd_set_acl_portid,
		(void *)&cmd_set_acl_sip_mask,
		(void *)&cmd_set_acl_dip_mask,
		(void *)&cmd_set_acl_sport_range,
		(void *)&cmd_set_acl_dport_range,
		(void *)&cmd_set_acl_proto,
		NULL,
	},
};

/***********************start of ACL part******************************/
enum {
	PROTO_FIELD_IPV4,
	SRC_FIELD_IPV4,
	DST_FIELD_IPV4,
	SRCP_FIELD_IPV4,
	DSTP_FIELD_IPV4,
	NUM_FIELDS_IPV4
};

struct rte_acl_field_def sw_filter_ipv4_defs[NUM_FIELDS_IPV4] = {
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof(uint8_t),
		.field_index = PROTO_FIELD_IPV4,
		.input_index = RTE_ACL_IPV4VLAN_PROTO,
		.offset = 0,
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = SRC_FIELD_IPV4,
		.input_index = RTE_ACL_IPV4VLAN_SRC,
		.offset = offsetof(struct ipv4_hdr, src_addr) -
			offsetof(struct ipv4_hdr, next_proto_id),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST_FIELD_IPV4,
		.input_index = RTE_ACL_IPV4VLAN_DST,
		.offset = offsetof(struct ipv4_hdr, dst_addr) -
			offsetof(struct ipv4_hdr, next_proto_id),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint16_t),
		.field_index = SRCP_FIELD_IPV4,
		.input_index = RTE_ACL_IPV4VLAN_PORTS,
		.offset = sizeof(struct ipv4_hdr) -
			offsetof(struct ipv4_hdr, next_proto_id),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint16_t),
		.field_index = DSTP_FIELD_IPV4,
		.input_index = RTE_ACL_IPV4VLAN_PORTS,
		.offset = sizeof(struct ipv4_hdr) -
			offsetof(struct ipv4_hdr, next_proto_id) +
			sizeof(uint16_t),
	},
};

enum {
	SW_FILTER_ACL_INUSE = 0,
	SW_FILTER_ACL_TMP,
	SW_FILTER_ACL_ROLENUM
};

static struct rte_acl_ctx *sw_acl_context[SW_DPDK_MAX_PORT][SW_FILTER_ACL_ROLENUM] = {0};

static int sw_filter_acl_init(uint16_t port_id)
{
	//创建port的主备acl ctx
	int i = 0;
	for (; i < SW_FILTER_ACL_ROLENUM; i++)
	{
		char name[32] = {0};
		snprintf(name, sizeof(name), SW_FILTER_ACL_NAME"%02u-%s", port_id, i==SW_FILTER_ACL_INUSE ? "inuse" : "temp");
		struct rte_acl_param acl_param;
		acl_param.name = name;
		acl_param.socket_id = -1; // to do
		acl_param.rule_size = RTE_ACL_RULE_SZ(RTE_DIM(sw_filter_ipv4_defs));
		acl_param.max_rule_num = SW_FILTER_ACL_NUM;

		if ((sw_acl_context[port_id][i] = rte_acl_create(&acl_param)) == NULL)
		{
			SW_FILTER_Log_Error("Create acl error,port id:%u role:%s!\n", port_id, i==SW_FILTER_ACL_INUSE ? "inuse" : "temp");
			return -1;
		}

		if (0 != rte_acl_set_ctx_classify(sw_acl_context[port_id][i], RTE_ACL_CLASSIFY_SCALAR))
		{
			SW_FILTER_Log_Error("Set acl classify error,port id:%u role:%s!\n", port_id, i==SW_FILTER_ACL_INUSE ? "inuse" : "temp");
			return -1;
		}
	}	
}

/***********************end of ACL part******************************/

static int sw_filter_handle(void* cmd, char* buf, int buf_len)
{
	int len = 0;
	struct cmd_set_acl_result *acl_cmd = (struct cmd_set_acl_result *)cmd;
	//check cmd	
	uint16_t portid = acl_cmd->port_id;
	uint32_t port_mask = sw_dpdk_enabled_port_mask();
	if ((port_mask & (1 << portid)) == 0)
	{
		len += snprintf(buf+len, buf_len-len, "PortID:%u is not enabled, PortMask:%u!\n", portid, port_mask);
		return len;
	}

	cmdline_ipaddr_t sip_mask = acl_cmd->sip_mask;
	
	len += snprintf(buf+len, buf_len-len,"\n");

	return len;
}
#endif

/***********************start of ACL part******************************/
#define MAX_ACL_RULE_NUM	10000
#define DEFAULT_MAX_CATEGORIES	1
#define uint32_t_to_char(ip, a, b, c, d) do {\
		*a = (unsigned char)(ip >> 24 & 0xff);\
		*b = (unsigned char)(ip >> 16 & 0xff);\
		*c = (unsigned char)(ip >> 8 & 0xff);\
		*d = (unsigned char)(ip & 0xff);\
	} while (0)
	

#define GET_CB_FIELD(in, fd, base, lim, dlm)	do {            \
	unsigned long val;                                      \
	char *end;                                              \
	errno = 0;                                              \
	val = strtoul((in), &end, (base));                      \
	if (errno != 0 || end[0] != (dlm) || val > (lim))       \
		return -EINVAL;                               \
	(fd) = (typeof(fd))val;                                 \
	(in) = end + 1;                                         \
} while (0)

/*
  * ACL rules should have higher priorities than route ones to ensure ACL rule
  * always be found when input packets have multi-matches in the database.
  * A exception case is performance measure, which can define route rules with
  * higher priority and route rules will always be returned in each lookup.
  * Reserve range from ACL_RULE_PRIORITY_MAX + 1 to
  * RTE_ACL_MAX_PRIORITY for route entries in performance measure
  */
#define ACL_RULE_PRIORITY_MAX 0x10000000

/*
 * Rule and trace formats definitions.
 */

enum {
	PROTO_FIELD_IPV4,
	SRC_FIELD_IPV4,
	DST_FIELD_IPV4,
	SRCP_FIELD_IPV4,
	DSTP_FIELD_IPV4,
	NUM_FIELDS_IPV4
};

/*
 * That effectively defines order of IPV4VLAN classifications:
 *  - PROTO
 *  - VLAN (TAG and DOMAIN)
 *  - SRC IP ADDRESS
 *  - DST IP ADDRESS
 *  - PORTS (SRC and DST)
 */
enum {
	RTE_ACL_IPV4VLAN_PROTO,
	RTE_ACL_IPV4VLAN_SRC,
	RTE_ACL_IPV4VLAN_DST,
	RTE_ACL_IPV4VLAN_PORTS,
	RTE_ACL_IPV4VLAN_NUM
};

struct ipv4_5tuple {
	uint8_t  proto;
	uint32_t ip_src;
	uint32_t ip_dst;
	uint16_t port_src;
	uint16_t port_dst;
};

struct rte_acl_field_def ipv4_defs[5] = {
    /* first input field - always one byte long. */
    {
        .type = RTE_ACL_FIELD_TYPE_BITMASK,
        .size = sizeof (uint8_t),
        .field_index = 0,
        .input_index = 0,
        .offset = offsetof (struct ipv4_5tuple, proto),
    },

    /* next input field (IPv4 source address) - 4 consecutive bytes. */
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof (uint32_t),
        .field_index = 1,
        .input_index = 1,
       .offset = offsetof (struct ipv4_5tuple, ip_src),
    },

    /* next input field (IPv4 destination address) - 4 consecutive bytes. */
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof (uint32_t),
        .field_index = 2,
        .input_index = 2,
       .offset = offsetof (struct ipv4_5tuple, ip_dst),
    },

    /*
     * Next 2 fields (src & dst ports) form 4 consecutive bytes.
     * They share the same input index.
     */
    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof (uint16_t),
        .field_index = 3,
        .input_index = 3,
        .offset = offsetof (struct ipv4_5tuple, port_src),
    },

    {
        .type = RTE_ACL_FIELD_TYPE_RANGE,
        .size = sizeof (uint16_t),
        .field_index = 4,
        .input_index = 3,
        .offset = offsetof (struct ipv4_5tuple, port_dst),
    },
};


enum 
{
	SW_FILTER_FILED_SRC_ADDR,
	SW_FILTER_FILED_DST_ADDR,
	SW_FILTER_FILED_SRC_PORT,
	SW_FILTER_FILED_DST_PORT,
	SW_FILTER_FILED_PROTO,
	SW_FILTER_FILED_NUM,
};

RTE_ACL_RULE_DEF(acl4_rule, RTE_DIM(ipv4_defs));

const char sw_acl_port_delim[] = ":";
static struct rte_acl_ctx *sw_filter_acl_ctx[SW_DPDK_MAX_PORT] = {0};
static struct rte_acl_rule *sw_filter_acl_rules_base[SW_DPDK_MAX_PORT] = {0};
static uint64_t sw_filter_acl_stat[SW_DPDK_MAX_PORT][MAX_ACL_RULE_NUM] = {{0}};
static uint32_t sw_filter_acl_num[SW_DPDK_MAX_PORT] = {0};

static inline void
print_one_ipv4_rule(struct acl4_rule *rule, int extra)
{
	unsigned char a, b, c, d;

	uint32_t_to_char(rule->field[SRC_FIELD_IPV4].value.u32,
			&a, &b, &c, &d);
	printf("%hhu.%hhu.%hhu.%hhu/%u ", a, b, c, d,
			rule->field[SRC_FIELD_IPV4].mask_range.u32);
	uint32_t_to_char(rule->field[DST_FIELD_IPV4].value.u32,
			&a, &b, &c, &d);
	printf("%hhu.%hhu.%hhu.%hhu/%u ", a, b, c, d,
			rule->field[DST_FIELD_IPV4].mask_range.u32);
	printf("%hu : %hu %hu : %hu 0x%hhx/0x%hhx ",
		rule->field[SRCP_FIELD_IPV4].value.u16,
		rule->field[SRCP_FIELD_IPV4].mask_range.u16,
		rule->field[DSTP_FIELD_IPV4].value.u16, 
		rule->field[DSTP_FIELD_IPV4].mask_range.u16,
		rule->field[PROTO_FIELD_IPV4].value.u8,
		rule->field[PROTO_FIELD_IPV4].mask_range.u8);
	if (extra)
		printf("0x%x-0x%x-0x%x ",
			rule->data.category_mask,
			rule->data.priority,
			rule->data.userdata);
}


/*
 * Parse ClassBench rules file.
 * Expected format:
 * '@'<src_ipv4_addr>'/'<masklen> <space> \
 * <dst_ipv4_addr>'/'<masklen> <space> \
 * <src_port_low> <space> ":" <src_port_high> <space> \
 * <dst_port_low> <space> ":" <dst_port_high> <space> \
 * <proto>'/'<mask>
 */
static int
parse_ipv4_rule(const char *in, uint32_t *addr, uint32_t *mask_len)
{
	uint8_t a, b, c, d, m;

	GET_CB_FIELD(in, a, 0, UINT8_MAX, '.');
	GET_CB_FIELD(in, b, 0, UINT8_MAX, '.');
	GET_CB_FIELD(in, c, 0, UINT8_MAX, '.');
	GET_CB_FIELD(in, d, 0, UINT8_MAX, '/');
	GET_CB_FIELD(in, m, 0, sizeof(uint32_t) * CHAR_BIT, 0);

	addr[0] = IPv4(a, b, c, d);
	mask_len[0] = m;

	return 0;
}

static int
sw_filter_parse_ipv4_rule(char *str, struct acl4_rule *v)
{
	int i, rc;
	char *s, *sp, *in[SW_FILTER_FILED_NUM];
	static const char *dlm = ",";
	int dim = SW_FILTER_FILED_NUM;

	char tmp[128] = {0};
	memcpy(tmp, str, strlen(str));
	for (i = 0; i < (int)strlen(str); i++)
	{
		//trim
		if (tmp[i] == '\r' || tmp[i] == '\n')
		{
			tmp[i] = '\0';
			break;
		}
	}
	
	s = tmp;
	SW_FILTER_Log_Info("Start to parse ipv4 rule:[%s] \n", s);

	for (i = 0; i != dim; i++, s = NULL) {
		in[i] = strtok_r(s, dlm, &sp);
		if (in[i] == NULL)
		{
			SW_FILTER_Log_Error("%s error, line:%d \n", __FUNCTION__, __LINE__);
			return -1;
		}
		//else
		//	SW_FILTER_Log_Info("i:%d, value:%s \n", i, in[i]);
	}

	rc = parse_ipv4_rule(in[SW_FILTER_FILED_SRC_ADDR],
			&v->field[SRC_FIELD_IPV4].value.u32,
			&v->field[SRC_FIELD_IPV4].mask_range.u32);
	if (rc != 0) {
		SW_FILTER_Log_Error("failed to read source address/mask: %s\n", in[SW_FILTER_FILED_SRC_ADDR]);
		return rc;
	}
	else
		SW_FILTER_Log_Info("source address/mask: %u-%u\n", v->field[SRC_FIELD_IPV4].value.u32, v->field[SRC_FIELD_IPV4].mask_range.u32);

	rc = parse_ipv4_rule(in[SW_FILTER_FILED_DST_ADDR],
			&v->field[DST_FIELD_IPV4].value.u32,
			&v->field[DST_FIELD_IPV4].mask_range.u32);
	if (rc != 0) {
		SW_FILTER_Log_Error("failed to read destination address/mask: %s\n", in[SW_FILTER_FILED_DST_ADDR]);
		return rc;
	}
	else
		SW_FILTER_Log_Info("dest address/mask: %u-%u\n", v->field[DST_FIELD_IPV4].value.u32, v->field[DST_FIELD_IPV4].mask_range.u32);
	
	//get src port range
	char *in_port[2];
	s = in[SW_FILTER_FILED_SRC_PORT];
	for (i = 0; i < 2; i++, s=NULL)
	{
		in_port[i] = strtok_r(s, sw_acl_port_delim, &sp);
		if (in_port[i] == NULL)
		{
			SW_FILTER_Log_Error("%s error, line:%d \n", __FUNCTION__, __LINE__);
			return -1;
		}
		//else
		//	SW_FILTER_Log_Info("Sport range %u : %s \n", i, in_port[i]);
	}
	
	GET_CB_FIELD(in_port[0],
		v->field[SRCP_FIELD_IPV4].value.u16,
		0, UINT16_MAX, 0);
	GET_CB_FIELD(in_port[1],
		v->field[SRCP_FIELD_IPV4].mask_range.u16,
		0, UINT16_MAX, 0);

	//get dst prot range	
	s = in[SW_FILTER_FILED_DST_PORT];
	for (i = 0; i < 2; i++,s=NULL)
	{
		in_port[i] = strtok_r(s, sw_acl_port_delim, &sp);
		if (in_port[i] == NULL)
		{
			SW_FILTER_Log_Error("%s error, line:%d \n", __FUNCTION__, __LINE__);
			return -1;
		}
		//else
		//	SW_FILTER_Log_Info("Dport range %u : %s , origin:%s \n", i, in_port[i], in[SW_FILTER_FILED_DST_PORT]);
	}
	
	GET_CB_FIELD(in_port[0],
		v->field[DSTP_FIELD_IPV4].value.u16,
		0, UINT16_MAX, 0);
	GET_CB_FIELD(in_port[1],
		v->field[DSTP_FIELD_IPV4].mask_range.u16,
		0, UINT16_MAX, 0);

	if (v->field[SRCP_FIELD_IPV4].mask_range.u16
			< v->field[SRCP_FIELD_IPV4].value.u16
			|| v->field[DSTP_FIELD_IPV4].mask_range.u16
			< v->field[DSTP_FIELD_IPV4].value.u16)
	{
		SW_FILTER_Log_Error("sport range:%u value:%u, dport range:%u value:%u \n", 
							v->field[SRCP_FIELD_IPV4].mask_range.u16,
							v->field[SRCP_FIELD_IPV4].value.u16,
							v->field[DSTP_FIELD_IPV4].mask_range.u16,
							v->field[DSTP_FIELD_IPV4].value.u16);
		return -1;
	}

	SW_FILTER_Log_Info("source port range: %u-%u\n", v->field[SRCP_FIELD_IPV4].value.u16, v->field[SRCP_FIELD_IPV4].mask_range.u16);
	SW_FILTER_Log_Info("source port range: %u-%u\n", v->field[DSTP_FIELD_IPV4].value.u16, v->field[DSTP_FIELD_IPV4].mask_range.u16);
	
	GET_CB_FIELD(in[SW_FILTER_FILED_PROTO], v->field[PROTO_FIELD_IPV4].value.u8,
		0, UINT8_MAX, '/');
	GET_CB_FIELD(in[SW_FILTER_FILED_PROTO], v->field[PROTO_FIELD_IPV4].mask_range.u8,
		0, UINT8_MAX, 0);

	SW_FILTER_Log_Info("proto mask: %u-%u\n", v->field[PROTO_FIELD_IPV4].value.u8, v->field[PROTO_FIELD_IPV4].mask_range.u8);

	return 0;
}

static int
sw_filter_add_rules(const char *rule_path,
				uint16_t port_id,
				struct rte_acl_rule **pacl_base,
				unsigned int *pacl_num, uint32_t rule_size)
{
	uint8_t *acl_rules = NULL;
	struct acl4_rule *next;
	unsigned int acl_num = 0, total_num = 0;
	char buff[256];
	FILE *fh = fopen(rule_path, "rb");
	int val,ret;

	if (fh == NULL)
	{
		SW_FILTER_Log_Error("%s: Open %s failed\n", __func__, rule_path);
		return -1;
	}
	
	//获得满足条件的port
	while ((fgets(buff, 256, fh) != NULL)) {
		char port_s[32] = {0};
		char sip_s[32] = {0};
		char dip_s[32] = {0};
		char sport_s[32] = {0};
		char dport_s[32] = {0};
		char proto_s[32] = {0};
		if (6 != (ret = sscanf(buff, "%[^,],%[^,],%[^,],%[^,],%[^,],%[^\n]", 
					port_s,sip_s,dip_s,sport_s,dport_s,proto_s)))
		{
			SW_FILTER_Log_Error("sscanf error,ret:%d, %s-%s-%s-%s-%s-%s \n", ret,
					port_s,sip_s,dip_s,sport_s,dport_s,proto_s);
			fclose(fh);
			return -1;
		}
		else
		{
			SW_FILTER_Log_Info("sscanf ok, %s-%s-%s-%s-%s-%s \n", port_s,sip_s,dip_s,sport_s,dport_s,proto_s);
		}

		if (port_s[0] == '#' || port_s[0] == '\r' || port_s[0] == '\n')
			continue;

		if (atoi(port_s) != port_id)
			continue;

		acl_num++;
	}

	if (acl_num == 0)
		goto _out;

	val = fseek(fh, 0, SEEK_SET);
	if (val < 0) {
		SW_FILTER_Log_Error("fseek to set error, ret = %d \n", val);
		fclose(fh);
		return -1;
	}

	acl_rules = calloc(acl_num, rule_size);
	if (NULL == acl_rules)
	{
		SW_FILTER_Log_Error("calloc %u error! \n", acl_num);
		fclose(fh);
		return -1;
	}
	
	while ((fgets(buff, 256, fh) != NULL)) {
		char port_s[32] = {0};
		char sip_s[32] = {0};
		char dip_s[32] = {0};
		char sport_s[32] = {0};
		char dport_s[32] = {0};
		char proto_s[32] = {0};
		if (6 != (ret = sscanf(buff, "%[^,],%[^,],%[^,],%[^,],%[^,],%[^\n]", 
					port_s,sip_s,dip_s,sport_s,dport_s,proto_s)))
		{
			SW_FILTER_Log_Error("sscanf error,ret:%d, %s-%s-%s-%s-%s-%s \n", ret,
					port_s,sip_s,dip_s,sport_s,dport_s,proto_s);
			fclose(fh);
			return -1;
		}

		if (atoi(port_s) != port_id)
			continue;
		
		next = (struct acl4_rule *)(acl_rules + total_num * rule_size);
		char *_rule = strstr(buff, ",") + 1;
		if (0 > sw_filter_parse_ipv4_rule(_rule, next))
		{
			SW_FILTER_Log_Error("sw_filter_parse_ipv4_rule error, check the config please !\n");
			return -1;
		}
		//else
		//	SW_FILTER_Log_Info("PortID:%u parse ok:[%s] \n", port_id, buff);

		total_num++;
		next->data.priority = RTE_ACL_MAX_PRIORITY - total_num;
		next->data.category_mask = 0x1;
		next->data.userdata = total_num;

		print_one_ipv4_rule(next, 1);
	}

_out:
	fclose(fh);
	fh = NULL;
	
	*pacl_base = (struct rte_acl_rule *)acl_rules;
	*pacl_num = total_num;
	return 0;
}

static struct rte_acl_ctx*
sw_filter_setup_acl(struct rte_acl_rule *acl_base, 
							unsigned int acl_num,
							uint16_t port_id,
							int socketid)
{
	char name[32] = {0};
	struct rte_acl_param acl_param;
	struct rte_acl_config acl_build_param;
	struct rte_acl_ctx *context;
	int dim = RTE_DIM(ipv4_defs);

	/* Create ACL contexts */
	snprintf(name, sizeof(name), "%s-%02u", "PortAcl", port_id);

	acl_param.name = name;
	acl_param.socket_id = socketid;
	acl_param.rule_size = RTE_ACL_RULE_SZ(dim);
	acl_param.max_rule_num = MAX_ACL_RULE_NUM;

	if ((context = rte_acl_create(&acl_param)) == NULL)
	{
		SW_FILTER_Log_Error("PortID:%u, Failed to create ACL context\n", port_id);
		return NULL;
	}
	
	if (rte_acl_set_ctx_classify(context, RTE_ACL_CLASSIFY_SCALAR) != 0)
	{
		SW_FILTER_Log_Error("PortID:%u, Failed to setup classify method for  ACL context\n", port_id);
		return NULL;
	}
	
	if (rte_acl_add_rules(context, acl_base, acl_num) < 0)
	{
		SW_FILTER_Log_Error("PortID:%u, add rules failed\n", port_id);
		return NULL;
	}

	/* Perform builds */
	memset(&acl_build_param, 0, sizeof(acl_build_param));

	acl_build_param.num_categories = DEFAULT_MAX_CATEGORIES;
	acl_build_param.num_fields = dim;
	memcpy(&acl_build_param.defs, ipv4_defs, sizeof(ipv4_defs));

	if (rte_acl_build(context, &acl_build_param) != 0)
	{
		SW_FILTER_Log_Error("PortID:%u, Failed to build ACL trie\n", port_id);
		return NULL;
	}

	rte_acl_dump(context);
	return context;
}

static int
sw_filter_acl_init(const char *path)
{
	uint32_t i;
	int socketid;
	struct rte_acl_rule *acl_base_ipv4;
	unsigned int acl_num_ipv4 = 0;

	uint32_t rx_port_mask = sw_dpdk_enabled_rx_port_mask();
	for (i = 0; i < SW_DPDK_MAX_PORT; i++)
	{
		if ((rx_port_mask & (1 << i)) == 0)
		{
			SW_FILTER_Log_Info("PortID:%u not rx mode, skip it ...\n", i);
			continue;
		}
		else
			SW_FILTER_Log_Info("PortID:%u is rx mode, start to add acl ...\n", i);

		if (sw_filter_add_rules(path, i, &acl_base_ipv4, &acl_num_ipv4, sizeof(struct acl4_rule)) < 0)
		{
			SW_FILTER_Log_Error("PortID:%u add rules error!\n", i);
			return -1;
		}

		if (acl_num_ipv4 > 0)
		{
			sw_filter_acl_num[i] = acl_num_ipv4;
			sw_filter_acl_rules_base[i] = acl_base_ipv4;
			socketid = sw_dpdk_get_port_socket(i);
			sw_filter_acl_ctx[i] = sw_filter_setup_acl(acl_base_ipv4, acl_num_ipv4, i, socketid);
			if (NULL == sw_filter_acl_ctx[i])
			{
				SW_FILTER_Log_Error("PortID:%u add set acl error!\n", i);
				return -1;
			}
		}
	}

	return 0;
}

/***********************end of ACL part******************************/

/******************************************************************************/
//acl cmd part
/* show acl */
cmdline_parse_token_string_t cmd_show_acl_show =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_acl_result,
		 show, "show");
cmdline_parse_token_string_t cmd_show_acl_acl =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_acl_result,
		 acl, "acl");
cmdline_parse_token_string_t cmd_show_acl_port =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_acl_result,
		 port, "port");
cmdline_parse_token_num_t cmd_show_acl_portid =
	TOKEN_NUM_INITIALIZER
		(struct cmd_show_acl_result,
		 port_id, UINT16);

static void
cmd_show_acl_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_show_acl_result* res = parsed_result;

	int len = 0;
	char buf[SW_CMD_BUFF_LEN] = {0};
	sw_command_client_send_and_recv(SW_CMD_TYPE_SHOW_ACL, res, 
									sizeof(struct cmd_show_acl_result), 
									buf, SW_CMD_BUFF_LEN, &len, SW_CMD_TIMEOUT);

	printf("%s\n", buf);
}


cmdline_parse_inst_t cmd_show_acl = {
	.f = cmd_show_acl_parsed,
	.data = NULL,
	.help_str = "show acl port <port_id>",
	.tokens = {
		(void *)&cmd_show_acl_show,
		(void *)&cmd_show_acl_acl,	
		(void *)&cmd_show_acl_port,
		(void *)&cmd_show_acl_portid,
		NULL,
	},
};

static int sw_filter_cmd_show_acl(uint16_t portid, char* buf, int buf_len)
{
	int len = 0;
	uint16_t i = 0;
	uint32_t enabled_port_mask = sw_dpdk_enabled_port_mask();
	uint32_t enabled_rx_port_mask = sw_dpdk_enabled_rx_port_mask();
	if ((enabled_port_mask & (1 << portid)) == 0)
	{
		len += snprintf(buf+len, buf_len-len, "PortID:%u is not enabled, PortMask:%d!\n", portid, enabled_port_mask);
		return len;
	}

	if ((enabled_rx_port_mask & (1 << portid)) == 0)
	{
		len += snprintf(buf+len, buf_len-len, "PortID:%u is not rx mode !\n", portid);
		return len;
	}

	struct rte_acl_rule* rule = NULL;
	for (; i < sw_filter_acl_num[portid]; i++)
	{
		rule = (struct rte_acl_rule *)((uint8_t*)sw_filter_acl_rules_base[portid] + i * sizeof(struct acl4_rule));
		len += snprintf(buf+len, buf_len-len, "rule:[%04u] ", i+1);
		len += snprintf(buf+len, buf_len-len, "hit cnt:%"PRIu64" ", sw_filter_acl_stat[portid][i+1]);
		
		unsigned char a, b, c, d;
		uint32_t_to_char(rule->field[SRC_FIELD_IPV4].value.u32,
				&a, &b, &c, &d);
		len += snprintf(buf+len, buf_len-len, "%hhu.%hhu.%hhu.%hhu/%u ", a, b, c, d,
				rule->field[SRC_FIELD_IPV4].mask_range.u32);
		uint32_t_to_char(rule->field[DST_FIELD_IPV4].value.u32,
				&a, &b, &c, &d);
		len += snprintf(buf+len, buf_len-len, "%hhu.%hhu.%hhu.%hhu/%u ", a, b, c, d,
				rule->field[DST_FIELD_IPV4].mask_range.u32);
		len += snprintf(buf+len, buf_len-len, "%hu:%hu %hu:%hu 0x%hhx/0x%hhx ",
			rule->field[SRCP_FIELD_IPV4].value.u16,
			rule->field[SRCP_FIELD_IPV4].mask_range.u16,
			rule->field[DSTP_FIELD_IPV4].value.u16,
			rule->field[DSTP_FIELD_IPV4].mask_range.u16,
			rule->field[PROTO_FIELD_IPV4].value.u8,
			rule->field[PROTO_FIELD_IPV4].mask_range.u8);
		len += snprintf(buf+len, buf_len-len, "0x%x-0x%x-0x%x \n",
				rule->data.category_mask,
				rule->data.priority,
				rule->data.userdata);
	}

	return len;
}

/******************************************************************************/


int sw_filter_port(uint16_t port_id, PKT_INFO_S* pkt_info)
{
	if (port_id >= SW_DPDK_MAX_PORT || NULL == sw_filter_acl_ctx[port_id])
		return -1;

	int ret;
	struct rte_acl_ctx *acl_ctx = sw_filter_acl_ctx[port_id];
	struct ipv4_5tuple v;
	
	/* convert to network byte order. */
	v.proto  = pkt_info->proto;
	v.ip_src = rte_cpu_to_be_32(pkt_info->sip);
	v.ip_dst = rte_cpu_to_be_32(pkt_info->dip);
	v.port_src = rte_cpu_to_be_16(pkt_info->sport);
	v.port_dst = rte_cpu_to_be_16(pkt_info->dport);

	uint32_t results;
	const uint8_t *data = (uint8_t *)&v;
	ret = rte_acl_classify(acl_ctx, &data, &results, 1, 1);
	if (ret != 0)
		return -1;

	if (results != 0)
	{
	#ifdef SW_FILTER_DEBUG
		SW_FILTER_Log_Info("Pkt: %u:%u-%u:%u match acl:%u \n", pkt_info->sip, pkt_info->sport, pkt_info->dip, pkt_info->dport, 
						results);
	#endif

		sw_filter_acl_stat[port_id][results]++;
	
		return 0;
	}
	
	return -1;
}

int sw_filter_init(const char *cfg_path)
{
	if (NULL == cfg_path)
	{
		SW_FILTER_Log_Error("cfg_path null error!\n");
		return -1;
	}

	if (0 != sw_filter_acl_init(cfg_path))
	{
		SW_FILTER_Log_Error("sw_filter_acl_init error!\n");
		return -1;
	}

	sw_command_register_show_acl(sw_filter_cmd_show_acl);
		
	//sw_command_register_set_acl(sw_filter_handle);
	return 0;
}

