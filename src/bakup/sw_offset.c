#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <hs.h>
#include "sw_dpdk.h"
#include "sw_offset.h"

#define UNUSED(x) UNUSED_ ## x __attribute__((unused))
#define SW_STATADD(a)	__sync_fetch_and_add(&(a),1)

#define SW_OFFSET_MAX_NUM 10000
#define SW_OFFSET_HS_RULE_LEN 32

typedef struct
{
	uint16_t layer;
	uint16_t port;
	uint32_t matched;
}SW_OFFSET_MATCH_CTX;

enum {
	SW_OFFSET_L2 = 1,
	SW_OFFSET_L3,
	SW_OFFSET_L4,
};

enum {
	SW_OFFSET_RULE_TYPE_HEX = 1,
	SW_OFFSET_RULE_TYPE_STRING,
};

typedef struct
{
	uint16_t offset;	
	uint16_t type;
	uint64_t match_cnt;
	char value[SW_OFFSET_HS_RULE_LEN];
	char alias[32];
}SW_OFFSET_RULE_INFO;
static SW_OFFSET_RULE_INFO sw_offset_rule_info_l2[SW_DPDK_MAX_PORT][SW_OFFSET_MAX_NUM] = {{{0}}};
static SW_OFFSET_RULE_INFO sw_offset_rule_info_l3[SW_DPDK_MAX_PORT][SW_OFFSET_MAX_NUM] = {{{0}}};
static SW_OFFSET_RULE_INFO sw_offset_rule_info_l4[SW_DPDK_MAX_PORT][SW_OFFSET_MAX_NUM] = {{{0}}};

static unsigned hs_flags_l2[SW_DPDK_MAX_PORT][SW_OFFSET_MAX_NUM] = {{0}};
static unsigned hs_flags_l3[SW_DPDK_MAX_PORT][SW_OFFSET_MAX_NUM] = {{0}};
static unsigned hs_flags_l4[SW_DPDK_MAX_PORT][SW_OFFSET_MAX_NUM] = {{0}};
static unsigned hs_ids_l2[SW_DPDK_MAX_PORT][SW_OFFSET_MAX_NUM] = {{0}};
static unsigned hs_ids_l3[SW_DPDK_MAX_PORT][SW_OFFSET_MAX_NUM] = {{0}};
static unsigned hs_ids_l4[SW_DPDK_MAX_PORT][SW_OFFSET_MAX_NUM] = {{0}};

static hs_database_t *hs_db_l2[SW_DPDK_MAX_PORT] = {0};
static hs_database_t *hs_db_l3[SW_DPDK_MAX_PORT] = {0};
static hs_database_t *hs_db_l4[SW_DPDK_MAX_PORT] = {0};

static hs_scratch_t *hs_scratch_l2[SW_DPDK_MAX_PORT][SW_DPDK_MAX_TX_NUM] = {{0}};
static hs_scratch_t *hs_scratch_l3[SW_DPDK_MAX_PORT][SW_DPDK_MAX_TX_NUM] = {{0}};
static hs_scratch_t *hs_scratch_l4[SW_DPDK_MAX_PORT][SW_DPDK_MAX_TX_NUM] = {{0}};

static char* hs_exp_l2[SW_DPDK_MAX_PORT][SW_OFFSET_MAX_NUM] = {{0}};
static char* hs_exp_l3[SW_DPDK_MAX_PORT][SW_OFFSET_MAX_NUM] = {{0}};
static char* hs_exp_l4[SW_DPDK_MAX_PORT][SW_OFFSET_MAX_NUM] = {{0}};
static int hs_exp_l2_num[SW_DPDK_MAX_PORT] = {0};
static int hs_exp_l3_num[SW_DPDK_MAX_PORT] = {0};
static int hs_exp_l4_num[SW_DPDK_MAX_PORT] = {0};

//用于动态添加规则的临时保存
static char* hs_exp_l2_1[SW_DPDK_MAX_PORT][SW_OFFSET_MAX_NUM] = {{0}};
static char* hs_exp_l3_1[SW_DPDK_MAX_PORT][SW_OFFSET_MAX_NUM] = {{0}};
static char* hs_exp_l4_1[SW_DPDK_MAX_PORT][SW_OFFSET_MAX_NUM] = {{0}};
static int hs_exp_l2_num_1[SW_DPDK_MAX_PORT] = {0};
static int hs_exp_l3_num_1[SW_DPDK_MAX_PORT] = {0};
static int hs_exp_l4_num_1[SW_DPDK_MAX_PORT] = {0};


//主备切换指针
static SW_OFFSET_RULE_INFO **sw_offset_rule_info_l2_using;
static SW_OFFSET_RULE_INFO **sw_offset_rule_info_l3_using;
static SW_OFFSET_RULE_INFO **sw_offset_rule_info_l4_using;
static unsigned **hs_flags_l2_using;
static unsigned **hs_flags_l3_using;
static unsigned **hs_flags_l4_using;
static unsigned **hs_ids_l2_using;
static unsigned **hs_ids_l3_using;
static unsigned **hs_ids_l4_using;
static hs_database_t **hs_db_l2_using;
static hs_database_t **hs_db_l3_using;
static hs_database_t **hs_db_l4_using;
static hs_scratch_t ***hs_scratch_l2_using;
static hs_scratch_t ***hs_scratch_l3_using;
static hs_scratch_t ***hs_scratch_l4_using;
static char ***hs_exp_l2_using;
static char ***hs_exp_l3_using;
static char ***hs_exp_l4_using;
static int *hs_exp_l2_num_using;
static int *hs_exp_l3_num_using;
static int *hs_exp_l4_num_using;




/******************************************************************************/
//cmd
/* show acl */
cmdline_parse_token_string_t cmd_show_offset_show =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_offset_result,
		 show, "show");
cmdline_parse_token_string_t cmd_show_offset_offset =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_offset_result,
		 offset, "offset");
cmdline_parse_token_string_t cmd_show_offset_port =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_offset_result,
		 port, "port");
cmdline_parse_token_num_t cmd_show_offset_portid =
	TOKEN_NUM_INITIALIZER
		(struct cmd_show_offset_result,
		 port_id, UINT16);

static void
cmd_show_offset_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_show_offset_result* res = parsed_result;

	int len = 0;
	char buf[SW_CMD_BUFF_LEN] = {0};
	sw_command_client_send_and_recv(SW_CMD_TYPE_SHOW_OFFSET, res, 
									sizeof(struct cmd_show_offset_result), 
									buf, SW_CMD_BUFF_LEN, &len, SW_CMD_TIMEOUT);

	printf("%s\n", buf);
}


cmdline_parse_inst_t cmd_show_offset = {
	.f = cmd_show_offset_parsed,
	.data = NULL,
	.help_str = "show offset port <port_id>",
	.tokens = {
		(void *)&cmd_show_offset_show,
		(void *)&cmd_show_offset_offset,	
		(void *)&cmd_show_offset_port,
		(void *)&cmd_show_offset_portid,
		NULL,
	},
};

static int sw_offset_cmd_show_stat(uint16_t portid, char* buf, int buf_len)
{
	int len = 0;
	int i = 0;
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

	len += snprintf(buf+len, buf_len-len,"\nL4 Offset Rule:\n");
	for (i = 0; i < hs_exp_l4_num[portid]; i++)
	{
		len += snprintf(buf+len, buf_len-len, "    %05d  Match:%12"PRIu64"  Alias:%16s  Pattern:%s\n", i,
			sw_offset_rule_info_l4[portid][i].match_cnt, 
			sw_offset_rule_info_l4[portid][i].alias, 
			sw_offset_rule_info_l4[portid][i].value);
	}

	len += snprintf(buf+len, buf_len-len,"\nL3 Offset Rule:\n");
	for (i = 0; i < hs_exp_l3_num[portid]; i++)
	{
		len += snprintf(buf+len, buf_len-len, "    %05d  Match:%12"PRIu64"  %16s  %s\n", i,
			sw_offset_rule_info_l3[portid][i].match_cnt, 
			sw_offset_rule_info_l3[portid][i].alias, 
			sw_offset_rule_info_l3[portid][i].value);
	}

	len += snprintf(buf+len, buf_len-len,"\nL2 Offset Rule:\n");
	for (i = 0; i < hs_exp_l2_num[portid]; i++)
	{
		len += snprintf(buf+len, buf_len-len, "    %05d  Match:%12"PRIu64"  %16s  %s\n", i,
			sw_offset_rule_info_l2[portid][i].match_cnt, 
			sw_offset_rule_info_l2[portid][i].alias, 
			sw_offset_rule_info_l2[portid][i].value);
	}
	
	return len;
}

/******************************************************************************/
// example:each line means a rx port configuration
// rx_port,L2|L3|L4,offset,target_value,target_type,alias
//     rx_port  : number type, port id that is rx mode
//     L2|L3|L4 : string type, just use L2 or L3 or L4
//     offset   : number type, the offset number wanted to match
//     target_v : hex type or string type
//     target_t : string type, option is "hex" and "string", which "hex" means the target_v can be "1234abcd" 
//     alias    : string type, the alias of this offset rule 
// 0,L4,20,GET,string,HTTP_GET
// 0,L4,20,0x50 0x4f 0x53 0x54,hex,HTTP_POST
int sw_offset_dynamic_add_rule(char* rule, char* error, int err_len)
{
	static int single_user = 0;
	if (single_user)
	{
		SW_OFFSET_Log_Error("Maybe someone else is adding rules, please wait ... \n");
		snprintf(error, err_len, "Maybe someone else is adding rules, please wait ... \n");
		goto _error;
	}
		
	int ret;
	//rx_port,L2|L3|L4,offset,target_value,target_type,alias
	char port_s[16] = {0};
	char layer_s[16] = {0};
	char offset_s[16] = {0};
	char value_s[32]= {0};
	char type_s[16] = {0};
	char alias_s[32] = {0};

	memset(error,0,err_len);
	if (6 != (ret = sscanf(rule, "%[^,],%[^,],%[^,],%[^,],%[^,],%[^\n]", 
				port_s,layer_s,offset_s,value_s,type_s, alias_s)))
	{
		SW_OFFSET_Log_Error("sscanf error,ret:%d, %s-%s-%s-%s-%s-%s \n", ret,
				port_s,layer_s,offset_s,value_s,type_s, alias_s);
		
		snprintf(error, err_len, "sscanf error, ret:%d, %s-%s-%s-%s-%s-%s \n", ret,
				port_s,layer_s,offset_s,value_s,type_s, alias_s);
		goto _error;
	}

	int port = atoi(port_s);
	if (port >= SW_DPDK_MAX_PORT)
	{
		SW_OFFSET_Log_Error("port id:%d exceed max id:%d !\n", port, SW_DPDK_MAX_PORT);
		snprintf(error, err_len, "port id:%d exceed max id:%d !\n", port, SW_DPDK_MAX_PORT);
		goto _error;
	}
	
	uint32_t rx_port_mask = sw_dpdk_enabled_rx_port_mask();
	if ((rx_port_mask & (1 << port)) == 0)
	{
		snprintf(error, err_len, "PortID:%d not rx mode, skip it ...\n", port);
		SW_OFFSET_Log_Info("PortID:%d not rx mode \n", port);
		goto _error;
	}
	else
		SW_OFFSET_Log_Info("PortID:%d is rx mode, start to add offset rule ...\n", port);

	if (0 != strcmp("L2", layer_s) && 0 != strcmp("L3", layer_s) && 0 != strcmp("L4", layer_s))
	{
		snprintf(error, err_len, "layser:%s error!\n", layer_s);
		SW_OFFSET_Log_Error("layser:%s error!\n", layer_s);
		goto _error;
	}

	uint16_t offset = (uint16_t)atoi(offset_s);
	if (offset >= 1500)
	{
		snprintf(error, err_len, "offset:%s maybe too long !\n", offset_s);
		SW_OFFSET_Log_Error("offset:%s maybe too long !\n", offset_s);
		goto _error;
	}

	if (0 != strcmp("string", type_s) && 0 != strcmp("hex", type_s))
	{
		snprintf(error, err_len, "type:%s error!\n", type_s);
		SW_OFFSET_Log_Error("type:%s error!\n", type_s);
		goto _error;
	}

	if (strlen(value_s) > SW_OFFSET_HS_RULE_LEN)
	{
		snprintf(error, err_len, "value:%s maybe too long!\n", value_s);
		SW_OFFSET_Log_Error("value:%s maybe too long!\n", value_s);
		goto _error;
	}

	if (strlen(alias_s) > 32)
	{
		snprintf(error, err_len, "alias:%s maybe too long!\n", alias_s);
		SW_OFFSET_Log_Error("alias:%s maybe too long!\n", alias_s);
		goto _error;
	}

	uint16_t type = 0;
	int rule_num = 0;
	char *rule_exp = NULL;
	if (0 == strcmp("L2", layer_s))
	{
		rule_num = hs_exp_l2_num[port];
		hs_exp_l2[port][rule_num] = malloc(SW_OFFSET_HS_RULE_LEN);
		rule_exp = hs_exp_l2[port][rule_num];
		if (NULL == rule_exp)
		{
			SW_OFFSET_Log_Error("L2 Port:%u, rule num:%d malloc error!\n", port, rule_num);
			return -1;
		}
		
		memset(rule_exp, 0, SW_OFFSET_HS_RULE_LEN);
		hs_flags_l2[port][rule_num] |= HS_FLAG_SOM_LEFTMOST;
		hs_ids_l2[port][rule_num] = rule_num;
	}
	else if (0 == strcmp("L3", layer_s))
	{
		rule_num = hs_exp_l3_num[port];
		hs_exp_l3[port][rule_num] = malloc(SW_OFFSET_HS_RULE_LEN);
		rule_exp = hs_exp_l3[port][rule_num];
		if (NULL == rule_exp)
		{
			SW_OFFSET_Log_Error("L3 Port:%u, rule num:%d malloc error!\n", port, rule_num);
			return -1;
		}

		memset(rule_exp, 0, SW_OFFSET_HS_RULE_LEN);
		hs_flags_l3[port][rule_num] |= HS_FLAG_SOM_LEFTMOST;
		hs_ids_l3[port][rule_num] = rule_num;
	}
	else if (0 == strcmp("L4", layer_s))
	{
		rule_num = hs_exp_l4_num[port];
		hs_exp_l4[port][rule_num] = malloc(SW_OFFSET_HS_RULE_LEN);
		rule_exp = hs_exp_l4[port][rule_num];
		if (NULL == rule_exp)
		{
			SW_OFFSET_Log_Error("L4 Port:%u, rule num:%d malloc error!\n", port, rule_num);
			return -1;
		}

		memset(rule_exp, 0, SW_OFFSET_HS_RULE_LEN);
		hs_flags_l4[port][rule_num] |= HS_FLAG_SOM_LEFTMOST;
		hs_ids_l4[port][rule_num] = rule_num;
	}

	if (0 == strcmp("hex", type_s))
	{
		//check the hex value
		char* token = strtok(value_s, " ");
		int hex_value, rule_off = 0;
		while(token)
		{
			if (1 != sscanf(token, "%x", &hex_value))
			{
				SW_OFFSET_Log_Error("value:%s maybe have error hex value:%s !\n", value_s, token);
				return -1;
			}

			memcpy(rule_exp+rule_off, token, strlen(token));
			rule_exp[rule_off] = '\\';
			rule_off += strlen(token);
			
			token = strtok(NULL, " ");
		}

		type = (uint16_t)SW_OFFSET_RULE_TYPE_HEX;
		SW_OFFSET_Log_Info("Parse A Hex rule:%s \n", rule_exp);
	}


	if (0 == strcmp("string", type_s))
	{
		memcpy(rule_exp, value_s, strlen(value_s));
		type = (uint16_t)SW_OFFSET_RULE_TYPE_STRING;
		SW_OFFSET_Log_Info("Parse A String rule:%s \n", rule_exp);
	}

	if (0 == strcmp("L2", layer_s))
	{
		hs_exp_l2_num[port]++;
		sw_offset_rule_info_l2[port][rule_num].offset = offset;
		sw_offset_rule_info_l2[port][rule_num].type = type;
		memcpy(sw_offset_rule_info_l2[port][rule_num].value, rule_exp, strlen(rule_exp));
		memcpy(sw_offset_rule_info_l2[port][rule_num].alias, alias_s, strlen(alias_s));
	}
	else if (0 == strcmp("L3", layer_s))
	{
		hs_exp_l3_num[port]++;
		sw_offset_rule_info_l3[port][rule_num].offset = offset;
		sw_offset_rule_info_l3[port][rule_num].type = type;
		memcpy(sw_offset_rule_info_l3[port][rule_num].value, rule_exp, strlen(rule_exp));
		memcpy(sw_offset_rule_info_l3[port][rule_num].alias, alias_s, strlen(alias_s));
	}
	else if (0 == strcmp("L4", layer_s))
	{
		hs_exp_l4_num[port]++;
		sw_offset_rule_info_l4[port][rule_num].offset = offset;
		sw_offset_rule_info_l4[port][rule_num].type = type;
		memcpy(sw_offset_rule_info_l4[port][rule_num].value, rule_exp, strlen(rule_exp));
		memcpy(sw_offset_rule_info_l4[port][rule_num].alias, alias_s, strlen(alias_s));
	}

	single_user = 0; 
	return 0;

_error:
	single_user = 0; 
	return -1;

}

int sw_offset_dynamic_del_rule(int port, int type, int rule_id)
{

}

static int sw_offset_parse(char* oneline)
{
	int ret;
	//rx_port,L2|L3|L4,offset,target_value,target_type,alias
	char port_s[16] = {0};
	char layer_s[16] = {0};
	char offset_s[16] = {0};
	char value_s[32]= {0};
	char type_s[16] = {0};
	char alias_s[32] = {0};
	
	if (6 != (ret = sscanf(oneline, "%[^,],%[^,],%[^,],%[^,],%[^,],%[^\n]", 
				port_s,layer_s,offset_s,value_s,type_s, alias_s)))
	{
		SW_OFFSET_Log_Error("sscanf error,ret:%d, %s-%s-%s-%s-%s-%s \n", ret,
				port_s,layer_s,offset_s,value_s,type_s, alias_s);
		return -1;
	}

	int port = atoi(port_s);
	if (port >= SW_DPDK_MAX_PORT)
	{
		SW_OFFSET_Log_Error("port id:%d error!\n", port);
		return -1;
	}
	
	uint32_t rx_port_mask = sw_dpdk_enabled_rx_port_mask();
	if ((rx_port_mask & (1 << port)) == 0)
	{
		SW_OFFSET_Log_Info("PortID:%d not rx mode, skip it ...\n", port);
		return 0;
	}
	else
		SW_OFFSET_Log_Info("PortID:%d is rx mode, start to add offset rule ...\n", port);

	if (0 != strcmp("L2", layer_s) && 0 != strcmp("L3", layer_s) && 0 != strcmp("L4", layer_s))
	{
		SW_OFFSET_Log_Error("layser:%s error!\n", layer_s);
		return -1;
	}

	uint16_t offset = (uint16_t)atoi(offset_s);
	if (offset >= 1500)
	{
		SW_OFFSET_Log_Error("offset:%s maybe too long !\n", offset_s);
		return -1;
	}

	if (0 != strcmp("string", type_s) && 0 != strcmp("hex", type_s))
	{
		SW_OFFSET_Log_Error("type:%s error!\n", type_s);
		return -1;
	}

	if (strlen(value_s) > SW_OFFSET_HS_RULE_LEN)
	{
		SW_OFFSET_Log_Error("value:%s maybe too long!\n", value_s);
		return -1;
	}

	if (strlen(alias_s) > 32)
	{
		SW_OFFSET_Log_Error("alias:%s maybe too long!\n", alias_s);
		return -1;
	}

	uint16_t type = 0;
	int rule_num = 0;
	char *rule_exp = NULL;
	if (0 == strcmp("L2", layer_s))
	{
		rule_num = hs_exp_l2_num[port];
		hs_exp_l2[port][rule_num] = malloc(SW_OFFSET_HS_RULE_LEN);
		rule_exp = hs_exp_l2[port][rule_num];
		if (NULL == rule_exp)
		{
			SW_OFFSET_Log_Error("L2 Port:%u, rule num:%d malloc error!\n", port, rule_num);
			return -1;
		}
		
		memset(rule_exp, 0, SW_OFFSET_HS_RULE_LEN);
		hs_flags_l2[port][rule_num] |= HS_FLAG_SOM_LEFTMOST;
		hs_ids_l2[port][rule_num] = rule_num;
	}
	else if (0 == strcmp("L3", layer_s))
	{
		rule_num = hs_exp_l3_num[port];
		hs_exp_l3[port][rule_num] = malloc(SW_OFFSET_HS_RULE_LEN);
		rule_exp = hs_exp_l3[port][rule_num];
		if (NULL == rule_exp)
		{
			SW_OFFSET_Log_Error("L3 Port:%u, rule num:%d malloc error!\n", port, rule_num);
			return -1;
		}

		memset(rule_exp, 0, SW_OFFSET_HS_RULE_LEN);
		hs_flags_l3[port][rule_num] |= HS_FLAG_SOM_LEFTMOST;
		hs_ids_l3[port][rule_num] = rule_num;
	}
	else if (0 == strcmp("L4", layer_s))
	{
		rule_num = hs_exp_l4_num[port];
		hs_exp_l4[port][rule_num] = malloc(SW_OFFSET_HS_RULE_LEN);
		rule_exp = hs_exp_l4[port][rule_num];
		if (NULL == rule_exp)
		{
			SW_OFFSET_Log_Error("L4 Port:%u, rule num:%d malloc error!\n", port, rule_num);
			return -1;
		}

		memset(rule_exp, 0, SW_OFFSET_HS_RULE_LEN);
		hs_flags_l4[port][rule_num] |= HS_FLAG_SOM_LEFTMOST;
		hs_ids_l4[port][rule_num] = rule_num;
	}

	if (0 == strcmp("hex", type_s))
	{
		//check the hex value
		char* token = strtok(value_s, " ");
		int hex_value, rule_off = 0;
		while(token)
		{
			if (1 != sscanf(token, "%x", &hex_value))
			{
				SW_OFFSET_Log_Error("value:%s maybe have error hex value:%s !\n", value_s, token);
				return -1;
			}

			memcpy(rule_exp+rule_off, token, strlen(token));
			rule_exp[rule_off] = '\\';
			rule_off += strlen(token);
			
	        token = strtok(NULL, " ");
	    }

		type = (uint16_t)SW_OFFSET_RULE_TYPE_HEX;
		SW_OFFSET_Log_Info("Parse A Hex rule:%s \n", rule_exp);
	}


	if (0 == strcmp("string", type_s))
	{
		memcpy(rule_exp, value_s, strlen(value_s));
		type = (uint16_t)SW_OFFSET_RULE_TYPE_STRING;
		SW_OFFSET_Log_Info("Parse A String rule:%s \n", rule_exp);
	}

	if (0 == strcmp("L2", layer_s))
	{
		hs_exp_l2_num[port]++;
		sw_offset_rule_info_l2[port][rule_num].offset = offset;
		sw_offset_rule_info_l2[port][rule_num].type = type;
		memcpy(sw_offset_rule_info_l2[port][rule_num].value, rule_exp, strlen(rule_exp));
		memcpy(sw_offset_rule_info_l2[port][rule_num].alias, alias_s, strlen(alias_s));
	}
	else if (0 == strcmp("L3", layer_s))
	{
		hs_exp_l3_num[port]++;
		sw_offset_rule_info_l3[port][rule_num].offset = offset;
		sw_offset_rule_info_l3[port][rule_num].type = type;
		memcpy(sw_offset_rule_info_l3[port][rule_num].value, rule_exp, strlen(rule_exp));
		memcpy(sw_offset_rule_info_l3[port][rule_num].alias, alias_s, strlen(alias_s));
	}
	else if (0 == strcmp("L4", layer_s))
	{
		hs_exp_l4_num[port]++;
		sw_offset_rule_info_l4[port][rule_num].offset = offset;
		sw_offset_rule_info_l4[port][rule_num].type = type;
		memcpy(sw_offset_rule_info_l4[port][rule_num].value, rule_exp, strlen(rule_exp));
		memcpy(sw_offset_rule_info_l4[port][rule_num].alias, alias_s, strlen(alias_s));
	}

	return 0;
}

static int sw_offset_conf_init(const char* conf_path)
{
	FILE* fp = fopen(conf_path, "r");
	if (NULL == fp)
		return -1;

	char oneline[256] = {0};
	while(fgets(oneline, sizeof(oneline), fp) != NULL )
	{
		if (oneline[0] == '#' || oneline[0] == '\r' || oneline[0] == '\n')
			continue;

		printf("Parse:%s\n", oneline);
		if (0 > sw_offset_parse(oneline))
		{
			printf("Conf -- %s -- Error !\n", oneline);
			fclose(fp);
			return -1;
		}
	}

	fclose(fp);

	//编译各个端口的hs规则集
	uint32_t i = 0;
	uint32_t rx_port_mask = sw_dpdk_enabled_rx_port_mask();
	for (; i < SW_DPDK_MAX_PORT; i++)
	{
		if ((rx_port_mask & (1 << i)) == 0)
			continue;

		uint16_t tx_num = sw_dpdk_port_tx_num(i);
		if (tx_num == 0)
		{
			SW_OFFSET_Log_Error("Port:%u get tx num error 0 !\n", i);
			return -1;
		}

		uint16_t j;
		hs_compile_error_t *compileErr = NULL;
		hs_error_t hs_err_ret;
		if (hs_exp_l2_num[i] > 0)
		{
			hs_err_ret= hs_compile_multi((const char * const*)hs_exp_l2[i], 
										hs_flags_l2[i],
										hs_ids_l2[i],
                       					hs_exp_l2_num[i], 
                       					HS_MODE_BLOCK, 
                       					NULL, 
                       					&hs_db_l2[i], 
                       					&compileErr);

			if (HS_SUCCESS != hs_err_ret)
			{
				if (compileErr->expression < 0) 
			    {
			        SW_OFFSET_Log_Error("L2: ERROR: %s !\n", compileErr->message);
			    } 
			    else 
			    {
			    	SW_OFFSET_Log_Error("L2: Line %d index %d, Pattern %s failed compilation with error: %s! \n", 
							__LINE__,
							compileErr->expression,
							hs_exp_l2[i][compileErr->expression],
							compileErr->message);
			    }
				
				return -1;
			}

			SW_OFFSET_Log_Info("Port %02u L2 HS Complie ok, rule num:%d \n", i, hs_exp_l2_num[i]);
			for (j = 0; j < tx_num; j++)
			{
				hs_err_ret= hs_alloc_scratch(hs_db_l2[i], &(hs_scratch_l2[i][j]));
				if (HS_SUCCESS != hs_err_ret)
				{
					SW_OFFSET_Log_Error("Port:%u, thread:%u scratch L2 error!\n", i, j);
					return -1;
				}
			}
			
		}

		if (hs_exp_l3_num[i] > 0)
		{
			hs_err_ret= hs_compile_multi((const char * const*)hs_exp_l3[i], 
										hs_flags_l3[i],
										hs_ids_l3[i],
                       					hs_exp_l3_num[i], 
                       					HS_MODE_BLOCK, 
                       					NULL, 
                       					&hs_db_l3[i], 
                       					&compileErr);

			if (HS_SUCCESS != hs_err_ret)
			{
				if (compileErr->expression < 0) 
			    {
			        SW_OFFSET_Log_Error("L3: ERROR: %s !\n", compileErr->message);
			    } 
			    else 
			    {
			    	SW_OFFSET_Log_Error("L3: Line %d index %d, Pattern %s failed compilation with error: %s! \n", 
							__LINE__,
							compileErr->expression,
							hs_exp_l3[i][compileErr->expression],
							compileErr->message);
			    }
				
				return -1;
			}

			SW_OFFSET_Log_Info("Port %02u L3 HS Complie ok, rule num:%d \n", i, hs_exp_l3_num[i]);
			for (j = 0; j < tx_num; j++)
			{
				hs_err_ret= hs_alloc_scratch(hs_db_l3[i], &(hs_scratch_l3[i][j]));
				if (HS_SUCCESS != hs_err_ret)
				{
					SW_OFFSET_Log_Error("Port:%u, thread:%u scratch L3 error!\n", i, j);
					return -1;
				}
			}
		}

		if (hs_exp_l4_num[i] > 0)
		{
			hs_err_ret= hs_compile_multi((const char * const*)hs_exp_l4[i], 
										hs_flags_l4[i],
										hs_ids_l4[i],
                       					hs_exp_l4_num[i], 
                       					HS_MODE_BLOCK, 
                       					NULL, 
                       					&hs_db_l4[i], 
                       					&compileErr);

			if (HS_SUCCESS != hs_err_ret)
			{
				if (compileErr->expression < 0) 
			    {
			        SW_OFFSET_Log_Error("L4: ERROR: %s !\n", compileErr->message);
			    } 
			    else 
			    {
			    	SW_OFFSET_Log_Error("L4: Line %d index %d, Pattern %s failed compilation with error: %s! \n", 
							__LINE__,
							compileErr->expression,
							hs_exp_l4[i][compileErr->expression],
							compileErr->message);
			    }
				
				return -1;
			}

			SW_OFFSET_Log_Info("Port %02u L4 HS Complie ok, rule num:%d \n", i, hs_exp_l4_num[i]);
			for (j = 0; j < tx_num; j++)
			{
				hs_err_ret= hs_alloc_scratch(hs_db_l4[i], &(hs_scratch_l4[i][j]));
				if (HS_SUCCESS != hs_err_ret)
				{
					SW_OFFSET_Log_Error("Port:%u, thread:%u scratch L4 error!\n", i, j);
					return -1;
				}
			}
		}
	}
	
	return 0;
}

static int hyperscan_callback(unsigned int id, unsigned long long from,
                    unsigned long long UNUSED(to), unsigned int UNUSED(flags), void *ctx)
{
	//return -1 stop scan
	if (NULL == ctx)
		return -1;

	SW_OFFSET_MATCH_CTX *m_ctx = (SW_OFFSET_MATCH_CTX *)ctx;
	uint16_t port = m_ctx->port;
	//printf("Port:%u ID:%d match at %d \n", port, id, from);
		
	if (SW_OFFSET_L4 == m_ctx->layer)
	{
		if (sw_offset_rule_info_l4[port][id].offset == from)
		{
			SW_STATADD(sw_offset_rule_info_l4[port][id].match_cnt);
			m_ctx->matched = 1;
			return -1;
		}
	}
	else if (SW_OFFSET_L3 == m_ctx->layer)
	{
		if (sw_offset_rule_info_l3[port][id].offset == from)
		{
			SW_STATADD(sw_offset_rule_info_l3[port][id].match_cnt);
			m_ctx->matched = 1;
			return -1;
		}
	}
	else if (SW_OFFSET_L2 == m_ctx->layer)
	{
		if (sw_offset_rule_info_l2[port][id].offset == from)
		{
			SW_STATADD(sw_offset_rule_info_l2[port][id].match_cnt);
			m_ctx->matched = 1;
			return -1;
		}
	}

	//return 0 continue scan
	return 0;
}

int sw_offset_match(uint16_t portid, int thread_id, PKT_INFO_S* pkt_info)
{
	SW_OFFSET_MATCH_CTX ctx;
	ctx.port = portid;
	ctx.matched = 0;
	hs_database_t * db = NULL;
	hs_error_t err;

//scan_l4:
	if (NULL == pkt_info->l4 || 0 == pkt_info->trans_len)
		goto scan_l3;
	
	db = hs_db_l4[portid];
	if (db)
	{
		ctx.layer = (uint16_t)SW_OFFSET_L4;
		err = hs_scan(db, (const char*)(pkt_info->l4), pkt_info->trans_len, 0, hs_scratch_l4[portid][thread_id], 
			hyperscan_callback, (void *)&ctx);

		if (err != HS_SUCCESS && err != HS_SCAN_TERMINATED)
		{
			SW_OFFSET_Log_Error("hyperscan Search, HS SCAN error, err %d!\n", err);
			return -1;
		}

		if (ctx.matched)
			return 0;
			
			//int i;
			//printf("\n\n=================================\n");
			//for (i = 0; i < pkt_info->trans_len; i++)
			//{
			//	printf("%x ", pkt_info->l4[i]);
			//	if (i && i % 16 == 0)
			//		printf("\n");
			//}			
	}

scan_l3:
	if (NULL == pkt_info->l3 || 0 == pkt_info->net_len)
		goto scan_l2;
	
	db = hs_db_l3[portid];
	if (db)
	{
		ctx.layer = (uint16_t)SW_OFFSET_L3;
		err = hs_scan(db, (const char*)(pkt_info->l3), pkt_info->net_len, 0, hs_scratch_l3[portid][thread_id], 
			hyperscan_callback, (void *)&ctx);

		if (err != HS_SUCCESS && err != HS_SCAN_TERMINATED)
		{
			SW_OFFSET_Log_Error("hyperscan Search, HS SCAN error, err %d!\n", err);
			return -1;
		}
		
		if (ctx.matched)
			return 0;
	}

scan_l2:
	if (NULL == pkt_info->l2 || 0 == pkt_info->trans_len)
		return -1;
	
	db = hs_db_l2[portid];
	if (db)
	{
		ctx.layer = (uint16_t)SW_OFFSET_L2;
		err = hs_scan(db, (const char*)(pkt_info->l2), pkt_info->pkt_len, 0, hs_scratch_l2[portid][thread_id], 
			hyperscan_callback, (void *)&ctx);

		if (err != HS_SUCCESS && err != HS_SCAN_TERMINATED)
		{
			SW_OFFSET_Log_Error("hyperscan Search, HS SCAN error, err %d!\n", err);
			return -1;
		}
		
		if (ctx.matched)
			return 0;
	}

	return 0;
}

int sw_offset_init(const char* cfg_path)
{
	if (NULL == cfg_path)
	{
		SW_OFFSET_Log_Error("cfg_path null error!\n");
		return -1;
	}

	if (0 != sw_offset_conf_init(cfg_path))
	{
		SW_OFFSET_Log_Error("sw_offset_conf_init error!\n");
		return -1;
	}

	sw_command_register_show_offset(sw_offset_cmd_show_stat);

	return 0;
}

