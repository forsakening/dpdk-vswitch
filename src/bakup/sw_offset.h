#ifndef __SW_OFFSET_H__
#define __SW_OFFSET_H__

#include "sw_parse.h"
#include "sw_command.h"

#define SW_OFFSET_Log_Error(fmt,...) printf("\033[0;32;31m[SWOFFS ERROR] \033[m"fmt, ##__VA_ARGS__)
#define SW_OFFSET_Log_Info(fmt,...) printf("\033[0;32;32m[SWOFFS INFO] \033[m"fmt, ##__VA_ARGS__)

extern cmdline_parse_inst_t cmd_show_offset;
struct cmd_show_offset_result {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t offset;
	cmdline_fixed_string_t port;
	uint16_t port_id;
};

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
// rule:    offset rule
// error:   if function add error, string error will set
// err_len: error string buffer length
// return 0  : add ok
// return -1 : add error
int sw_offset_dynamic_add_rule(char* rule, char* error, int err_len);

int sw_offset_match(uint16_t portid, int thread_id, PKT_INFO_S* pkt_info);

int sw_offset_init(const char *);

#endif
