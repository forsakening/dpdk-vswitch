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

int sw_offset_match(uint16_t portid, int thread_id, PKT_INFO_S* pkt_info);

int sw_offset_init(const char *);

#endif
