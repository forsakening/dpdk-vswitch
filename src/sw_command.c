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

#include "sw_dpdk.h"
#include "sw_command.h"
#include "sw_filter.h"
#include "sw_offset.h"

#define SW_CMD_MAGIC       0xabcdbeef
#define SW_CMD_SERVER_PORT 12345  

static void _strip(char *str) {
	int i = 0;
	for (i = 0; i < strlen(str); ++i) {
		if (str[i] == '\r' || str[i] == '\n' || str[i] == ' ' || str[i] == '\t') {
			str[i] = 0;
			return;
		}
	}
}

int _get_fd_message(struct cmdline *cl, const char *prompt, char *recvbuf, int buflen) {
	memset(recvbuf, 0, buflen);
	cmdline_printf(cl, "###############################################################################################\n");
	cmdline_printf(cl, prompt);
	int ret = 0;
	while (1) {
		ret = recv(cl->s_out, recvbuf, buflen, 0);
		_strip(recvbuf);
		//printf("_get_fd_message : %s len: %d ret: %d\n", recvbuf, strlen(recvbuf), ret);
		if (ret == 0) {
			ret = -1;
			break;
		}
		if (strlen(recvbuf) != 0 && 32 <= recvbuf[0] && recvbuf[0] <= 126) {
			printf("_get_fd_message : %s len: %d ret: %d\n", recvbuf, strlen(recvbuf), ret);
			break;
		}
	}
	if (strcmp("exit", recvbuf) == 0)
		return -1;

	return ret;
}

static void sw_command_server_handle(int fd);


int execute(const char* cmd, char *outbuf) {
	FILE *fp;
    char buf[1024];
	int index = 0;
    if ((fp = popen(cmd, "r")) == NULL) {
        perror("popen failed");
        return -1;
    }
    while (fgets(buf, 1024, fp) != NULL) {
		memcpy(outbuf + index, buf, strlen(buf));
		index += strlen(buf);
    }
    if (pclose(fp) == -1) {
        perror("pclose failed");
        return -2;
    }
    return 0;
}


/*** quit ***/
/* exit application */

struct cmd_quit_result {
	cmdline_fixed_string_t quit;
};

static void
cmd_quit_parsed(__attribute__((unused)) void *parsed_result,
		struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	cmdline_quit(cl);
	printf("EXIT !\n");
	sleep(1);
	exit(1);
}

cmdline_parse_token_string_t cmd_quit_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_quit_result, quit,
				 "quit");

cmdline_parse_inst_t cmd_quit = {
	.f = cmd_quit_parsed,  /* function to call */
	.data = NULL,      /* 2nd arg of func */
	.help_str = "exit application",
	.tokens = {        /* token list, NULL terminated */
		(void *)&cmd_quit_tok,
		NULL,
	},
};



/*** clear_history ***/
/* clears history buffer */

struct cmd_clear_history_result {
	cmdline_fixed_string_t str;
};

static void
cmd_clear_history_parsed(__attribute__((unused)) void *parsed_result,
		struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	rdline_clear_history(&cl->rdl);
}

cmdline_parse_token_string_t cmd_clear_history_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_clear_history_result, str,
				 "clear_history");

cmdline_parse_inst_t cmd_clear_history = {
	.f = cmd_clear_history_parsed,  /* function to call */
	.data = NULL,      /* 2nd arg of func */
	.help_str = "clear command history",
	.tokens = {        /* token list, NULL terminated */
		(void *)&cmd_clear_history_tok,
		NULL,
	},
};

/* show port stats */
struct cmd_show_port_stats_result {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t stats;
	uint16_t port_id;
};

cmdline_parse_token_string_t cmd_show_port_stats_show =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_port_stats_result,
		 show, "show");
cmdline_parse_token_string_t cmd_show_port_stats_port =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_port_stats_result,
		 port, "port");
cmdline_parse_token_string_t cmd_show_port_stats_stats =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_port_stats_result,
		 stats, "stats");
cmdline_parse_token_num_t cmd_show_port_stats_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_show_port_stats_result,
		 port_id, UINT16);

static void
cmd_show_port_stats_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_show_port_stats_result* res = parsed_result;
	res->port_id = htons(res->port_id);

	int len = 0;
	char buf[SW_CMD_BUFF_LEN] = {0};
	sw_command_client_send_and_recv(SW_CMD_TYPE_SHOW_PORT, res, 
									sizeof(struct cmd_show_port_stats_result), 
									buf, SW_CMD_BUFF_LEN, &len, SW_CMD_TIMEOUT);

	cmdline_printf(cl, "%s\n", buf);
	
	//if (NULL != sw_cmd_func_map.show_port)
	//	sw_cmd_func_map.show_port(portid);
}

cmdline_parse_inst_t cmd_show_port_stats = {
	.f = cmd_show_port_stats_parsed,
	.data = NULL,
	.help_str = "show port stats <port_id>",
	.tokens = {
		(void *)&cmd_show_port_stats_show,
		(void *)&cmd_show_port_stats_port,
		(void *)&cmd_show_port_stats_stats,
		(void *)&cmd_show_port_stats_port_id,
		NULL,
	},
};

//show fwd id
///////////////////////////////////////
struct cmd_show_fwd_result {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t fwd;
	uint16_t port_id;
};

cmdline_parse_token_string_t cmd_show_fwd_show =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_fwd_result,
		 show, "show");
cmdline_parse_token_string_t cmd_show_fwd_fwd =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_fwd_result,
		 fwd, "fwd");
cmdline_parse_token_num_t cmd_show_fwd_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_show_fwd_result,
		 port_id, UINT16);

static void
cmd_show_fwd_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_show_fwd_result* res = parsed_result;
	//res->port_id = htons(res->port_id);

	int len = 0;
	char buf[SW_CMD_BUFF_LEN] = {0};
	sw_command_client_send_and_recv(SW_CMD_TYPE_SHOW_FWD, res, 
									sizeof(struct cmd_show_fwd_result), 
									buf, SW_CMD_BUFF_LEN, &len, SW_CMD_TIMEOUT);

	cmdline_printf(cl, "%s\n", buf);
	
	//if (NULL != sw_cmd_func_map.show_port)
	//	sw_cmd_func_map.show_port(portid);
}

cmdline_parse_inst_t cmd_show_fwd = {
	.f = cmd_show_fwd_parsed,
	.data = NULL,
	.help_str = "show fwd <port_id>",
	.tokens = {
		(void *)&cmd_show_fwd_show,
		(void *)&cmd_show_fwd_fwd,
		(void *)&cmd_show_fwd_port_id,
		NULL,
	},
};

//set fwd port-id len lend_mode syn_mode acl_mode off_mode
///////////////////////////////////////
struct cmd_set_fwd_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t fwd;
	// uint16_t port_id;
	// uint16_t delay_s;
	// uint16_t loopback;
	// uint16_t len;
	// uint16_t len_mode;
	// uint16_t syn_mode;
	// uint16_t acl_mode;
	// uint16_t off_mode;
};

cmdline_parse_token_string_t cmd_set_fwd_set =
	TOKEN_STRING_INITIALIZER
		(struct cmd_set_fwd_result,
		 set, "set");
cmdline_parse_token_string_t cmd_set_fwd_fwd =
	TOKEN_STRING_INITIALIZER
		(struct cmd_set_fwd_result,
		 fwd, "fwd");
// cmdline_parse_token_num_t cmd_set_fwd_port_id =
// 	TOKEN_NUM_INITIALIZER
// 		(struct cmd_set_fwd_result,
// 		 port_id, UINT16);
// cmdline_parse_token_num_t cmd_set_fwd_delay =
// 	TOKEN_NUM_INITIALIZER
// 		(struct cmd_set_fwd_result,
// 		 delay_s, UINT16);
// cmdline_parse_token_num_t cmd_set_fwd_loopback =
// 	TOKEN_NUM_INITIALIZER
// 		(struct cmd_set_fwd_result,
// 		 loopback, UINT16);
// cmdline_parse_token_num_t cmd_set_fwd_len =
// 	TOKEN_NUM_INITIALIZER
// 		(struct cmd_set_fwd_result,
// 		 len, UINT16);
// cmdline_parse_token_num_t cmd_set_fwd_len_mode =
// 	TOKEN_NUM_INITIALIZER
// 		(struct cmd_set_fwd_result,
// 		 len_mode, UINT16);
// cmdline_parse_token_num_t cmd_set_fwd_syn_mode =
// 	TOKEN_NUM_INITIALIZER
// 		(struct cmd_set_fwd_result,
// 		 syn_mode, UINT16);
// cmdline_parse_token_num_t cmd_set_fwd_acl_mode =
// 	TOKEN_NUM_INITIALIZER
// 		(struct cmd_set_fwd_result,
// 		 acl_mode, UINT16);
// cmdline_parse_token_num_t cmd_set_fwd_off_mode =
// 	TOKEN_NUM_INITIALIZER
// 		(struct cmd_set_fwd_result,
// 		 off_mode, UINT16);


struct cmd_set_fwd_result_x {
	uint16_t port_id;
	uint16_t delay_s;
	uint16_t loopback;
	uint16_t len;
	uint16_t len_mode;
    uint16_t max_len;
	uint16_t max_len_mode;
	uint16_t syn_mode;
	uint16_t acl_mode;
	uint16_t off_mode;
	uint16_t ipv6_mode;
	uint16_t vlan_offload_mode;
	uint16_t mpls_offload_mode;
};

static void
cmd_set_fwd_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_set_fwd_result* res = parsed_result;
	//res->port_id = htons(res->port_id);

	int len = 0;
	char buf[SW_CMD_BUFF_LEN] = {0};
	char recvbuf[256] = { 0 };

	if (_get_fd_message(cl, "Please Input Read PortId:\n", recvbuf, sizeof(recvbuf)) == -1)
		return;
	int portid = atoi(recvbuf);

	int delay_s = 0;
	while (1) {
		if (_get_fd_message(cl, "Please Input Delay Seconds: (0-10)\n", recvbuf, sizeof(recvbuf)) == -1)
			return;

		delay_s = atoi(recvbuf);
		if (delay_s < 0 || delay_s > 10) {
			continue;
		} else {
			break;
		}
	}
	int loopback = 0;
	while (1) {
		if (_get_fd_message(cl, "If You Need Loopback: (0 or 1)\n", recvbuf, sizeof(recvbuf)) == -1)
			return;

		loopback = atoi(recvbuf);
		if (loopback != 0 && loopback != 1) {
			continue;
		} else {
			break;
		}
	}

	int filter_length = 0;
	while (1) {
		if (_get_fd_message(cl, "Input Packet Filter Length: (60-1508)\n", recvbuf, sizeof(recvbuf)) == -1)
			return;

		filter_length = atoi(recvbuf);
		if (filter_length < 60 || filter_length > 1508) {
			continue;
		} else {
			break;
		}
	}
	
	int len_mode = 0;
	while (1) {
		if (_get_fd_message(cl, "Input Length Filter Mode: (0,disable 1,forward to rx port 2,forward to tx port 3,drop )\n", recvbuf, sizeof(recvbuf)) == -1)
			return;

		len_mode = atoi(recvbuf);
		if (len_mode != 0 && len_mode != 1 && len_mode != 2 && len_mode != 3) {
			continue;
		} else {
			break;
		}
	}

    int filter_max_length = 0;
	while (1) {
		if (_get_fd_message(cl, "Input Packet Filter Max Length: (60-1508)\n", recvbuf, sizeof(recvbuf)) == -1)
			return;

		filter_max_length = atoi(recvbuf);
		if (filter_max_length < 60 || filter_max_length > 1508) {
			continue;
		} else {
			break;
		}
	}
	
	int max_len_mode = 0;
	while (1) {
		if (_get_fd_message(cl, "Input Max Length Filter Mode: (0,disable 1,forward to rx port 2,forward to tx port 3,drop )\n", recvbuf, sizeof(recvbuf)) == -1)
			return;

		max_len_mode = atoi(recvbuf);
		if (max_len_mode != 0 && max_len_mode != 1 && max_len_mode != 2 && max_len_mode != 3) {
			continue;
		} else {
			break;
		}
	}

	int syn_mode = 0;
	while (1) {
		if (_get_fd_message(cl, "Input Syn Filter Mode: (0,disable 1,forward to rx port 2,forward to tx port 3,drop )\n", recvbuf, sizeof(recvbuf)) == -1)
			return;

		syn_mode = atoi(recvbuf);
		if (syn_mode != 0 && syn_mode != 1 && syn_mode != 2 && syn_mode != 3) {
			continue;
		} else {
			break;
		}
	}

	int acl_mode = 0;
	while (1) {
		if (_get_fd_message(cl, "Input Acl Filter Mode: (0,disable 1,forward to rx port 2,forward to tx port 3,drop )\n", recvbuf, sizeof(recvbuf)) == -1)
			return;

		acl_mode = atoi(recvbuf);
		if (acl_mode != 0 && acl_mode != 1 && acl_mode != 2 && acl_mode != 3) {
			continue;
		} else {
			break;
		}
	}

	int offset_mode = 0;
	while (1) {
		if (_get_fd_message(cl, "Input Offset Filter Mode: (0,disable 1,forward to rx port 2,forward to tx port 3,drop )\n", recvbuf, sizeof(recvbuf)) == -1)
			return;

		offset_mode = atoi(recvbuf);
		if (offset_mode != 0 && offset_mode != 1 && offset_mode != 2 && offset_mode != 3) {
			continue;
		} else {
			break;
		}
	}

    int ipv6_mode = 0;
	while (1) {
		if (_get_fd_message(cl, "Input IPv6 Filter Mode: (0,disable 1,forward to rx port 2,forward to tx port 3,drop )\n", recvbuf, sizeof(recvbuf)) == -1)
			return;

		ipv6_mode = atoi(recvbuf);
		if (ipv6_mode != 0 && ipv6_mode != 1 && ipv6_mode != 2 && ipv6_mode != 3) {
			continue;
		} else {
			break;
		}
	}

    int vlan_offload_mode = 0;
	while (1) {
		if (_get_fd_message(cl, "Input Vlan Offset Mode: (0,disable 1,offset the vlan head)\n", recvbuf, sizeof(recvbuf)) == -1)
			return;

		vlan_offload_mode = atoi(recvbuf);
		if (vlan_offload_mode != 0 && vlan_offload_mode != 1) {
			continue;
		} else {
			break;
		}
	}

    int mpls_offload_mode = 0;
	while (1) {
		if (_get_fd_message(cl, "Input Mpls Offset Mode: (0,disable 1,offset the mpls head)\n", recvbuf, sizeof(recvbuf)) == -1)
			return;

		mpls_offload_mode = atoi(recvbuf);
		if (mpls_offload_mode != 0 && mpls_offload_mode != 1) {
			continue;
		} else {
			break;
		}
	}
    
	struct cmd_set_fwd_result_x res_x = {0};
	res_x.port_id = portid;
	res_x.delay_s = delay_s;
	res_x.loopback = loopback;
	res_x.len = filter_length;
	res_x.len_mode = len_mode;
    res_x.max_len = filter_max_length;
	res_x.max_len_mode = max_len_mode;
	res_x.syn_mode = syn_mode;
	res_x.acl_mode = acl_mode;
	res_x.off_mode = offset_mode;
    res_x.ipv6_mode = ipv6_mode;
    res_x.vlan_offload_mode = vlan_offload_mode;
    res_x.mpls_offload_mode = mpls_offload_mode;
	
	sw_command_client_send_and_recv(SW_CMD_TYPE_SET_FWD, &res_x, 
									sizeof(struct cmd_set_fwd_result_x), 
									buf, SW_CMD_BUFF_LEN, &len, SW_CMD_TIMEOUT);

	printf("%s\n", buf);
	
	//if (NULL != sw_cmd_func_map.show_port)
	//	sw_cmd_func_map.show_port(portid);
}

cmdline_parse_inst_t cmd_set_fwd = {
	.f = cmd_set_fwd_parsed,
	.data = NULL,
	.help_str = "set fwd",
	.tokens = {
		(void *)&cmd_set_fwd_set,
		(void *)&cmd_set_fwd_fwd,
		// (void *)&cmd_set_fwd_port_id,
		// (void *)&cmd_set_fwd_delay,
		// (void *)&cmd_set_fwd_loopback,
		// (void *)&cmd_set_fwd_len,
		// (void *)&cmd_set_fwd_len_mode,
		// (void *)&cmd_set_fwd_syn_mode,
		// (void *)&cmd_set_fwd_acl_mode,
		// (void *)&cmd_set_fwd_off_mode,
		NULL,
	},
};

////////////////////////////////////////////////////////////////
/* kill self*/
struct cmd_kill_self_result {
	cmdline_fixed_string_t kill;
	cmdline_fixed_string_t self;
};

cmdline_parse_token_string_t cmd_kill_self_kill =
	TOKEN_STRING_INITIALIZER
		(struct cmd_kill_self_result,
		 kill, "kill");
cmdline_parse_token_string_t cmd_kill_self_self =
	TOKEN_STRING_INITIALIZER
		(struct cmd_kill_self_result,
		 self, "self");

static void
cmd_kill_self_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	int len = 0;
	char buf[SW_CMD_BUFF_LEN] = {0};
	sw_command_client_send_and_recv(SW_CMD_TYPE_KILL_SELF, parsed_result, 
									sizeof(struct cmd_kill_self_result), 
									buf, SW_CMD_BUFF_LEN, &len, SW_CMD_TIMEOUT);

	cmdline_printf(cl, "%s\n", buf);
}

cmdline_parse_inst_t cmd_kill_self = {
	.f = cmd_kill_self_parsed,
	.data = NULL,
	.help_str = "kill self",
	.tokens = {
		(void *)&cmd_kill_self_kill,
		(void *)&cmd_kill_self_self,
		NULL,
	},
};


/* show core mode stats */
struct cmd_show_core_mode_result {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t core;
	cmdline_fixed_string_t mode;
};

cmdline_parse_token_string_t cmd_show_core_mode_show =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_core_mode_result,
		 show, "show");
cmdline_parse_token_string_t cmd_show_core_mode_core =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_core_mode_result,
		 core, "core");
cmdline_parse_token_string_t cmd_show_core_mode_mode =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_core_mode_result,
		 mode, "mode");

static void
cmd_show_core_mode_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_show_core_mode_result* res = parsed_result;

	int len = 0;
	char buf[SW_CMD_BUFF_LEN] = {0};
	sw_command_client_send_and_recv(SW_CMD_TYPE_SHOW_CORE_MODE, res, 
									sizeof(struct cmd_show_core_mode_result), 
									buf, SW_CMD_BUFF_LEN, &len, SW_CMD_TIMEOUT);

	cmdline_printf(cl, "%s\n", buf);
}

cmdline_parse_inst_t cmd_show_core_mode = {
	.f = cmd_show_core_mode_parsed,
	.data = NULL,
	.help_str = "show core mode",
	.tokens = {
		(void *)&cmd_show_core_mode_show,
		(void *)&cmd_show_core_mode_core,
		(void *)&cmd_show_core_mode_mode,
		NULL,
	},
};

// ===================================
// show device
// ===================================
struct cmd_show_device_result {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t device;
};

cmdline_parse_token_string_t cmd_show_device_show =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_device_result,
		 show, "show");
cmdline_parse_token_string_t cmd_show_device_device =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_device_result,
		 device, "device");

static void
cmd_show_device_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	char outbuf[4096] = { 0 };
	FILE *pf;
	struct cmd_show_device_result* res = parsed_result;

	system("python /home/vswitch/usertools/getnic.py");
	pf = fopen("/home/vswitch/build/device.txt", "rb");
	if (pf) {
		fread(outbuf, 1, sizeof(outbuf), pf);
		cmdline_printf(cl, "%s", outbuf);
	} else {
		cmdline_printf(cl, "get device error\n", outbuf);
	}
}


cmdline_parse_inst_t cmd_show_device = {
	.f = cmd_show_device_parsed,
	.data = NULL,
	.help_str = "show device",
	.tokens = {
		(void *)&cmd_show_device_show,
		(void *)&cmd_show_device_device,
		NULL,
	},
};

// ===================================
// bind device
// ===================================
struct cmd_bind_device_result {
	cmdline_fixed_string_t bind;
	cmdline_fixed_string_t device;
	cmdline_fixed_string_t devicename;
};

cmdline_parse_token_string_t cmd_bind_device_bind =
	TOKEN_STRING_INITIALIZER
		(struct cmd_bind_device_result,
		 bind, "bind");
cmdline_parse_token_string_t cmd_bind_device_device =
	TOKEN_STRING_INITIALIZER
		(struct cmd_bind_device_result,
		 device, "device");
cmdline_parse_token_string_t cmd_bind_device_devicename =
	TOKEN_STRING_INITIALIZER
		(struct cmd_bind_device_result,
		 devicename, NULL);


static void
cmd_bind_device_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	char outbuf[4096] = { 0 };
	struct cmd_bind_device_result* res = parsed_result;
	char cmd[1024];
	sprintf(cmd, "python /home/vswitch/usertools/dpdk-devbind.py --bind=igb_uio %s", res->devicename);
	printf("%s\n", cmd);
	if (execute(cmd, outbuf) == 0) {
		cmdline_printf(cl, "ok\n");
	} else {
		cmdline_printf(cl, "bind device error\n");
	}

	system("python /home/vswitch/usertools/getnic.py");
	FILE *pf = fopen("/home/vswitch/build/device.txt", "rb");
	if (pf) {
		fread(outbuf, 1, sizeof(outbuf), pf);
		cmdline_printf(cl, "%s", outbuf);
	} else {
		cmdline_printf(cl, "get device error\n", outbuf);
	}
}

cmdline_parse_inst_t cmd_bind_device = {
	.f = cmd_bind_device_parsed,
	.data = NULL,
	.help_str = "bind device <devicename>",
	.tokens = {
		(void *)&cmd_bind_device_bind,
		(void *)&cmd_bind_device_device,
		(void *)&cmd_bind_device_devicename,
		NULL,
	},
};

// ===================================
// show io
// ===================================
struct cmd_show_io_result {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t io;
};

cmdline_parse_token_string_t cmd_show_io_show =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_io_result,
		 show, "show");
cmdline_parse_token_string_t cmd_show_io_io =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_io_result,
		 io, "io");

static void
cmd_show_io_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	char outbuf[4096] = { 0 };
	char line[1024] = { 0 };
	char tx_core_map_str[1024] = { 0 };
	char core[10] = { 0 };
	const char *conf_path = "/home/vswitch/conf/vswitch.conf";
	int i, j;
	SW_PORT_PEER tmp_conf[SW_DPDK_MAX_PORT] = {{0}};
	if (0 > sw_config_init(conf_path, (void *)tmp_conf))
	{
		cmdline_printf("Init Conf:%s error\n", conf_path);
		return;
	}
	for (i = 0; i < SW_DPDK_MAX_PORT; i++)
	{
		if (!tmp_conf[i].init)
			continue;
		memset(tx_core_map_str, 0, sizeof(tx_core_map_str));
		tx_core_map_str[0] = '[';
		for (j = 0; j < tmp_conf[i].tx_core_num; j++) {
			sprintf(core, "%u", tmp_conf[i].tx_core_map[j]);
			strcat(tx_core_map_str, core);
			if (j != tmp_conf[i].tx_core_num - 1) 
				strcat(tx_core_map_str, ",");
		}
		strcat(tx_core_map_str, "]");

		sprintf(line, "#%2u in_port: %u, out_port: %u, delay_seconds: %u, loopback: %u, read_core: %u, send_core_num: %u, send_cores: %s\n", i, 
									tmp_conf[i].rx_port, 		tmp_conf[i].tx_port,
									tmp_conf[i].delay_s, 		tmp_conf[i].loopback,  tmp_conf[i].rx_core,
									tmp_conf[i].tx_core_num, 	tx_core_map_str);
		strcat(outbuf, line);
	}
	cmdline_printf(cl, outbuf);
}


cmdline_parse_inst_t cmd_show_io = {
	.f = cmd_show_io_parsed,
	.data = NULL,
	.help_str = "show io",
	.tokens = {
		(void *)&cmd_show_io_show,
		(void *)&cmd_show_io_io,
		NULL,
	},
};

// ===================================
// show tmpio
// ===================================

struct cmd_show_tmpio_result {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t tmpio;
};

cmdline_parse_token_string_t cmd_show_tmpio_show =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_tmpio_result,
		 show, "show");
cmdline_parse_token_string_t cmd_show_tmpio_tmpio =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_tmpio_result,
		 tmpio, "tmpio");

SW_PORT_PEER the_tmp_conf[SW_DPDK_MAX_PORT] = {{0}};



static void
cmd_show_tmpio_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	char outbuf[4096] = { 0 };
	char line[1024] = { 0 };
	char tx_core_map_str[1024] = { 0 };
	char core[10] = { 0 };
	int i, j;
	
	for (i = 0; i < SW_DPDK_MAX_PORT; i++)
	{
		if (the_tmp_conf[i].tx_core_num == 0)
			continue;

		memset(tx_core_map_str, 0, sizeof(tx_core_map_str));
		tx_core_map_str[0] = '[';
		for (j = 0; j < the_tmp_conf[i].tx_core_num; j++) {
			//printf("the_tmp_conf[%u].tx_core_map[%u] = %u\n", i, j, the_tmp_conf[i].tx_core_map[j]);
			sprintf(core, "%u", the_tmp_conf[i].tx_core_map[j]);
			strcat(tx_core_map_str, core);
			if (j != the_tmp_conf[i].tx_core_num - 1) 
				strcat(tx_core_map_str, ",");
		}
		strcat(tx_core_map_str, "]");

		sprintf(line, "#%2u in_port: %u, out_port: %u, delay_seconds: %u, loopback: %u, read_core: %u, send_core_num: %u, send_cores: %s\n", i, 
									the_tmp_conf[i].rx_port, 		the_tmp_conf[i].tx_port,
									the_tmp_conf[i].delay_s, 		the_tmp_conf[i].loopback,  the_tmp_conf[i].rx_core, 
									the_tmp_conf[i].tx_core_num, 	tx_core_map_str);
		strcat(outbuf, line);
	}
	cmdline_printf(cl, outbuf);
}

cmdline_parse_inst_t cmd_show_tmpio = {
	.f = cmd_show_tmpio_parsed,
	.data = NULL,
	.help_str = "show tmpio",
	.tokens = {
		(void *)&cmd_show_tmpio_show,
		(void *)&cmd_show_tmpio_tmpio,
		NULL,
	},
};

// ========================
// set tmpio
// ========================
struct cmd_set_tmpio_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t tmpio;
	// uint16_t lineno;
	// uint16_t rx_port;
	// uint16_t tx_port;
	// uint16_t delay_s;
	// uint16_t loopback;
	// uint16_t rx_core;
	// uint16_t tx_core_num;
	// cmdline_fixed_string_t tx_core_map;
};

cmdline_parse_token_string_t cmd_set_tmpio_set =
	TOKEN_STRING_INITIALIZER
		(struct cmd_set_tmpio_result,
		 set, "set");
cmdline_parse_token_string_t cmd_set_tmpio_tmpio =
	TOKEN_STRING_INITIALIZER
		(struct cmd_set_tmpio_result,
		 tmpio, "tmpio");
// cmdline_parse_token_num_t cmd_set_tmpio_lineno =
// 	TOKEN_NUM_INITIALIZER
// 		(struct cmd_set_tmpio_result,
// 		 lineno, UINT16);
// cmdline_parse_token_num_t cmd_set_tmpio_rx_port =
// 	TOKEN_NUM_INITIALIZER
// 		(struct cmd_set_tmpio_result,
// 		 rx_port, UINT16);
// cmdline_parse_token_num_t cmd_set_tmpio_tx_port =
// 	TOKEN_NUM_INITIALIZER
// 		(struct cmd_set_tmpio_result,
// 		 tx_port, UINT16);
// cmdline_parse_token_num_t cmd_set_tmpio_delay_s =
// 	TOKEN_NUM_INITIALIZER
// 		(struct cmd_set_tmpio_result,
// 		 delay_s, UINT16);
// cmdline_parse_token_num_t cmd_set_tmpio_loopback =
// 	TOKEN_NUM_INITIALIZER
// 		(struct cmd_set_tmpio_result,
// 		 loopback, UINT16);
// cmdline_parse_token_num_t cmd_set_tmpio_rx_core =
// 	TOKEN_NUM_INITIALIZER
// 		(struct cmd_set_tmpio_result,
// 		 rx_core, UINT16);
// cmdline_parse_token_num_t cmd_set_tmpio_tx_core_num =
// 	TOKEN_NUM_INITIALIZER
// 		(struct cmd_set_tmpio_result,
// 		 tx_core_num, UINT16);
// cmdline_parse_token_string_t cmd_set_tmpio_tx_core_map =
// 	TOKEN_STRING_INITIALIZER
// 		(struct cmd_set_tmpio_result,
// 		 tx_core_map, NULL);
void _print_device(struct cmdline *cl) {
	char outbuf[4096] = { 0 };
	system("python /home/vswitch/usertools/getnic.py");
	FILE *pf = fopen("/home/vswitch/build/device.txt", "rb");
	if (pf) {
		fread(outbuf, 1, sizeof(outbuf), pf);
		cmdline_printf(cl, "%s", outbuf);
	} else {
		cmdline_printf(cl, "get device error\n", outbuf);
	}
}

int _check_core(int coreid) {
	int i, j;
	for (i = 0; i < SW_DPDK_MAX_PORT; i++)
	{
		if (the_tmp_conf[i].tx_core_num == 0)
			continue;
		
		if (the_tmp_conf[i].rx_core == coreid)
			return i;
		for (j = 0; j < the_tmp_conf[i].tx_core_num; j++) {
			//printf("the_tmp_conf[%u].tx_core_map[%u] = %u\n", i, j, the_tmp_conf[i].tx_core_map[j]);
			if (coreid == the_tmp_conf[i].tx_core_map[j])
				return i;
		}
	}
	return -1;
}

static void
cmd_set_tmpio_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	SW_PORT_PEER *confptr;
	int outbuf[1024] = { 0 };
	int recvbuf[1024] = { 0 };
	struct cmd_set_tmpio_result* res = parsed_result;
	int ret = 0;
	int fd = cl->s_out;
	// confptr = &the_tmp_conf[res->lineno];
	// confptr->rx_port = res->rx_port;	
	// confptr->tx_port = res->tx_port;
	// confptr->delay_s = res->delay_s;		
	// confptr->loopback = res->loopback;
	// confptr->rx_core = res->rx_core;
	// ret = sw_config_console_parse_tx_core_map(res->tx_core_map, confptr->tx_core_map);
	// if (ret == -1) {
	// 	cmdline_printf(cl, "parse_tx_core_map error\n");
	// 	return;
	// }
	// confptr->tx_core_num = ret;
	cmd_show_tmpio_parsed(0, cl, 0);

	int lineno = 0;
	while (1) {
		if (_get_fd_message(cl, "Please Input Tmpio Lineno: (0-23)\n", recvbuf, sizeof(recvbuf)) == -1)
			return;

		lineno = atoi(recvbuf);
		printf("lineno : %d\n", lineno);
		if (lineno < 0 || lineno > 23) {
			continue;
		} else {
			break;
		}
	}
	confptr = &the_tmp_conf[lineno];

	_print_device(cl);
	if (_get_fd_message(cl, "Please Input InPort Index:\n", recvbuf, sizeof(recvbuf)) == -1)
		return;
	int rx_port = atoi(recvbuf);
	//printf("rx_port : %d\n", rx_port);

	_print_device(cl);
	if (_get_fd_message(cl, "Please Input OutPort Index:\n", recvbuf, sizeof(recvbuf)) == -1)
		return;
	int tx_port = atoi(recvbuf);
	//printf("tx_port : %d\n", tx_port);

	int delay_s = 0;
	while (1) {
		if (_get_fd_message(cl, "Please Input Delay Seconds: (0-10)\n", recvbuf, sizeof(recvbuf)) == -1)
			return;

		delay_s = atoi(recvbuf);
		printf("delay_s : %d\n", delay_s);
		if (delay_s < 0 || delay_s > 10) {
			continue;
		} else {
			break;
		}
	}
	int loopback = 0;
	while (1) {
		if (_get_fd_message(cl, "If You Need Loopback: (0 or 1)\n", recvbuf, sizeof(recvbuf)) == -1)
			return;

		loopback = atoi(recvbuf);
		printf("loopback : %d\n", loopback);
		if (loopback != 0 && loopback != 1) {
			continue;
		} else {
			break;
		}
	}

	execute("lscpu | grep NUMA", outbuf);
	cmdline_printf(cl, "%s", outbuf);
	int rx_core = 0;
	while (1) {
		if (_get_fd_message(cl, "Please Input RX Core:\n", recvbuf, sizeof(recvbuf)) == -1)
			return;
		rx_core = atoi(recvbuf);
		int cret = _check_core(rx_core);
		if (cret == -1 || cret == lineno) {
			break;
		} else {
			cmdline_printf(cl, "Core %u is used by other port\n", rx_core);
		}
	}
	
	//printf("rx_core : %d\n", rx_core);
	while (1) {
		if (_get_fd_message(cl, "Please Input TX Cores: eg. 1,2,3\n", recvbuf, sizeof(recvbuf)) == -1)
			return;
		char tmpmap[128] = { 0 };
		tmpmap[0] = '[';
		strcat(tmpmap, recvbuf);
		strcat(tmpmap, "]");
		printf("TX Cores : %s\n", tmpmap);
		ret = sw_config_console_parse_tx_core_map(tmpmap, confptr->tx_core_map);
		if (ret == -1) {
			cmdline_printf(cl, "parse_tx_core_map error\n");
			continue;
		} else {
			confptr->tx_core_num = ret;
			int n = 0;
			int checkok = 1;
			for (n = 0; n < confptr->tx_core_num; ++n) {
				int coreid = confptr->tx_core_map[n];
				if (_check_core(coreid) != lineno) {
					cmdline_printf(cl, "Core %u is used by other port\n", coreid);
					checkok = 0;
					break;
				}
			}
			if (checkok) {
				break;
			}
		}
	}
	confptr->rx_port = rx_port;	
	confptr->tx_port = tx_port;
	confptr->delay_s = delay_s;		
	confptr->loopback = loopback;
	confptr->rx_core = rx_core;

	cmdline_printf(cl, "ok\n");
}

cmdline_parse_inst_t cmd_set_tmpio = {
	.f = cmd_set_tmpio_parsed,
	.data = NULL,
	.help_str = "set tmpio",
	.tokens = {
		(void *)&cmd_set_tmpio_set,
		(void *)&cmd_set_tmpio_tmpio,
		// (void *)&cmd_set_tmpio_lineno,
		// (void *)&cmd_set_tmpio_rx_port,
		// (void *)&cmd_set_tmpio_tx_port,
		// (void *)&cmd_set_tmpio_delay_s,
		// (void *)&cmd_set_tmpio_loopback,
		// (void *)&cmd_set_tmpio_rx_core,
		// (void *)&cmd_set_tmpio_tx_core_num,
		// (void *)&cmd_set_tmpio_tx_core_map,
		NULL,
	},
};


// ===================================
// save tmpio
// ===================================

struct cmd_save_tmpio_result {
	cmdline_fixed_string_t save;
	cmdline_fixed_string_t tmpio;
};

cmdline_parse_token_string_t cmd_save_tmpio_save =
	TOKEN_STRING_INITIALIZER
		(struct cmd_save_tmpio_result,
		 save, "save");
cmdline_parse_token_string_t cmd_save_tmpio_tmpio =
	TOKEN_STRING_INITIALIZER
		(struct cmd_save_tmpio_result,
		 tmpio, "tmpio");

static void
cmd_save_tmpio_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	int i, j;
	const char *confpath = "/home/vswitch/conf/vswitch.conf";
	FILE *pf;
	SW_PORT_PEER *confptr;
	char tx_core_map_str[1024] = { 0 };
	char core[10];
	
	pf = fopen(confpath, "wb");
	if (pf == NULL) {
		
		cmdline_printf(cl, "write file %s failed, Errno: %u, %s\n", confpath, errno, strerror(errno));
		return;
	}
	for (i = 0; i < SW_DPDK_MAX_PORT; i++) {
		confptr = &the_tmp_conf[i];
		if (confptr->tx_core_num == 0)
			continue;
		memset(tx_core_map_str, 0, sizeof(tx_core_map_str));
		tx_core_map_str[0] = '[';
		for (j = 0; j < the_tmp_conf[i].tx_core_num; j++) {
			sprintf(core, "%u", the_tmp_conf[i].tx_core_map[j]);
			strcat(tx_core_map_str, core);
			if (j != the_tmp_conf[i].tx_core_num - 1) 
				strcat(tx_core_map_str, " ");
		}
		strcat(tx_core_map_str, "]");

		fprintf(pf, "%u,%u,%u,%s,%u,%u\n", 
									the_tmp_conf[i].rx_port, 		the_tmp_conf[i].tx_port,
									the_tmp_conf[i].rx_core,
									tx_core_map_str,				the_tmp_conf[i].delay_s,
									the_tmp_conf[i].loopback);
	}
	fclose(pf);
	cmdline_printf(cl, "ok\n");
}

cmdline_parse_inst_t cmd_save_tmpio = {
	.f = cmd_save_tmpio_parsed,
	.data = NULL,
	.help_str = "save tmpio",
	.tokens = {
		(void *)&cmd_save_tmpio_save,
		(void *)&cmd_save_tmpio_tmpio,
		NULL,
	},
};

// ===================================
// clear tmpio
// ===================================

struct cmd_clear_tmpio_result {
	cmdline_fixed_string_t clear;
	cmdline_fixed_string_t tmpio;
};

cmdline_parse_token_string_t cmd_clear_tmpio_clear =
	TOKEN_STRING_INITIALIZER
		(struct cmd_clear_tmpio_result,
		 clear, "clear");
cmdline_parse_token_string_t cmd_clear_tmpio_tmpio =
	TOKEN_STRING_INITIALIZER
		(struct cmd_clear_tmpio_result,
		 tmpio, "tmpio");

static void
cmd_clear_tmpio_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	memset(the_tmp_conf, 0, sizeof(the_tmp_conf));
	cmdline_printf(cl, "ok\n");
}

cmdline_parse_inst_t cmd_clear_tmpio = {
	.f = cmd_clear_tmpio_parsed,
	.data = NULL,
	.help_str = "clear tmpio",
	.tokens = {
		(void *)&cmd_clear_tmpio_clear,
		(void *)&cmd_clear_tmpio_tmpio,
		NULL,
	},
};


// ===================================
// start vswitch
// ===================================
struct cmd_start_vswitch_result {
	cmdline_fixed_string_t start;
	cmdline_fixed_string_t vswitch;
	uint32_t pps;
};

cmdline_parse_token_string_t cmd_start_vswitch_start =
	TOKEN_STRING_INITIALIZER
		(struct cmd_start_vswitch_result,
		 start, "start");
cmdline_parse_token_string_t cmd_start_vswitch_vswitch =
	TOKEN_STRING_INITIALIZER
		(struct cmd_start_vswitch_result,
		 vswitch, "vswitch");
cmdline_parse_token_num_t cmd_start_vswitch_pps =
	TOKEN_NUM_INITIALIZER
		(struct cmd_start_vswitch_result,
		 pps, UINT32);

static void
cmd_start_vswitch_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	struct cmd_start_vswitch_result *res = parsed_result;
	char cmd[128] = { 0 };
	char outbuf[1024] = { 0 };
	int retry = 0;
	sprintf(cmd, "/home/vswitch/build/vswitch %u -d", res->pps);
	system(cmd);
	cmdline_printf(cl, "vswitch is starting, please wait... \n");
	sleep(1);
	while (retry < 60 * 3) {
		execute("cat /home/vswitch/build/runlog", outbuf);
		if (outbuf[0]) {
			break;
		} else {
			sleep(1);
			++retry;
		}
	}
	if (outbuf[0] == 0) {
		cmdline_printf(cl, "unknow stats: wait timeout\n");
	} else {
		cmdline_printf(cl, "%s\n", outbuf);
	}
}

cmdline_parse_inst_t cmd_start_vswitch = {
	.f = cmd_start_vswitch_parsed,
	.data = NULL,
	.help_str = "start vswitch <pps>",
	.tokens = {
		(void *)&cmd_start_vswitch_start,
		(void *)&cmd_start_vswitch_vswitch,
		(void *)&cmd_start_vswitch_pps,
		NULL,
	},
};


// ===================================
// set bind device
// ===================================
struct cmd_set_bind_device_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t bind;
	cmdline_fixed_string_t device;
	cmdline_fixed_string_t devicename;
};

cmdline_parse_token_string_t cmd_set_bind_device_set =
	TOKEN_STRING_INITIALIZER
		(struct cmd_set_bind_device_result,
		 set, "set");
cmdline_parse_token_string_t cmd_set_bind_device_bind =
	TOKEN_STRING_INITIALIZER
		(struct cmd_set_bind_device_result,
		 bind, "bind");
cmdline_parse_token_string_t cmd_set_bind_device_device =
	TOKEN_STRING_INITIALIZER
		(struct cmd_set_bind_device_result,
		 device, "device");
cmdline_parse_token_string_t cmd_set_bind_device_devicename =
	TOKEN_STRING_INITIALIZER
		(struct cmd_set_bind_device_result,
		 devicename, NULL);


static void
cmd_set_bind_device_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	char outbuf[4096] = { 0 };
	struct cmd_set_bind_device_result* res = parsed_result;
	FILE *pf;
	pf = fopen("/home/vswitch/conf/binddevice.conf", "a");
	sprintf(outbuf, "%s\n", res->devicename);
	fwrite(outbuf, 1, strlen(outbuf), pf);
	fclose(pf);
	cmdline_printf(cl, "ok\n");
}

cmdline_parse_inst_t cmd_set_bind_device = {
	.f = cmd_set_bind_device_parsed,
	.data = NULL,
	.help_str = "set bind device <devicename>",
	.tokens = {
		(void *)&cmd_set_bind_device_set,
		(void *)&cmd_set_bind_device_bind,
		(void *)&cmd_set_bind_device_device,
		(void *)&cmd_set_bind_device_devicename,
		NULL,
	},
};


// ===================================
// show bind device
// ===================================
struct cmd_show_bind_device_result {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t bind;
	cmdline_fixed_string_t device;
};

cmdline_parse_token_string_t cmd_show_bind_device_show =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_bind_device_result,
		 show, "show");
cmdline_parse_token_string_t cmd_show_bind_device_bind =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_bind_device_result,
		 bind, "bind");
cmdline_parse_token_string_t cmd_show_bind_device_device =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_bind_device_result,
		 device, "device");

static void
cmd_show_bind_device_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	char outbuf[4096] = { 0 };
	FILE *pf;
	pf = fopen("/home/vswitch/conf/binddevice.conf", "rb");
	if (pf) {
		fread(outbuf, 1, sizeof(outbuf), pf);
		fclose(pf);
		cmdline_printf(cl, "%s\n", outbuf);
	}
}

cmdline_parse_inst_t cmd_show_bind_device = {
	.f = cmd_show_bind_device_parsed,
	.data = NULL,
	.help_str = "show bind device",
	.tokens = {
		(void *)&cmd_show_bind_device_show,
		(void *)&cmd_show_bind_device_bind,
		(void *)&cmd_show_bind_device_device,
		NULL,
	},
};


// ===================================
// clear bind device
// ===================================
struct cmd_clear_bind_device_result {
	cmdline_fixed_string_t clear;
	cmdline_fixed_string_t bind;
	cmdline_fixed_string_t device;
};

cmdline_parse_token_string_t cmd_clear_bind_device_clear =
	TOKEN_STRING_INITIALIZER
		(struct cmd_clear_bind_device_result,
		 clear, "clear");
cmdline_parse_token_string_t cmd_clear_bind_device_bind =
	TOKEN_STRING_INITIALIZER
		(struct cmd_clear_bind_device_result,
		 bind, "bind");
cmdline_parse_token_string_t cmd_clear_bind_device_device =
	TOKEN_STRING_INITIALIZER
		(struct cmd_clear_bind_device_result,
		 device, "device");

static void
cmd_clear_bind_device_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	char outbuf[4096] = { 0 };
	FILE *pf;
	pf = fopen("/home/vswitch/conf/binddevice.conf", "wb");
	fclose(pf);
	cmdline_printf(cl, "ok\n");
}

cmdline_parse_inst_t cmd_clear_bind_device = {
	.f = cmd_clear_bind_device_parsed,
	.data = NULL,
	.help_str = "clear bind device",
	.tokens = {
		(void *)&cmd_clear_bind_device_clear,
		(void *)&cmd_clear_bind_device_bind,
		(void *)&cmd_clear_bind_device_device,
		NULL,
	},
};

// ===================================
// set password
// ===================================
struct cmd_set_password_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t password;
	cmdline_fixed_string_t newpwd;
};

cmdline_parse_token_string_t cmd_set_password_set =
	TOKEN_STRING_INITIALIZER
		(struct cmd_set_password_result,
		 set, "set");
cmdline_parse_token_string_t cmd_set_password_password =
	TOKEN_STRING_INITIALIZER
		(struct cmd_set_password_result,
		 password, "password");
cmdline_parse_token_string_t cmd_set_password_newpwd =
	TOKEN_STRING_INITIALIZER
		(struct cmd_set_password_result,
		 newpwd, NULL);

static void
cmd_set_password_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	char outbuf[4096] = { 0 };
	struct cmd_set_password_result* res = parsed_result;
	FILE *pf;
	pf = fopen("/home/vswitch/conf/password.conf", "wb");
	fprintf(pf, "%s", res->newpwd);
	fclose(pf);
	cmdline_printf(cl, "ok\n");
}

cmdline_parse_inst_t cmd_set_password = {
	.f = cmd_set_password_parsed,
	.data = NULL,
	.help_str = "set password [newpassword]",
	.tokens = {
		(void *)&cmd_set_password_set,
		(void *)&cmd_set_password_password,
		(void *)&cmd_set_password_newpwd,
		NULL,
	},
};

// ===================================
// show numa
// ===================================
struct cmd_show_numa_result {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t numa;
	cmdline_fixed_string_t devicename;
};

cmdline_parse_token_string_t cmd_show_numa_show =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_numa_result,
		 show, "show");
cmdline_parse_token_string_t cmd_show_numa_numa =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_numa_result,
		 numa, "numa");
cmdline_parse_token_string_t cmd_show_numa_devicename =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_numa_result,
		 devicename, NULL);

static void
cmd_show_numa_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	char outbuf[4096] = { 0 };
	char cmd[1024] = {0};
	struct cmd_show_numa_result* res = parsed_result;
	sprintf(cmd, "cat /sys/class/net/%s/device/numa_node", res->devicename);
	execute(cmd, outbuf);
	cmdline_printf(cl, "%s\n", outbuf);
}

cmdline_parse_inst_t cmd_show_numa = {
	.f = cmd_show_numa_parsed,
	.data = NULL,
	.help_str = "show numa [devicename]",
	.tokens = {
		(void *)&cmd_show_numa_show,
		(void *)&cmd_show_numa_numa,
		(void *)&cmd_show_numa_devicename,
		NULL,
	},
};


////////////////////////////////////////////////////////////////
/* show portpeer*/
struct cmd_show_portpeer_result {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t portpeer;
};

cmdline_parse_token_string_t cmd_show_portpeer_show =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_portpeer_result,
		 show, "show");
cmdline_parse_token_string_t cmd_show_portpeer_portpeer =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_portpeer_result,
		 portpeer, "portpeer");

static void
cmd_show_portpeer_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	int len = 0;
	char buf[SW_CMD_BUFF_LEN] = {0};
	sw_command_client_send_and_recv(SW_CMD_TYPE_SHOW_PORTPEER, parsed_result, 
									sizeof(struct cmd_show_portpeer_result), 
									buf, SW_CMD_BUFF_LEN, &len, SW_CMD_TIMEOUT);

	cmdline_printf(cl, "%s\n", buf);
}

cmdline_parse_inst_t cmd_show_portpeer = {
	.f = cmd_show_portpeer_parsed,
	.data = NULL,
	.help_str = "show portpeer",
	.tokens = {
		(void *)&cmd_show_portpeer_show,
		(void *)&cmd_show_portpeer_portpeer,
		NULL,
	},
};

////////////////////////////////////////////////////////////////
/* show systeminfo*/
struct cmd_show_systeminfo_result {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t systeminfo;
};

cmdline_parse_token_string_t cmd_show_systeminfo_show =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_systeminfo_result,
		 show, "show");
cmdline_parse_token_string_t cmd_show_systeminfo_systeminfo =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_systeminfo_result,
		 systeminfo, "systeminfo");

static void
cmd_show_systeminfo_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	char outbuf[4096] = { 0 };
	cmdline_printf(cl, "====== meminfo ======\n");
	execute("cat /proc/meminfo | grep Mem", outbuf);
	cmdline_printf(cl, "%s\n", outbuf);
	memset(outbuf, 0, sizeof(outbuf));
	execute("cat /proc/meminfo | grep Huge", outbuf);
	cmdline_printf(cl, "%s\n", outbuf);
	memset(outbuf, 0, sizeof(outbuf));
	cmdline_printf(cl, "====== numainfo ======\n");
	execute("numactl --hardware", outbuf);
	cmdline_printf(cl, "%s\n", outbuf);
	memset(outbuf, 0, sizeof(outbuf));
	cmdline_printf(cl, "====== temperature ======\n");
	execute("sensors", outbuf);
	cmdline_printf(cl, "%s\n", outbuf);
}

cmdline_parse_inst_t cmd_show_systeminfo = {
	.f = cmd_show_systeminfo_parsed,
	.data = NULL,
	.help_str = "show systeminfo",
	.tokens = {
		(void *)&cmd_show_systeminfo_show,
		(void *)&cmd_show_systeminfo_systeminfo,
		NULL,
	},
};


////////////////////////////////////////////////////////////////
/* show huagepage*/
struct cmd_show_hugepage_result {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t hugepage;
};

cmdline_parse_token_string_t cmd_show_hugepage_show =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_hugepage_result,
		 show, "show");
cmdline_parse_token_string_t cmd_show_hugepage_hugepage =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_hugepage_result,
		 hugepage, "hugepage");

static void
cmd_show_hugepage_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	char outbuf[4096] = { 0 };
	cmdline_printf(cl, "================= numainfo ==============\n", outbuf);
	execute("numactl --hardware", outbuf);
	cmdline_printf(cl, "%s\n", outbuf);
	cmdline_printf(cl, "=========================================\n", outbuf);
	memset(outbuf, 0, sizeof(outbuf));
	execute("grep -i 'echo' /etc/rc.local", outbuf);
	cmdline_printf(cl, "%s\n", outbuf);
}

cmdline_parse_inst_t cmd_show_hugepage = {
	.f = cmd_show_hugepage_parsed,
	.data = NULL,
	.help_str = "show hugepage",
	.tokens = {
		(void *)&cmd_show_hugepage_show,
		(void *)&cmd_show_hugepage_hugepage,
		NULL,
	},
};


////////////////////////////////////////////////////////////////
/* set huagepage*/
struct cmd_set_hugepage_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t hugepage;
	uint16_t	mem_G;
	uint16_t 	numanode;
};

cmdline_parse_token_string_t cmd_set_hugepage_set =
	TOKEN_STRING_INITIALIZER
		(struct cmd_set_hugepage_result,
		 set, "set");
cmdline_parse_token_string_t cmd_set_hugepage_hugepage =
	TOKEN_STRING_INITIALIZER
		(struct cmd_set_hugepage_result,
		 hugepage, "hugepage");
cmdline_parse_token_num_t cmd_set_hugepage_mem =
	TOKEN_NUM_INITIALIZER
		(struct cmd_set_hugepage_result,
		 mem_G, UINT16);
cmdline_parse_token_num_t cmd_set_hugepage_numanode=
	TOKEN_NUM_INITIALIZER
		(struct cmd_set_hugepage_result,
		 numanode, UINT16);

static void
cmd_set_hugepage_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	char cmd[4096] = { 0 };
	char outbuf[4096] = { 0 };
	struct cmd_set_hugepage_result *res = parsed_result;
	// sed -i 's/echo.*node0.*/echo 8 > \/sys\/devices\/system\/node\/node0\/hugepages\/hugepages-1048576kB\/nr_hugepages/g' /etc/rc.local
	sprintf(cmd, "sed -i 's/echo.*node%u.*/echo %u > \\/sys\\/devices\\/system\\/node\\/node%u\\/hugepages\\/hugepages-1048576kB\\/nr_hugepages/g' /etc/rc.local",
			 res->numanode, res->mem_G, res->numanode);
	system(cmd);
	sprintf(cmd, "echo %u > /sys/devices/system/node/node%u/hugepages/hugepages-1048576kB/nr_hugepages",
			 res->mem_G, res->numanode);
	system(cmd);
	execute("grep -i 'echo' /etc/rc.local", outbuf);
	cmdline_printf(cl, "%s\n", outbuf);
}

cmdline_parse_inst_t cmd_set_hugepage = {
	.f = cmd_set_hugepage_parsed,
	.data = NULL,
	.help_str = "set hugepage <mem_G> <numanode>",
	.tokens = {
		(void *)&cmd_set_hugepage_set,
		(void *)&cmd_set_hugepage_hugepage,
		(void *)&cmd_set_hugepage_mem,
		(void *)&cmd_set_hugepage_numanode,
		NULL,
	},
};


////////////////////////////////////////////////////////////////
/* unbind device */
struct cmd_unbind_device_result {
	cmdline_fixed_string_t unbind;
	cmdline_fixed_string_t device;
	cmdline_fixed_string_t devicename;
};

cmdline_parse_token_string_t cmd_unbind_device_unbind =
	TOKEN_STRING_INITIALIZER
		(struct cmd_unbind_device_result,
		 unbind, "unbind");
cmdline_parse_token_string_t cmd_unbind_device_device =
	TOKEN_STRING_INITIALIZER
		(struct cmd_unbind_device_result,
		 device, "device");
cmdline_parse_token_string_t cmd_unbind_device_devicename =
	TOKEN_STRING_INITIALIZER
		(struct cmd_unbind_device_result,
		 devicename, NULL);

static void
cmd_unbind_device_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	char cmd[4096] = { 0 };
	char outbuf[4096] = { 0 };
	struct cmd_unbind_device_result *res = parsed_result;
	char id[32] = { 0 };
	char driver[32] = { 0 };

	sprintf(cmd, "python /home/vswitch/usertools/getnic.py | grep %s", res->devicename);
	execute(cmd, outbuf);
	if (strlen(outbuf) == 0) {
		cmdline_printf(cl, "Error: can't find device '%s'\n", res->devicename);
		return;
	}
	char *idstart = strstr(outbuf, "id: ");
	if (!idstart) {
		cmdline_printf(cl, "Error: device '%s' id error\n", res->devicename);
		return;
	}
	idstart += strlen("id: ");
	char *end = strstr(idstart, " ");
	memcpy(id, idstart, end - idstart);

	char *drvstart = strstr(outbuf, "driver: ");
	if (!drvstart) {
		cmdline_printf(cl, "Error: device '%s' is unbinded\n", res->devicename);
		return;
	}
	drvstart += strlen("driver: ");
	end = strstr(drvstart, "\n");
	memcpy(driver, drvstart, end - drvstart);
	sprintf(cmd, "python ../usertools/dpdk-devbind.py --bind=%s %s", driver, id);
	
	system(cmd);

	system("python /home/vswitch/usertools/getnic.py");
	FILE *pf = fopen("/home/vswitch/build/device.txt", "rb");
	if (pf) {
		fread(outbuf, 1, sizeof(outbuf), pf);
		cmdline_printf(cl, "%s", outbuf);
	} else {
		cmdline_printf(cl, "get device error\n", outbuf);
	}
}

cmdline_parse_inst_t cmd_unbind_device = {
	.f = cmd_unbind_device_parsed,
	.data = NULL,
	.help_str = "unbind device <devicename>",
	.tokens = {
		(void *)&cmd_unbind_device_unbind,
		(void *)&cmd_unbind_device_device,
		(void *)&cmd_unbind_device_devicename,
		NULL,
	},
};

// =======================================================
// snmp part
// =======================================================
////////////////////////////////////////////////////////////////
/* add snmpv3 user */
struct cmd_add_snmpv3_user_result {
	cmdline_fixed_string_t add;
	cmdline_fixed_string_t snmpv3;
	cmdline_fixed_string_t user;
	cmdline_fixed_string_t username;
	cmdline_fixed_string_t password;
	cmdline_fixed_string_t private;
};

cmdline_parse_token_string_t cmd_add_snmpv3_user_add =
	TOKEN_STRING_INITIALIZER
		(struct cmd_add_snmpv3_user_result,
		 add, "add");
cmdline_parse_token_string_t cmd_add_snmpv3_user_snmpv3 =
	TOKEN_STRING_INITIALIZER
		(struct cmd_add_snmpv3_user_result,
		 snmpv3, "snmpv3");
cmdline_parse_token_string_t cmd_add_snmpv3_user_user =
	TOKEN_STRING_INITIALIZER
		(struct cmd_add_snmpv3_user_result,
		 user, "user");
cmdline_parse_token_string_t cmd_add_snmpv3_user_username =
	TOKEN_STRING_INITIALIZER
		(struct cmd_add_snmpv3_user_result,
		 username, NULL);
cmdline_parse_token_string_t cmd_add_snmpv3_user_password =
	TOKEN_STRING_INITIALIZER
		(struct cmd_add_snmpv3_user_result,
		 password, NULL);
cmdline_parse_token_string_t cmd_add_snmpv3_user_private =
	TOKEN_STRING_INITIALIZER
		(struct cmd_add_snmpv3_user_result,
		 private, NULL);

static void
cmd_add_snmpv3_user_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	char cmd[4096] = { 0 };
	struct cmd_add_snmpv3_user_result *res = parsed_result;

	system("service snmpd stop");
	sprintf(cmd, "net-snmp-create-v3-user -ro -A %s -X %s -a MD5 -x DES %s", res->password, res->private, res->username);
	system(cmd);
	system("service snmpd start");
	cmdline_printf(cl, "ok\n");
}

cmdline_parse_inst_t cmd_add_snmpv3_user = {
	.f = cmd_add_snmpv3_user_parsed,
	.data = NULL,
	.help_str = "add snmpv3 user <username> <password> <private>",
	.tokens = {
		(void *)&cmd_add_snmpv3_user_add,
		(void *)&cmd_add_snmpv3_user_snmpv3,
		(void *)&cmd_add_snmpv3_user_user,
		(void *)&cmd_add_snmpv3_user_username,
		(void *)&cmd_add_snmpv3_user_password,
		(void *)&cmd_add_snmpv3_user_private,
		NULL,
	},
};


////////////////////////////////////////////////////////////////
/* show snmpv3 user */
struct cmd_show_snmpv3_user_result {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t snmpv3;
	cmdline_fixed_string_t user;
};

cmdline_parse_token_string_t cmd_show_snmpv3_user_show =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_snmpv3_user_result,
		 show, "show");
cmdline_parse_token_string_t cmd_show_snmpv3_user_snmpv3 =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_snmpv3_user_result,
		 snmpv3, "snmpv3");
cmdline_parse_token_string_t cmd_show_snmpv3_user_user =
	TOKEN_STRING_INITIALIZER
		(struct cmd_show_snmpv3_user_result,
		 user, "user");

static void
cmd_show_snmpv3_user_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	char outbuf[4096] = { 0 };
	struct cmd_add_snmpv3_user_result *res = parsed_result;

	execute("grep usmUser /var/lib/net-snmp/snmpd.conf | grep -o '\".*\" ' | grep -o ' \".*\"'", outbuf);
	cmdline_printf(cl, "snmpv3 username list:\n==========================\n%s\n", outbuf);
}

cmdline_parse_inst_t cmd_show_snmpv3_user = {
	.f = cmd_show_snmpv3_user_parsed,
	.data = NULL,
	.help_str = "show snmpv3 user",
	.tokens = {
		(void *)&cmd_show_snmpv3_user_show,
		(void *)&cmd_show_snmpv3_user_snmpv3,
		(void *)&cmd_show_snmpv3_user_user,
		NULL,
	},
};

////////////////////////////////////////////////////////////////
/* del snmpv3 user */
struct cmd_del_snmpv3_user_result {
	cmdline_fixed_string_t del;
	cmdline_fixed_string_t snmpv3;
	cmdline_fixed_string_t user;
	cmdline_fixed_string_t username;
};

cmdline_parse_token_string_t cmd_del_snmpv3_user_del =
	TOKEN_STRING_INITIALIZER
		(struct cmd_del_snmpv3_user_result,
		 del, "del");
cmdline_parse_token_string_t cmd_del_snmpv3_user_snmpv3 =
	TOKEN_STRING_INITIALIZER
		(struct cmd_del_snmpv3_user_result,
		 snmpv3, "snmpv3");
cmdline_parse_token_string_t cmd_del_snmpv3_user_user =
	TOKEN_STRING_INITIALIZER
		(struct cmd_del_snmpv3_user_result,
		 user, "user");
cmdline_parse_token_string_t cmd_del_snmpv3_user_username =
	TOKEN_STRING_INITIALIZER
		(struct cmd_del_snmpv3_user_result,
		 username, NULL);


static void
cmd_del_snmpv3_user_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	char cmd[4096] = { 0 };
	char outbuf[4096] = { 0 };
	struct cmd_del_snmpv3_user_result *res = parsed_result;
	system("service snmpd stop");
	sprintf(cmd, "sed -i '/^usmUser .* \"%s\"/d' /var/lib/net-snmp/snmpd.conf", res->username);
	system(cmd);
	sprintf(cmd, "sed -i '/^rouser %s/d' /etc/snmp/snmpd.conf", res->username);
	system(cmd);
	system("service snmpd start");
	cmdline_printf(cl, "ok\n");
}

cmdline_parse_inst_t cmd_del_snmpv3_user = {
	.f = cmd_del_snmpv3_user_parsed,
	.data = NULL,
	.help_str = "del snmpv3 user <username>",
	.tokens = {
		(void *)&cmd_del_snmpv3_user_del,
		(void *)&cmd_del_snmpv3_user_snmpv3,
		(void *)&cmd_del_snmpv3_user_user,
		(void *)&cmd_del_snmpv3_user_username,
		NULL,
	},
};

////////////////////////////////////////////////////////////////
/* set snmpv3 port */
struct cmd_set_snmpv3_port_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t snmpv3;
	cmdline_fixed_string_t port;
	uint16_t number;
};

cmdline_parse_token_string_t cmd_set_snmpv3_port_set =
	TOKEN_STRING_INITIALIZER
		(struct cmd_set_snmpv3_port_result,
		 set, "set");
cmdline_parse_token_string_t cmd_set_snmpv3_port_snmpv3 =
	TOKEN_STRING_INITIALIZER
		(struct cmd_set_snmpv3_port_result,
		 snmpv3, "snmpv3");
cmdline_parse_token_string_t cmd_set_snmpv3_port_port =
	TOKEN_STRING_INITIALIZER
		(struct cmd_set_snmpv3_port_result,
		 port, "port");
cmdline_parse_token_num_t cmd_set_snmpv3_port_number =
	TOKEN_NUM_INITIALIZER
		(struct cmd_set_snmpv3_port_result,
		 number, UINT16);


static void
cmd_set_snmpv3_port_parsed(
	void *parsed_result,
	__attribute__((unused)) struct cmdline *cl,
	__attribute__((unused)) void *data)
{
	char cmd[4096] = { 0 };
	char outbuf[4096] = { 0 };
	struct cmd_set_snmpv3_port_result *res = parsed_result;
	system("service snmpd stop");
	sprintf(cmd, "OPTIONS=\"udp:%u\"", res->number);
	FILE *f = fopen("/etc/sysconfig/snmpd", "wb");
	if (!f) {
		cmdline_printf(cl, "set snmp port failed : can't open /etc/sysconfig/snmpd\n");
	} else {
		fprintf(f, cmd);
		fclose(f);
		sprintf(cmd, "firewall-cmd --zone=public --add-port=%u/udp --permanent", res->number);
		system(cmd);
		system("firewall-cmd --reload");
	}
	system("service snmpd start");
	cmdline_printf(cl, "ok\n");
}

cmdline_parse_inst_t cmd_set_snmpv3_port = {
	.f = cmd_set_snmpv3_port_parsed,
	.data = NULL,
	.help_str = "set snmpv3 port <udpport>",
	.tokens = {
		(void *)&cmd_set_snmpv3_port_set,
		(void *)&cmd_set_snmpv3_port_snmpv3,
		(void *)&cmd_set_snmpv3_port_port,
		(void *)&cmd_set_snmpv3_port_number,
		NULL,
	},
};


/****************/

cmdline_parse_ctx_t vswitch_ctx[] = {
	(cmdline_parse_inst_t *)&cmd_clear_history,
//	(cmdline_parse_inst_t *)&cmd_quit,
	(cmdline_parse_inst_t *)&cmd_kill_self,	
	(cmdline_parse_inst_t *)&cmd_show_port_stats,
	(cmdline_parse_inst_t *)&cmd_show_core_mode,
	(cmdline_parse_inst_t *)&cmd_show_portpeer,
	(cmdline_parse_inst_t *)&cmd_show_systeminfo,
	(cmdline_parse_inst_t *)&cmd_show_hugepage,
//	(cmdline_parse_inst_t *)&cmd_set_acl,
	(cmdline_parse_inst_t *)&cmd_show_acl,
	(cmdline_parse_inst_t *)&cmd_add_acl,
	(cmdline_parse_inst_t *)&cmd_del_acl,
	(cmdline_parse_inst_t *)&cmd_show_offset,
	(cmdline_parse_inst_t *)&cmd_show_fwd,
	(cmdline_parse_inst_t *)&cmd_set_fwd,
	(cmdline_parse_inst_t *)&cmd_show_device,
	(cmdline_parse_inst_t *)&cmd_bind_device,
	(cmdline_parse_inst_t *)&cmd_unbind_device,
	(cmdline_parse_inst_t *)&cmd_set_bind_device,
	(cmdline_parse_inst_t *)&cmd_show_bind_device,
	(cmdline_parse_inst_t *)&cmd_clear_bind_device,
	(cmdline_parse_inst_t *)&cmd_show_io,
	(cmdline_parse_inst_t *)&cmd_show_tmpio,
	(cmdline_parse_inst_t *)&cmd_set_tmpio,
	(cmdline_parse_inst_t *)&cmd_save_tmpio,
	(cmdline_parse_inst_t *)&cmd_clear_tmpio,
	(cmdline_parse_inst_t *)&cmd_start_vswitch,
	(cmdline_parse_inst_t *)&cmd_set_password,
	(cmdline_parse_inst_t *)&cmd_set_hugepage,
	(cmdline_parse_inst_t *)&cmd_add_snmpv3_user,
	(cmdline_parse_inst_t *)&cmd_show_snmpv3_user,
	(cmdline_parse_inst_t *)&cmd_del_snmpv3_user,
	(cmdline_parse_inst_t *)&cmd_set_snmpv3_port,
	NULL,
};
// =================================================================================================================================================================================
// =================================================================================================================================================================================
// =================================================================================================================================================================================
// =================================================================================================================================================================================
// =================================================================================================================================================================================
// =================================================================================================================================================================================
// =================================================================================================================================================================================
// =================================================================================================================================================================================
// ======================================================================               Splitter                  ==================================================================
// =================================================================================================================================================================================
// =================================================================================================================================================================================
// =================================================================================================================================================================================
// =================================================================================================================================================================================
// =================================================================================================================================================================================
// =================================================================================================================================================================================
// =================================================================================================================================================================================
// =================================================================================================================================================================================
// =================================================================================================================================================================================
//cmd
typedef struct
{
	int magic;  //0xabcd1234
	int msg_len;
	SW_CMD_TYPE cmd_type;
	int cmd_len;
}SW_CMD_REQUEST;
//void* cmd_buf;

typedef struct
{
	int magic;  //0xabcd1234
	int msg_len;
}SW_CMD_RESPONSE;
//void* cmd_buf;

typedef struct
{	
	SW_CMD_SHOW_CORE_MODE show_core_mode;
	SW_CMD_SHOW_PORT show_port;
	SW_KILL_SELF kill_self;
	SW_CMD_SET_ACL set_acl;
	SW_CMD_SHOW_ACL show_acl;
	SW_CMD_SHOW_OFFSET show_off;
	SW_CMD_SHOW_FWD_RULE show_fwd;
	SW_CMD_SET_FWD_RULE set_fwd;
	SW_CMD_SHOW_PORTPEER_STATS show_portpeer;
}SW_CMD_FUNC_MAP;

SW_CMD_FUNC_MAP sw_cmd_func_map = {0};

static int sw_cmd_client_fd = -1;
static struct sockaddr_in sw_cmd_ser_addr;
static int sw_cmd_sock_len = sizeof(sw_cmd_ser_addr);

static void* sw_command_client_telnet_run(void* arg) 
{
	int fd = (int)arg;
	char password[128] = { 0 };
	char fpassword[128] = { 0 };
	FILE *passf;
	struct cmdline *cl = cmdline_new(vswitch_ctx, "\nVSWITCH > ", fd, fd);
	if (cl == NULL)
		return NULL;

	const char *conf_path = "/home/vswitch/conf/vswitch.conf";
	if (0 > sw_config_init(conf_path, (void *)the_tmp_conf))
	{
		cmdline_printf("Init Conf:%s error\n", conf_path);
	}

	cmdline_printf(cl, "\n\n");
	cmdline_printf(cl, "****************************************************\n");
	cmdline_printf(cl, "*********** WELCOME TO VSWITCH CONSOLE *************\n");
	cmdline_printf(cl, "****************************************************\n");
	cmdline_printf(cl, "\n\n");

	cmdline_printf(cl, "Please Input Password:\n");
	int ret = recv(fd, password, sizeof(password), 0);
	passf = fopen("/home/vswitch/conf/password.conf", "rb");
	if (passf) {
		int readc = fread(fpassword, 1, sizeof(fpassword), passf);
		int i;
		while (ret != -1 && ret != 0) {
			printf("Password is %s, Input is %s\n", fpassword, password);
			int pass = 1;
			for (i = 0; i < strlen(fpassword); ++i) {
				if (fpassword[i] != password[i]) {
					//cmdline_printf(cl, "Wrong Password 1 \n");
					pass = 0;
					break;
				}
			}
			if (password[i] != '\n' && password[i] != '\r' && password[i] != 0) {
				//cmdline_printf(cl, "Wrong Password 2 %c\n", password[i]);
				pass = 0;
			}
			if (pass == 1) {
				break;
			}
			
			cmdline_printf(cl, "Please Input Password:\n");
			ret = recv(fd, password, sizeof(password), 0);
		}
	}
	//cmdline_printf(cl, "Right Password\n");
	cmdline_printf(cl, "VSWITCH > ");

	cmdline_interact(cl);
	cmdline_quit(cl);
	cmdline_free(cl);
	printf("*********** QUIT VSWITCH CONSOLE *************\n");
	return NULL;
}


static void* sw_command_client_run(void* arg)
{
	FILE *pf;
	char buf[1024];
	char cmd[1024];

	if (arg)
		printf("Start to thread %s \n", __FUNCTION__);

	pf = fopen("/home/vswitch/conf/binddevice.conf", "rb");
	if (pf) {
		while (fgets(buf, 1024, pf) != NULL) {
			sprintf(cmd, "python ../usertools/dpdk-devbind.py --bind=igb_uio %s", buf);
			printf("%s\n", cmd);
			system(cmd);
		}
		fclose(pf);
	}

    sw_cmd_client_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sw_cmd_client_fd < 0)
    {
        printf("create socket fail!\n");
        return NULL;
    }

    memset(&sw_cmd_ser_addr, 0, sizeof(sw_cmd_ser_addr));
    sw_cmd_ser_addr.sin_family = AF_INET;
    //ser_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    sw_cmd_ser_addr.sin_addr.s_addr = htonl(INADDR_ANY);  //注意网络序转换
    sw_cmd_ser_addr.sin_port = htons(SW_CMD_SERVER_PORT);  //注意网络序转换

	//set nonblocking
	if (fcntl(sw_cmd_client_fd, F_SETFL, fcntl(sw_cmd_client_fd, F_GETFD, 0)|O_NONBLOCK) == -1)  
	{  
		printf("Set nonblock error!\n");
		return NULL;  
	}


	int sockfd, new_fd;/*socket����ͽ������Ӻ�ľ��?1?7*/  
    struct sockaddr_in my_addr;/*������ַ��Ϣ�ṹ�壬�����о�������Ը��?1?7*/  
    struct sockaddr_in their_addr;/*�Է���ַ��Ϣ*/  
    int sin_size;  
  
    sockfd = socket(AF_INET,SOCK_STREAM,0);//����socket   
    if(sockfd==-1){  
        printf("socket failed:%d",errno);  
        return -1;  
    }  

    my_addr.sin_family=AF_INET;/*�����Ա�ʾ���ձ�����������������*/  
    my_addr.sin_port=htons(1234);/*�˿ں�*/  
    my_addr.sin_addr.s_addr=htonl(INADDR_ANY);/*IP���������ݱ�ʾ����IP*/  
    bzero(&(my_addr.sin_zero),8);/*������������0*/  

    if(bind(sockfd,(struct sockaddr*)&my_addr,sizeof(struct sockaddr))<0){//�󶨵�ַ�ṹ���socket  
        printf("bind error");  
        return -1;  
    }  

    listen(sockfd, 10);//�������?1?7 ���ڶ�����������������   
    while(1){  
        sin_size = sizeof(struct sockaddr_in);  
        new_fd = accept(sockfd,(struct sockaddr*)&their_addr,&sin_size);//����������֪�����յ���Ϣ�������ֱ���socket��������յ��ĵ�ַ���?�Լ���Є1?7   
        if(new_fd == -1){  
            printf("accept failed");  
        } else{  
            printf("accept success");  
            //send(new_fd,"Hello World!",12,0);//�������ݣ������ֱ������Ӿ�������ݣ���С���������?����΄1?70���ɣ�   
			pthread_t threadid;
			if (0 != pthread_create(&threadid, NULL, sw_command_client_telnet_run, (void *)new_fd))
				return -1;
        }  
    }  
	
}

//创建socket 并等待处理消息
static void* sw_command_server_run(void* arg)
{
	if (arg)
		printf("Start to thread %s \n", __FUNCTION__);

	int server_fd, ret;
	struct sockaddr_in ser_addr; 

	server_fd = socket(AF_INET, SOCK_DGRAM, 0); //AF_INET:IPV4;SOCK_DGRAM:UDP
	if(server_fd < 0)
	{
		printf("create socket fail!\n");
		return NULL;
	}

	memset(&ser_addr, 0, sizeof(ser_addr));
	ser_addr.sin_family = AF_INET;
	ser_addr.sin_addr.s_addr = htonl(INADDR_ANY); //IP地址，需要进行网络序转换，INADDR_ANY：本地地址
	ser_addr.sin_port = htons(SW_CMD_SERVER_PORT);  //端口号，需要网络序转换

	ret = bind(server_fd, (struct sockaddr*)&ser_addr, sizeof(ser_addr));
	if(ret < 0)
	{
		printf("socket bind fail!\n");
		return NULL;
	}

	sw_command_server_handle(server_fd);
	
	close(server_fd);
	return NULL;
}


int sw_command_init(SW_CMD_ROLE role)
{
	pthread_t threadid;

	if (role == CMD_ROLE_SERVER)
	{
		if (0 != pthread_create(&threadid, NULL, sw_command_server_run, NULL))
			return -1;

		return 0;
	}
	else if (role == CMD_ROLE_CLIENT)
	{
		if (0 != pthread_create(&threadid, NULL, sw_command_client_run, NULL))
			return -1;

		return 0;
	}
	else
	{
		printf("ERROR Command Role:%d \n", role);
		return -1;
	}

	return 0;
}


int sw_command_register_show_core_mode(SW_CMD_SHOW_CORE_MODE func)
{
	if (sw_cmd_func_map.show_core_mode != NULL)
		return -1;

	sw_cmd_func_map.show_core_mode = func;
	return 0;
}

int sw_command_register_set_acl(SW_CMD_SET_ACL func)
{
	if (sw_cmd_func_map.set_acl != NULL)
		return -1;

	sw_cmd_func_map.set_acl = func;
	return 0;
}

int sw_command_register_show_acl(SW_CMD_SHOW_ACL func)
{
	if (sw_cmd_func_map.show_acl != NULL)
		return -1;

	sw_cmd_func_map.show_acl = func;
	return 0;
}

int sw_command_register_show_offset(SW_CMD_SHOW_OFFSET func)
{
	if (sw_cmd_func_map.show_off != NULL)
		return -1;

	sw_cmd_func_map.show_off = func;
	return 0;
}


int sw_command_register_show_port(SW_CMD_SHOW_PORT func)
{
	if (sw_cmd_func_map.show_port != NULL)
		return -1;

	sw_cmd_func_map.show_port = func;
	return 0;
}

int sw_command_register_show_portpeer_stats(SW_CMD_SHOW_PORTPEER_STATS func) {
	if (sw_cmd_func_map.show_portpeer != NULL) 
		return -1;
	sw_cmd_func_map.show_portpeer = func;
	return 0;
}
int sw_command_register_show_fwd_rule(SW_CMD_SHOW_FWD_RULE func)
{
	if (sw_cmd_func_map.show_fwd != NULL)
		return -1;

	sw_cmd_func_map.show_fwd = func;
	return 0;

}

int sw_command_register_set_fwd_rule(SW_CMD_SET_FWD_RULE func)
{
	if (sw_cmd_func_map.set_fwd != NULL)
		return -1;

	sw_cmd_func_map.set_fwd = func;
	return 0;

}

int sw_command_register_kill_self(SW_KILL_SELF func)
{
	if (sw_cmd_func_map.kill_self != NULL)
		return -1;

	sw_cmd_func_map.kill_self = func;
	return 0;
}

//////////////////////////////////////////////
int sw_command_client_send_and_recv(SW_CMD_TYPE cmd_type, 
														void* cmd_buf, 
														int cmd_len,
														void* recv_msg,
														int recv_buff_len,
														int* recv_len,
														int timeout)
{
	*recv_len = 0;
	int msg_len = sizeof(SW_CMD_REQUEST) + cmd_len;
	if (msg_len > SW_CMD_BUFF_LEN)
	{
		printf("[Internal Error] msg len :%d err!\n", msg_len);
		return -1;
	}
	
	char buf[SW_CMD_BUFF_LEN];
	SW_CMD_REQUEST *cmd_req = (SW_CMD_REQUEST *)buf;
	cmd_req->magic = htonl(SW_CMD_MAGIC);
	cmd_req->cmd_type = htonl(cmd_type);
	cmd_req->cmd_len = htonl(cmd_len);
	cmd_req->msg_len = htonl(msg_len);
	memcpy(buf+sizeof(SW_CMD_REQUEST), cmd_buf, cmd_len);
	int i = 0;
	printf("head size : %d\n", sizeof(SW_CMD_REQUEST));
	for (i = 0; i < sizeof(SW_CMD_REQUEST); ++i) 
	{
		printf("%02x", buf[i]);
	}
	printf("\n");
	//发送数据至服务端
	if (sendto(sw_cmd_client_fd, buf, msg_len, 0, (struct sockaddr *)&sw_cmd_ser_addr, (socklen_t)sw_cmd_sock_len) != msg_len)
	{
		printf("Warning: Command not send completely!\n");
		return -1;
	}

	//等待返回
	fd_set fdset;
	fd_set *rd = NULL, *wr = NULL;
	struct timeval tmout;
	int result;

	FD_ZERO (&fdset);
	FD_SET (sw_cmd_client_fd, &fdset);
	rd = &fdset;

	tmout.tv_sec = (long) timeout;
	tmout.tv_usec = 0;

	do
	{
		result = select(sw_cmd_client_fd + 1, rd, wr, NULL, &tmout);
	}while (result < 0 && errno == EINTR);

	if (0 >= result)
	{
		printf("[Internal Error] Command Timeout or Error, Check the Vswitch Alive and Logs !\n");
		return -1;
	}
	else
	{
		int len = recvfrom(sw_cmd_client_fd, buf, SW_CMD_BUFF_LEN, 0, (struct sockaddr *)&sw_cmd_ser_addr, (socklen_t *)&sw_cmd_sock_len); 
		if (len <= 0 || len > recv_buff_len)
		{
			printf("[Internal Error] This Command Not Receive Right !");
			return -1;
		}

		SW_CMD_RESPONSE* rsp = (SW_CMD_RESPONSE*)buf;
		if (ntohl(rsp->magic) != SW_CMD_MAGIC || ntohl(rsp->msg_len) != (uint32_t)len)
		{
			printf("[Internal Error] Recv MSG fmt Error !\n");
			return -1;
		}

		memcpy(recv_msg, buf+sizeof(SW_CMD_RESPONSE), len-sizeof(SW_CMD_RESPONSE));
		*recv_len = len;
	}

	return 0;
}

void sw_command_server_handle(int fd)
{
    char buf[SW_CMD_BUFF_LEN];  
    socklen_t len;
    int count;
    struct sockaddr_in clent_addr;  //clent_addr用于记录发送方的地址信息
    while(1)
    {
        memset(buf, 0, SW_CMD_BUFF_LEN);
        len = sizeof(clent_addr);
        count = recvfrom(fd, buf, SW_CMD_BUFF_LEN, 0, (struct sockaddr*)&clent_addr, &len);  //recvfrom是拥塞函数，没有数据就一直拥塞
        if(count < 0)
        {
            printf("recieve data fail!\n");
            continue;
        }

		//校验
		SW_CMD_REQUEST* cmd_req = (SW_CMD_REQUEST*)buf;
		if ((uint32_t)count != ntohl(cmd_req->msg_len))
		{
			printf("Not a complete Msg ! %u : %u\n", count, ntohl(cmd_req->msg_len));
			continue;
		}
		if (SW_CMD_MAGIC != ntohl(cmd_req->magic))
		{
			printf("Magic Number Error !\n");
			continue;
		}
		//按照业务处理
		int resp_len = 0;
		char resp_buf[SW_CMD_BUFF_LEN] = {0};
		if (SW_CMD_TYPE_SHOW_PORT == ntohl(cmd_req->cmd_type))
		{
			struct cmd_show_port_stats_result* res = (struct cmd_show_port_stats_result*)(buf + sizeof(SW_CMD_REQUEST));
			uint16_t portid = res->port_id;
			if (NULL != sw_cmd_func_map.show_port)
				resp_len = sw_cmd_func_map.show_port(ntohs(portid), resp_buf, SW_CMD_BUFF_LEN);
		}
		else if (SW_CMD_TYPE_SHOW_PORTPEER == ntohl(cmd_req->cmd_type)) {
			if (NULL != sw_cmd_func_map.show_portpeer)
				resp_len = sw_cmd_func_map.show_portpeer(resp_buf, SW_CMD_BUFF_LEN);
		}
		else if (SW_CMD_TYPE_KILL_SELF == ntohl(cmd_req->cmd_type))
		{
			if (NULL != sw_cmd_func_map.kill_self)
				resp_len = sw_cmd_func_map.kill_self(resp_buf, SW_CMD_BUFF_LEN);
		}
		else if (SW_CMD_TYPE_SHOW_CORE_MODE == ntohl(cmd_req->cmd_type))
		{
			if (NULL != sw_cmd_func_map.show_core_mode)
				resp_len = sw_cmd_func_map.show_core_mode(resp_buf, SW_CMD_BUFF_LEN);
		}
		else if (SW_CMD_TYPE_SET_ACL == ntohl(cmd_req->cmd_type))
		{
			struct cmd_set_acl_result* res = (struct cmd_set_acl_result*)(buf + sizeof(SW_CMD_REQUEST));
			if (NULL != sw_cmd_func_map.set_acl)
				resp_len = sw_cmd_func_map.set_acl((void*)res, resp_buf, SW_CMD_BUFF_LEN);
		}
		else if (SW_CMD_TYPE_SHOW_ACL == ntohl(cmd_req->cmd_type))
		{
			struct cmd_show_acl_result* res = (struct cmd_show_acl_result*)(buf + sizeof(SW_CMD_REQUEST));
			uint16_t portid = res->port_id;
			if (NULL != sw_cmd_func_map.show_acl)
				resp_len = sw_cmd_func_map.show_acl(portid, resp_buf, SW_CMD_BUFF_LEN);
		}
		else if (SW_CMD_TYPE_SHOW_OFFSET == ntohl(cmd_req->cmd_type))
		{
			struct cmd_show_offset_result* res = (struct cmd_show_offset_result*)(buf + sizeof(SW_CMD_REQUEST));
			uint16_t portid = res->port_id;
			if (NULL != sw_cmd_func_map.show_off)
				resp_len = sw_cmd_func_map.show_off(portid, resp_buf, SW_CMD_BUFF_LEN);
		}
		else if (SW_CMD_TYPE_SHOW_FWD == ntohl(cmd_req->cmd_type))
		{
			struct cmd_show_fwd_result* res = (struct cmd_show_fwd_result*)(buf + sizeof(SW_CMD_REQUEST));
			uint16_t portid = res->port_id;
			if (NULL != sw_cmd_func_map.show_fwd)
				resp_len = sw_cmd_func_map.show_fwd(portid, resp_buf, SW_CMD_BUFF_LEN);
		}
		else if (SW_CMD_TYPE_SET_FWD == ntohl(cmd_req->cmd_type))
		{
			struct cmd_set_fwd_result_x* res = (struct cmd_set_fwd_result_x*)(buf + sizeof(SW_CMD_REQUEST));		
			if (NULL != sw_cmd_func_map.set_fwd)
				resp_len = sw_cmd_func_map.set_fwd(res->port_id, res->delay_s, res->loopback, res->len, res->len_mode, res->max_len, res->max_len_mode, res->syn_mode, 
													res->acl_mode, res->off_mode, res->ipv6_mode, res->vlan_offload_mode, res->mpls_offload_mode, resp_buf, SW_CMD_BUFF_LEN);
		}
		
		int send_len = resp_len + sizeof(SW_CMD_RESPONSE);
		char send_buf[SW_CMD_BUFF_LEN];
		SW_CMD_RESPONSE* rsp = (SW_CMD_RESPONSE* )send_buf;
		rsp->magic = htonl(SW_CMD_MAGIC);
		rsp->msg_len = htonl(send_len);
		memcpy(send_buf+sizeof(SW_CMD_RESPONSE), resp_buf, resp_len);
        sendto(fd, send_buf, send_len, 0, (struct sockaddr*)&clent_addr, len); 
    }
}

