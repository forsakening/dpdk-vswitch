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

#include "sw_command.h"
#include "sw_filter.h"
#include "sw_offset.h"

#define SW_CMD_MAGIC       0xabcdbeef
#define SW_CMD_SERVER_PORT 12345  

static void sw_command_server_handle(int fd);

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

	printf("%s\n", buf);
	
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

	printf("%s\n", buf);
	
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
	uint16_t port_id;
	uint16_t delay_s;
	uint16_t loopback;
	uint16_t len;
	uint16_t len_mode;
	uint16_t syn_mode;
	uint16_t acl_mode;
	uint16_t off_mode;
};

cmdline_parse_token_string_t cmd_set_fwd_set =
	TOKEN_STRING_INITIALIZER
		(struct cmd_set_fwd_result,
		 set, "set");
cmdline_parse_token_string_t cmd_set_fwd_fwd =
	TOKEN_STRING_INITIALIZER
		(struct cmd_set_fwd_result,
		 fwd, "fwd");
cmdline_parse_token_num_t cmd_set_fwd_port_id =
	TOKEN_NUM_INITIALIZER
		(struct cmd_set_fwd_result,
		 port_id, UINT16);
cmdline_parse_token_num_t cmd_set_fwd_delay =
	TOKEN_NUM_INITIALIZER
		(struct cmd_set_fwd_result,
		 delay_s, UINT16);
cmdline_parse_token_num_t cmd_set_fwd_loopback =
	TOKEN_NUM_INITIALIZER
		(struct cmd_set_fwd_result,
		 loopback, UINT16);
cmdline_parse_token_num_t cmd_set_fwd_len =
	TOKEN_NUM_INITIALIZER
		(struct cmd_set_fwd_result,
		 len, UINT16);
cmdline_parse_token_num_t cmd_set_fwd_len_mode =
	TOKEN_NUM_INITIALIZER
		(struct cmd_set_fwd_result,
		 len_mode, UINT16);
cmdline_parse_token_num_t cmd_set_fwd_syn_mode =
	TOKEN_NUM_INITIALIZER
		(struct cmd_set_fwd_result,
		 syn_mode, UINT16);
cmdline_parse_token_num_t cmd_set_fwd_acl_mode =
	TOKEN_NUM_INITIALIZER
		(struct cmd_set_fwd_result,
		 acl_mode, UINT16);
cmdline_parse_token_num_t cmd_set_fwd_off_mode =
	TOKEN_NUM_INITIALIZER
		(struct cmd_set_fwd_result,
		 off_mode, UINT16);


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
	sw_command_client_send_and_recv(SW_CMD_TYPE_SET_FWD, res, 
									sizeof(struct cmd_set_fwd_result), 
									buf, SW_CMD_BUFF_LEN, &len, SW_CMD_TIMEOUT);

	printf("%s\n", buf);
	
	//if (NULL != sw_cmd_func_map.show_port)
	//	sw_cmd_func_map.show_port(portid);
}

cmdline_parse_inst_t cmd_set_fwd = {
	.f = cmd_set_fwd_parsed,
	.data = NULL,
	.help_str = "set fwd <port_id> <delay_s> <loopback> <len> <len-mode> <syn-mode> <acl-mode> <off-mode>",
	.tokens = {
		(void *)&cmd_set_fwd_set,
		(void *)&cmd_set_fwd_fwd,
		(void *)&cmd_set_fwd_port_id,
		(void *)&cmd_set_fwd_delay,
		(void *)&cmd_set_fwd_loopback,
		(void *)&cmd_set_fwd_len,
		(void *)&cmd_set_fwd_len_mode,
		(void *)&cmd_set_fwd_syn_mode,
		(void *)&cmd_set_fwd_acl_mode,
		(void *)&cmd_set_fwd_off_mode,
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

	printf("%s\n", buf);
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

	printf("%s\n", buf);
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

/****************/

cmdline_parse_ctx_t vswitch_ctx[] = {
	(cmdline_parse_inst_t *)&cmd_clear_history,
	(cmdline_parse_inst_t *)&cmd_quit,
	(cmdline_parse_inst_t *)&cmd_kill_self,	
	(cmdline_parse_inst_t *)&cmd_show_port_stats,
	(cmdline_parse_inst_t *)&cmd_show_core_mode,
//	(cmdline_parse_inst_t *)&cmd_set_acl,
	(cmdline_parse_inst_t *)&cmd_show_acl,
	(cmdline_parse_inst_t *)&cmd_show_offset,
	(cmdline_parse_inst_t *)&cmd_show_fwd,
	(cmdline_parse_inst_t *)&cmd_set_fwd,
	NULL,
};

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
}SW_CMD_FUNC_MAP;

SW_CMD_FUNC_MAP sw_cmd_func_map = {0};

static int sw_cmd_client_fd = -1;
static struct sockaddr_in sw_cmd_ser_addr;
static int sw_cmd_sock_len = sizeof(sw_cmd_ser_addr);
static void* sw_command_client_run(void* arg)
{
	if (arg)
		printf("Start to thread %s \n", __FUNCTION__);

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

	printf("\n\n\n");
	printf("****************************************************\n");
	printf("*********** WELCOME TO VSWITCH CONSOLE *************\n");
	printf("****************************************************\n");
	printf("\n\n");
	struct cmdline *cl = cmdline_stdin_new(vswitch_ctx, "\nVSWITCH > ");
	if (cl == NULL)
		return NULL;
	cmdline_interact(cl);
	cmdline_stdin_exit(cl);

	return NULL;
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
		if ((uint32_t)count != ntohl(cmd_req->msg_len) || SW_CMD_MAGIC != ntohl(cmd_req->magic))
		{
			printf("Not a complete Msg !\n");
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
			struct cmd_set_fwd_result* res = (struct cmd_set_fwd_result*)(buf + sizeof(SW_CMD_REQUEST));		
			if (NULL != sw_cmd_func_map.set_fwd)
				resp_len = sw_cmd_func_map.set_fwd(res->port_id, res->delay_s, res->loopback, res->len, res->len_mode, res->syn_mode, 
													res->acl_mode, res->off_mode, resp_buf, SW_CMD_BUFF_LEN);
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

