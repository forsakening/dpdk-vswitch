#ifndef _SW_COMMAND_H_
#define _SW_COMMAND_H_

#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_parse_string.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_ipaddr.h>
#include <cmdline_parse_portlist.h>
#include <cmdline_socket.h>
#include <cmdline.h>


#define SW_CMD_BUFF_LEN 100000
#define SW_CMD_TIMEOUT  3  // seconds

typedef enum
{
	SW_CMD_TYPE_SHOW_PORT = 0,
	SW_CMD_TYPE_KILL_SELF,
	SW_CMD_TYPE_SHOW_CORE_MODE,
	SW_CMD_TYPE_SHOW_ACL,
	SW_CMD_TYPE_SET_ACL,
	SW_CMD_TYPE_SHOW_OFFSET,
	SW_CMD_TYPE_SHOW_FWD,
	SW_CMD_TYPE_SET_FWD,
	SW_CMD_TYPE_SHOW_PORTPEER,
}SW_CMD_TYPE;

//注册设置五元组接口
// acl port id sip/mask dip/mask sport-low:sport-high dport-low:dport-high tcp/udp/ip
// acl port 3 1.2.3.0/24 2.3.4.0/32 1:1 0:65535 tcp
// acl port 3 1.2.3.0/24 2.3.4.0/32 1:1 0:65535 udp
// acl port 3 1.2.3.0/24 2.3.4.0/32 1:1 0:65535 ip
typedef int (* SW_CMD_SET_ACL)(void *, char*, int);
int sw_command_register_set_acl(SW_CMD_SET_ACL);


//注册展示五元组接口
// show acl port port_id
typedef int (* SW_CMD_SHOW_ACL)(uint16_t, char*, int);
int sw_command_register_show_acl(SW_CMD_SHOW_ACL);


//注册展示偏移接口
// show offset port port_id
typedef int (* SW_CMD_SHOW_OFFSET)(uint16_t, char*, int);
int sw_command_register_show_offset(SW_CMD_SHOW_OFFSET);


//注册展示core模式接口
typedef int (* SW_CMD_SHOW_CORE_MODE)(char*, int);
int sw_command_register_show_core_mode(SW_CMD_SHOW_CORE_MODE);

//注册展示fwd rule 接口
typedef int (* SW_CMD_SHOW_FWD_RULE)(uint16_t, char*, int);
int sw_command_register_show_fwd_rule(SW_CMD_SHOW_FWD_RULE);

//注册修改fwd rule 接口
//port,delay,loopback,len,len_mode,syn_mode,acl_mode,off_mode
typedef int (* SW_CMD_SET_FWD_RULE)(uint16_t, uint16_t, uint16_t, uint16_t, uint16_t, uint16_t, uint16_t,uint16_t,uint16_t,uint16_t, uint16_t,uint16_t,uint16_t,char*, int);
int sw_command_register_set_fwd_rule(SW_CMD_SET_FWD_RULE);


//注册展示端口统计接口
typedef int (* SW_CMD_SHOW_PORT)(uint16_t, char*, int);
int sw_command_register_show_port(SW_CMD_SHOW_PORT);

//注册退出主进程接口
typedef int (* SW_KILL_SELF)(char*, int);
int sw_command_register_kill_self(SW_KILL_SELF);

typedef int (*SW_CMD_SHOW_PORTPEER_STATS)(char *, int);
int sw_command_register_show_portpeer_stats(SW_CMD_SHOW_PORTPEER_STATS);

int sw_command_client_send_and_recv(SW_CMD_TYPE cmd_type, 
														void* cmd_buf, 
														int cmd_len,
														void* recv_msg,
														int recv_buff_len,
														int* recv_len,
														int timeout);


typedef enum
{
	CMD_ROLE_SERVER = 0,
	CMD_ROLE_CLIENT,
}SW_CMD_ROLE;
//启动命令行
//CMD_ROLE_SERVER  创建socket ,ok 返回 0，error返回非0
//CMD_ROLE_CLIENT  连接SERVER 并创建控制台, ok 返回 0, error 返回非0
int sw_command_init(SW_CMD_ROLE);

#endif
