#ifndef _SW_COMMAND_H_
#define _SW_COMMAND_H_

#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_parse_string.h>
#include <cmdline_parse_num.h>
#include <cmdline_socket.h>
#include <cmdline.h>

extern cmdline_parse_ctx_t vswitch_ctx[];

#define SW_CMD_BUFF_LEN 4096  
#define SW_CMD_TIMEOUT  3  // seconds

typedef enum
{
	SW_CMD_TYPE_SHOW_PORT = 0,
	SW_CMD_TYPE_KILL_SELF,
}SW_CMD_TYPE;


//注册展示端口统计接口
typedef int (* SW_CMD_SHOW_PORT)(uint16_t, char*, int);
int sw_command_register_show_port(SW_CMD_SHOW_PORT);

//注册退出主进程接口
typedef int (* SW_KILL_SELF)(char*, int);
int sw_command_register_kill_self(SW_KILL_SELF);

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
