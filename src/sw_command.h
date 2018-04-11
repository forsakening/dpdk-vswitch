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


//ע��չʾ�˿�ͳ�ƽӿ�
typedef int (* SW_CMD_SHOW_PORT)(uint16_t, char*, int);
int sw_command_register_show_port(SW_CMD_SHOW_PORT);

//ע���˳������̽ӿ�
typedef int (* SW_KILL_SELF)(char*, int);
int sw_command_register_kill_self(SW_KILL_SELF);

typedef enum
{
	CMD_ROLE_SERVER = 0,
	CMD_ROLE_CLIENT,
}SW_CMD_ROLE;
//����������
//CMD_ROLE_SERVER  ����socket ,ok ���� 0��error���ط�0
//CMD_ROLE_CLIENT  ����SERVER ����������̨, ok ���� 0, error ���ط�0
int sw_command_init(SW_CMD_ROLE);

#endif
