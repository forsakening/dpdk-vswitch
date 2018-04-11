#ifndef _SW_CONSOLE_H_
#define _SW_CONSOLE_H_

typedef struct
{
	void* ring_addr;    //各个ring的地址
	char msg_buf[120];  //实际存放的消息体内容
}SW_CON_MSG;//128 bytes

#endif