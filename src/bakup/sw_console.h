#ifndef _SW_CONSOLE_H_
#define _SW_CONSOLE_H_

typedef struct
{
	void* ring_addr;    //����ring�ĵ�ַ
	char msg_buf[120];  //ʵ�ʴ�ŵ���Ϣ������
}SW_CON_MSG;//128 bytes

#endif