#ifndef __SW_CONFIG_H__
#define __SW_CONFIG_H__

#define SW_CONFIG_Log_Error(fmt,...) printf("\033[0;32;31m[SWCONF ERROR] \033[m"fmt, ##__VA_ARGS__);
#define SW_CONFIG_Log_Info(fmt,...) printf("\033[0;32;32m[SWCONF INFO] \033[m"fmt, ##__VA_ARGS__);

#define SW_TX_MAP_SPLIT " "

int sw_config_init(char* conf_path, void* port_peer);

#endif