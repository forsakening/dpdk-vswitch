#ifndef _SW_LOG_H
#define _SW_LOG_H

#define SW_LOG_FILE "/var/log/switch.log"

typedef enum
{
	SW_LOG_INFO = 0,
	SW_LOG_WARN,
	SW_LOG_ERROR
}log_lv;

void sw_log(log_lv lv, const char *format, ...);

#endif
