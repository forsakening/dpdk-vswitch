#include <stdio.h>

#include "sw_log.h"

void sw_log_info(const char *format, ...);
void sw_log_warn(const char *format, ...);
void sw_log_err(const char *format, ...);

void sw_log(log_lv lv, const char *format, ...)
{
	printf("[SW]"format, ##__VA_ARGS__);
	return;

	if (lv == SW_LOG_INFO)
	{
		sw_log_info(format);	
	}
	else if (lv == SW_LOG_WARN)
	{
		sw_log_warn(format);
	}
	else if (lv == SW_LOG_ERROR)
	{
		sw_log_err(format);
	}
}

