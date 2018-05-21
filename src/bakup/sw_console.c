//@20180408 by Shawn.Z
//console client for vswitch

#include <stdio.h>
#include <unistd.h>
#include "sw_command.h"

int
main(void)
{
	sw_command_init(CMD_ROLE_CLIENT);

	while(1)
		sleep(10);
	
	return 0;
}

