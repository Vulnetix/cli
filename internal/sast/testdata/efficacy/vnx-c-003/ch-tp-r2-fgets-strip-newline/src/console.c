#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int run_console(void)
{
	char cmd[256];
	if (!fgets(cmd, sizeof cmd, stdin))
		return -1;
	cmd[strcspn(cmd, "\n")] = '\0';
~>	return system(cmd);
}
