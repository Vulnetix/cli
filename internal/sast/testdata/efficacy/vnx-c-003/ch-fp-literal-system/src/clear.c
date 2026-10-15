#include <stdlib.h>
#include <stdio.h>

#define CLEAR_CMD "clear"

void clear_screen(int verbose)
{
	char cmd[64];
	system("clear");
	system(CLEAR_CMD);
	snprintf(cmd, sizeof cmd, "sleep %d", verbose);
	system(cmd);
	if (system(NULL) == 0)
		return;
	FILE *p = popen("uname -a", "r");
	pclose(p);
}
