#include <stdio.h>
#include <stdlib.h>

int main(void)
{
	char cmd[256];
	char *host = getenv("QUERY_STRING");
	snprintf(cmd, sizeof cmd, "ping -c 1 %s", host);
~>	system(cmd);
	return 0;
}
