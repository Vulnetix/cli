#include <stdio.h>

int list_archive(int sock)
{
	char name[128];
	char cmd[512];
	FILE *p;
	int n = recv(sock, name, sizeof name - 1, 0);
	name[n] = 0;
	snprintf(cmd, sizeof(cmd),
	         "tar -tzf %s",
	         name);
~>	p = popen(cmd, "r");
	if (!p)
		return -1;
	return pclose(p);
}
