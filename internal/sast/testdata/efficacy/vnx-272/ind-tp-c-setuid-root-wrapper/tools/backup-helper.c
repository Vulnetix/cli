#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	char cmd[512];

	if (argc < 2) {
		fprintf(stderr, "usage: %s <volume>\n", argv[0]);
		return 2;
	}
~>	setuid(0);
	snprintf(cmd, sizeof(cmd), "/usr/sbin/backup-volume %s", argv[1]);
	return system(cmd);
}
