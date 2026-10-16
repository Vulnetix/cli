#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>

static const char *jail_root = "/var/lib/jaild/root";

int enter_jail(void)
{
~>	if (chroot(jail_root) != 0) {
		syslog(LOG_ERR, "chroot %s failed", jail_root);
		return -1;
	}
	if (chdir("/") != 0)
		return -1;
	return 0;
}

int main(int argc, char **argv)
{
	if (enter_jail() != 0)
		return 1;
	FILE *spool = fopen(argv[1], "a");
	if (!spool)
		return 1;
	fprintf(spool, "started\n");
	fclose(spool);
	return 0;
}
