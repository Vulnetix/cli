#include <stdio.h>
#include <syslog.h>
#include <unistd.h>

void enter(const char *dir)
{
	int rc = chroot(dir);
~>	if (rc < 0) {
		syslog(LOG_WARNING, "chroot(%s) failed, continuing unjailed", dir);
	}
	chdir("/");
}
