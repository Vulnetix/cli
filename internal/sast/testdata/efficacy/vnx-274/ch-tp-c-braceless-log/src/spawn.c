#include <stdio.h>
#include <syslog.h>
#include <unistd.h>

void child_setup(uid_t uid, gid_t gid)
{
~>	if (setgid(gid) == -1)
		perror("setgid");
~>	if (setuid(uid) == -1)
		syslog(LOG_WARNING, "setuid: %m");
	execl("/usr/libexec/helper", "helper", (char *)NULL);
}
