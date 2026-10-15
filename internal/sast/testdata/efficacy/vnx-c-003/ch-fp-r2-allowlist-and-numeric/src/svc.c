#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int is_allowed_service(const char *name);

int restart(int pid)
{
	char cmd[64];
	snprintf(cmd, sizeof cmd, "kill -HUP %d", pid);
	return system(cmd);
}

int restart_named(const char *argname)
{
	char cmd[128];
	const char *name = getenv("SERVICE");
	if (!name || !is_allowed_service(name))
		return -1;
	snprintf(cmd, sizeof cmd, "systemctl restart %s", name);
	return system(cmd);
}

void cleanup(void)
{
	system("rm -rf /tmp/build-cache");
	popen("uptime", "r");
}
