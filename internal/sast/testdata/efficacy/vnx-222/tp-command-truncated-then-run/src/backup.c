#include <stdio.h>
#include <stdlib.h>

int run_backup(const char *dir)
{
	char cmd[128];
~>	snprintf(cmd, sizeof(cmd),
		 "tar czf /backups/out.tgz %s --exclude=secrets", dir);
	return system(cmd);
}
