#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

void daemonize(void)
{
	if (fork() > 0)
		exit(0);
	setsid();
~>	umask(0);
	chdir("/");
}
