#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

/* Classic daemon start-up. Clearing the umask means every file this daemon
 * and its children create later gets exactly the mode it asks for, and
 * libraries ask for 0666. */
int daemonize(void)
{
	pid_t pid = fork();

	if (pid < 0)
		return -1;
	if (pid > 0)
		exit(0);
	setsid();
~>	umask(0);
	chdir("/");
	return 0;
}
