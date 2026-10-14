#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define APP_HOME "/srv/jail"

/* Serves one file from inside the jail. The process stays root after the
 * chroot, so anything it opens is opened with full privileges. */
int main(int argc, char **argv)
{
	if (argc < 2)
		return 1;
~>	chroot(APP_HOME);
	chdir("/");
	FILE *data = fopen(argv[1], "r+");
	if (data == NULL)
		return 1;
	fclose(data);
	return 0;
}
