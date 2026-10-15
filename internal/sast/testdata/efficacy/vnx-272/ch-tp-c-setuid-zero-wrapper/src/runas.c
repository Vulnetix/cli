#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* Installed setuid root so the web UI can restart the service. */
int main(int argc, char **argv)
{
	if (argc < 2)
		return 2;
~>	setgid(0);
~>	if (setuid(0) != 0) {
		perror("setuid");
		return 1;
	}
	return system(argv[1]);
}
