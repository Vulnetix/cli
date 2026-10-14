#include <stdio.h>

/* fchmod(fd, 0600); is done by the caller, which checks it. */
// chmod(path, 0600);
void notes(const char *path)
{
	printf("chmod(%s, 0600) failed\n", path);
	puts("if (chdir(home) < 0) chdir(\"/\");");
}
