#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

int make_fifo(char *out, size_t n)
{
	char dir[] = "/tmp/jobXXXXXX";
	if (mkdtemp(dir) == NULL)
		return -1;
	snprintf(out, n, "%s/ctl", dir);
	return mkfifo(out, 0600);
}
