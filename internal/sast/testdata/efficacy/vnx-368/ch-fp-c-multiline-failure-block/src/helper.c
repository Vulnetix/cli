#include <stdio.h>
#include <unistd.h>

int with_root(int (*fn)(void))
{
	uid_t me = geteuid();
	if (seteuid(0) == -1) {
		perror("seteuid");
		return -1;
	}
	int rc = fn();
	if (seteuid(me) == -1)
		_exit(1);
	return rc;
}
