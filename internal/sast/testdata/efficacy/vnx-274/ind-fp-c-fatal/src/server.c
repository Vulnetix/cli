#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void drop(uid_t uid, gid_t gid)
{
	if (setgid(gid) != 0)
		err(1, "setgid");
	if (setuid(uid) != 0) {
		perror("setuid");
		exit(EXIT_FAILURE);
	}
	if (seteuid(0) != 0)
		perror("seteuid(0) failed as expected");
}
