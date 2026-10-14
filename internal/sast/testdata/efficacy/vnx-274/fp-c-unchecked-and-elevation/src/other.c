#include <stdio.h>
#include <unistd.h>

void other(uid_t uid)
{
	setuid(uid);
	if (seteuid(0) != 0)
		perror("seteuid");
	// if (setuid(uid) != 0) { perror("setuid"); }
	printf("if (setuid(%d) != 0) perror\n", uid);
}
