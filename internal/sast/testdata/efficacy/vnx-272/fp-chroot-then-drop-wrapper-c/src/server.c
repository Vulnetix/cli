#include <unistd.h>

int start(const char *root)
{
	if (chroot(root) == -1)
		return -1;
	(void)chdir("/");
	drop_privileges();
	return serve();
}
