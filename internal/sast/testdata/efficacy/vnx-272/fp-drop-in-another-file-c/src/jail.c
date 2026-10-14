#include <unistd.h>

int jail_enter(const char *root)
{
	if (chroot(root) != 0)
		return -1;
	return chdir("/");
}
