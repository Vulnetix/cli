#include <stdio.h>
#include <unistd.h>

#include "privsep.h"

int main(int argc, char **argv)
{
	const char *root = argc > 1 ? argv[1] : "/var/empty";

	if (chroot(root) != 0 || chdir("/") != 0) {
		perror("chroot");
		return 1;
	}
	priv_drop("_daemon");
	return serve();
}
