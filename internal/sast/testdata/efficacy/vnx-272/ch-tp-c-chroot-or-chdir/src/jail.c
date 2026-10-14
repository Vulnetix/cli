#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern int serve(int fd);

static void enter_jail(const char *root)
{
~>	if (chroot(root) != 0 || chdir("/") != 0) {
		perror("jail");
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char **argv)
{
	enter_jail(argc > 1 ? argv[1] : "/var/empty");
	return serve(STDIN_FILENO);
}
