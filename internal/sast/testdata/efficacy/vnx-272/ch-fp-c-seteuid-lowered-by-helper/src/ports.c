#include <stdlib.h>
#include <unistd.h>

extern int bind_port(int port);

static void drop_root(void)
{
	if (seteuid(getuid()) != 0)
		abort();
}

int bind_low(int port)
{
	int fd;

	if (seteuid(0) != 0)
		return -1;
	fd = bind_port(port);
	drop_root();
	return fd;
}

int bind_low_again(int port)
{
	int fd;

	if (seteuid(0) != 0)
		return -1;
	fd = bind_port(port);
	lower_euid();
	return fd;
}
