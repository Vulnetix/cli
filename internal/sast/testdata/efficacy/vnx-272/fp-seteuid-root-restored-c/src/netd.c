#include <unistd.h>

int open_privileged_port(int port)
{
	uid_t saved = geteuid();
	int fd;

	if (seteuid(0) != 0)
		return -1;
	fd = bind_port(port);
	if (seteuid(saved) != 0)
		return -1;
	return fd;
}
