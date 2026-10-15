#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

int ctl_open(const char *path)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		return -1;
~>	chmod(addr.sun_path,
	      S_IRWXU | S_IRWXG | S_IRWXO);
	listen(fd, 8);
	return fd;
}
