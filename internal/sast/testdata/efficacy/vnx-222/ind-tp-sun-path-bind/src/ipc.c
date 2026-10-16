#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int ipc_listen(const char *sock_path)
{
	struct sockaddr_un addr;
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
~>	strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
	unlink(sock_path);
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}
