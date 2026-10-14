#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int open_low_port(unsigned short port)
{
	struct sockaddr_in sa;
	int fd;

	memset(&sa, 0, sizeof sa);
~>	if (seteuid(0) == -1)
		return -1;
	fd = socket(AF_INET, SOCK_STREAM, 0);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	if (bind(fd, (struct sockaddr *)&sa, sizeof sa) == -1) {
		close(fd);
		return -1;
	}
	return fd;
}
