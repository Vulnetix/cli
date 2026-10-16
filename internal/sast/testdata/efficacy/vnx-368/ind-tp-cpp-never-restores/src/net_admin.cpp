#include <sys/socket.h>
#include <unistd.h>

int bind_low_port(int sock, const struct sockaddr *addr, socklen_t len)
{
~>	::setegid(0);
	if (bind(sock, addr, len) != 0)
		return -1;
	return 0;
}
