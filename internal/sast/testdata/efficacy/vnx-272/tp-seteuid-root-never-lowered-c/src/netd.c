#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

static int listen_on(int port)
{
	struct sockaddr_in addr = {0};
	int fd = socket(AF_INET, SOCK_STREAM, 0);

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	return fd;
}

int main(void)
{
	if (seteuid(getuid()) != 0)
		return 1;
	load_config();
~>	seteuid(0);
	int fd = listen_on(80);
	serve_forever(fd);
	return 0;
}
