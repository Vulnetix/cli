#include <sys/socket.h>
#include <unistd.h>

int bind_low_port(int s, struct sockaddr *a, socklen_t l)
{
~>	setreuid(-1, 0);
	return bind(s, a, l);
}

int raise_group(void)
{
~>	if (setresgid(-1, 0, -1) < 0)
		return -1;
	return 0;
}
