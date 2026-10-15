#include <syslog.h>
#include <sys/socket.h>
#include <stdio.h>

void relay(int fd)
{
	char msg[512];
	ssize_t n = recv(fd, msg, sizeof msg - 1, 0);
	if (n <= 0)
		return;
	msg[n] = '\0';
~>	syslog(LOG_NOTICE, msg);
~>	fprintf(stderr,
	        msg);
}

int show(int argc, char **argv)
{
	char out[128];
~>	snprintf(out, sizeof out, argv[1], argc);
	puts(out);
	return 0;
}
