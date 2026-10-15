#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

void log_request(int fd)
{
	char req[512];
	ssize_t n = recv(fd, req, sizeof(req) - 1, 0);
	req[n] = '\0';
~>	syslog(LOG_INFO,
	       req);
}

void banner(void)
{
	const char *fmt = getenv("BANNER_FMT");
~>	printf(fmt, "server", 1);
}
