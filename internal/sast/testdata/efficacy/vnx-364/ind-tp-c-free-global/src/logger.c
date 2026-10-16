#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char *logbuf;
static size_t loglen;

static void flush_and_quit(int sig)
{
	(void)sig;
	write(STDERR_FILENO, logbuf, loglen);
~>	free(logbuf);
~>	logbuf = NULL;
	_exit(1);
}

int logger_init(size_t cap)
{
	logbuf = malloc(cap);
	if (logbuf == NULL)
		return -1;
	signal(SIGTERM, flush_and_quit);
	return 0;
}
