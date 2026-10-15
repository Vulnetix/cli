#include <signal.h>
#include <stdlib.h>
#include <string.h>

static char *logbuf;

static void on_term(int sig)
{
~>	free(logbuf);
~>	logbuf = NULL;
	_exit(0);
}

int main(void)
{
	logbuf = malloc(4096);
	signal(SIGTERM, on_term);
	signal(SIGINT, on_term);
	for (;;) {
		strcpy(logbuf, "tick");
	}
	free(logbuf);
	return 0;
}
