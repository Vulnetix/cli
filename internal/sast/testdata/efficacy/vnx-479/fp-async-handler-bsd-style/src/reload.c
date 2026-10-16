#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *config;

static void
handle_hup(int signo)
{
	(void)signo;
	free(config);
	config = malloc(4096);
	fprintf(stderr, "reloading\n");
}

int
setup(void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handle_hup;
	sigemptyset(&sa.sa_mask);
	return sigaction(SIGHUP, &sa, NULL);
}
