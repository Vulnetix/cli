#include <signal.h>
#include <stdlib.h>
#include <string.h>

static char *config_text = NULL;
static int reload_count;

static void handle_hup(int sig)
{
	(void)sig;
~>	reload_count += 1;
~>	free(config_text);
}

int install(void)
{
	struct sigaction sa = { .sa_handler = handle_hup, .sa_flags = SA_RESTART };
	sigemptyset(&sa.sa_mask);
	return sigaction(SIGHUP, &sa, NULL);
}
