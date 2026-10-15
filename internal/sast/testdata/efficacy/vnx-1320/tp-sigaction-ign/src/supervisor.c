#include <signal.h>
#include <string.h>

static void quiet_faults(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
~>	sigaction(SIGILL, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);
}
