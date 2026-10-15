#include <signal.h>
#include <syslog.h>

static void on_reload(int sig)
{
	syslog(LOG_NOTICE, "signal %d", sig);
}

int install(void)
{
	struct sigaction act = { .sa_handler = on_reload };
	sigfillset(&act.sa_mask);
	sigaction(SIGHUP, &act, NULL);
	sigaction(SIGUSR2, &act, NULL);
	return 0;
}
