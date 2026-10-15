#include <signal.h>
#include <syslog.h>
#include <string.h>

void on_usr1(int signo)
{
~>	syslog(LOG_INFO, "reload requested (%d)", signo);
}

int install(void)
{
	struct sigaction sa = { .sa_handler = on_usr1 };
	sigemptyset(&sa.sa_mask);
	return sigaction(SIGUSR1, &sa, NULL);
}
