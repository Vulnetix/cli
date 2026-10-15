#include <signal.h>
#include <stdio.h>

static void on_signal(int sig)
{
	printf("caught %d\n", sig);
}

int install(void)
{
	struct sigaction sa = { .sa_handler = on_signal, .sa_flags = SA_RESTART };
	sigemptyset(&sa.sa_mask);
~>	sigaction(SIGHUP, &sa, NULL);
~>	sigaction(SIGUSR1, &sa, NULL);
	return 0;
}
