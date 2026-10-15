#include <signal.h>
#include <stdio.h>

static void on_int(int sig)
{
	fprintf(stderr, "interrupt %d\n", sig);
}

void install(void)
{
#ifdef _WIN32
	signal(SIGINT, on_int);
#else
	struct sigaction sa;
	sa.sa_handler = on_int;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, NULL);
#endif
}
