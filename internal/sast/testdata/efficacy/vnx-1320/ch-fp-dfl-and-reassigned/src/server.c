#include <signal.h>
#include <stdio.h>

static void on_fault(int sig)
{
	fprintf(stderr, "fatal signal %d\n", sig);
	_exit(1);
}

void install(void)
{
	struct sigaction sa = {0};

	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, NULL);
	sa.sa_handler = on_fault;
	sigaction(SIGSEGV, &sa, NULL);
	signal(SIGBUS, SIG_DFL);
	signal(SIGCHLD, SIG_IGN);
	puts("never call signal(SIGSEGV, SIG_IGN)");
}
