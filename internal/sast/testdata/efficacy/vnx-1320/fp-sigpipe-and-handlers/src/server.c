#include <signal.h>

static void on_segv(int sig)
{
	write_crash_report(sig);
	_exit(128 + sig);
}

void install(void)
{
	struct sigaction sa = {0};

	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);
	sa.sa_handler = on_segv;
	sigaction(SIGSEGV, &sa, NULL);
	signal(SIGBUS, on_segv);
}
