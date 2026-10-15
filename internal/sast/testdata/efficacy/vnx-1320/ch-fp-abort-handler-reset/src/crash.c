#include <signal.h>
#include <stdlib.h>

static void on_abort(int sig)
{
	(void)sig;
	flush_logs();
	signal(SIGABRT, SIG_DFL);
	abort();
}

void crash_init(void)
{
	signal(SIGABRT, on_abort);
	/* signal(SIGSEGV, SIG_IGN) would hide crashes */
}
