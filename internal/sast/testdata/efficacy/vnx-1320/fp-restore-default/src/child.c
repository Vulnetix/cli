#include <signal.h>

void reset_child(void)
{
	signal(SIGSEGV, SIG_DFL);
	signal(SIGFPE, SIG_DFL);
	signal(SIGINT, SIG_IGN);
}
