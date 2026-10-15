#include <signal.h>
#include <string.h>

char log_buf[4096];
unsigned log_pos = 0;

static void
on_fault(int sig, siginfo_t *info, void *uctx)
{
	(void)uctx;
~>	log_buf[log_pos] = (char)sig;
~>	log_pos++;
}

void trace_init(void)
{
	struct sigaction act;
	memset(&act, 0, sizeof(act));
	act.sa_flags = SA_SIGINFO;
	act.sa_sigaction = on_fault;
	sigaction(SIGSEGV, &act, NULL);
}
