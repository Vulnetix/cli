#include <signal.h>

static long counters[8];
static int last_signal;

static void record(int sig)
{
~>	counters[sig & 7] = 0;
~>	last_signal = sig;
}

void stats_init(void)
{
	sigset(SIGUSR1, record);
	sigset(SIGUSR2, record);
}
