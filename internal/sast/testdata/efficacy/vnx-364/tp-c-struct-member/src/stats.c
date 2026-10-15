#include <signal.h>

struct stats {
	long hits;
	long misses;
};

struct stats g_stats;

static void dump_and_reset(int sig)
{
~>	g_stats.hits = 0;
~>	g_stats.misses = 0;
}

void install(void)
{
	signal(SIGUSR1, dump_and_reset);
}
