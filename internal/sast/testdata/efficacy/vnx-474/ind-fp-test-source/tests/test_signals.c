#include <signal.h>

static int hits;
static void count(int s) { (void)s; hits++; }

void test_signal_counts(void)
{
    signal(SIGUSR1, count);
    raise(SIGUSR1);
}
