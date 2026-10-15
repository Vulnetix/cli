#include <signal.h>

static volatile sig_atomic_t got_term = 0;
static volatile sig_atomic_t got_hup;

static void on_term(int sig)
{
	got_term = 1;
}

static void on_hup(int sig)
{
	int saved = sig;
	got_hup = saved;
}

int main(void)
{
	signal(SIGTERM, on_term);
	signal(SIGHUP, on_hup);
	while (!got_term) {
	}
	return 0;
}
