#include <signal.h>

volatile sig_atomic_t got_hup = 0;
static int counter;

static void on_hup(int sig)
{
	(void)sig;
	got_hup = 1;
}

static void tick(void)
{
	counter++;
	if (got_hup) {
		got_hup = 0;
		counter = 0;
	}
}

int main(void)
{
	signal(SIGHUP, on_hup);
	for (;;)
		tick();
}
