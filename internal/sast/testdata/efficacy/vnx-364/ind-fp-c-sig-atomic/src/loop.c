#include <signal.h>
#include <stdatomic.h>

static volatile sig_atomic_t stop;
static _Atomic int reload_pending;
static atomic_int signals_seen;

static void on_term(int sig)
{
	(void)sig;
	stop = 1;
}

static void on_hup(int sig)
{
	int local_copy = sig;
	local_copy++;
	reload_pending = 1;
	signals_seen++;
}

int main(void)
{
	signal(SIGTERM, on_term);
	signal(SIGHUP, on_hup);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_DFL);
	while (!stop) {
		/* stop = 0; would be the main loop's business */
	}
	return 0;
}
