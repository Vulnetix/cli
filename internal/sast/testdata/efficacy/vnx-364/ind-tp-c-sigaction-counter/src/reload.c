#include <signal.h>
#include <string.h>

struct server_state {
	int reloads;
	int running;
};

static struct server_state g_state;
static unsigned long hup_count;

static void on_hup(int signo, siginfo_t *info, void *ctx)
{
	(void)signo; (void)info; (void)ctx;
~>	hup_count++;
~>	g_state.reloads += 1;
}

void install_handlers(void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = on_hup;
	sa.sa_flags = SA_SIGINFO | SA_RESTART;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGHUP, &sa, NULL);
}
