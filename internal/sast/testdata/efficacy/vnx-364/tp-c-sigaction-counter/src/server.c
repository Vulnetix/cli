#include <signal.h>
#include <string.h>

int reload_count = 0;
int running = 1;

void handle_hup(int signo)
{
~>	reload_count++;
}

void handle_int(int signo, siginfo_t *info, void *ctx)
{
~>	running = 0;
}

int main(void)
{
	struct sigaction sa, sb;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handle_hup;
	sigaction(SIGHUP, &sa, NULL);
	sb.sa_sigaction = &handle_int;
	sb.sa_flags = SA_SIGINFO;
	sigaction(SIGINT, &sb, NULL);
	while (running) {
	}
	return reload_count;
}
