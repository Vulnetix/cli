#include <signal.h>
#include <string.h>

int worker_setup(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
~>	if (sigaction(SIGSEGV, &sa, NULL) != 0)
		return -1;
~>	sigaction(SIGXCPU, &sa, NULL);
	return 0;
}

void quiet(void)
{
	struct sigaction ign = { .sa_handler = SIG_IGN, .sa_flags = 0 };
~>	sigaction(SIGILL, &ign, 0);
}
