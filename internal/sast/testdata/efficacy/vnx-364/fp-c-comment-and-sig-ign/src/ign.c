#include <signal.h>

int state;

/* A handler that writes state = 1 races with main. */
static void reset_state(int sig)
{
	state = 0;
}

int main(void)
{
	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_DFL);
	reset_state(0);
	return state;
}
