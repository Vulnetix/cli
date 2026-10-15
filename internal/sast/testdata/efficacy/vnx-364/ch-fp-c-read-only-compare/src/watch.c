#include <signal.h>
#include <unistd.h>

int mode;
volatile sig_atomic_t stop;

static void on_int(int sig)
{
	if (mode == 2 || mode >= 3)
		_exit(1);
	stop = 1;
	(void)sig;
}

int main(void)
{
	signal(SIGINT, on_int);
	mode = 1;
	while (!stop)
		pause();
	return 0;
}
