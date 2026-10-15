#include <signal.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t stop;

static void say(const char *msg)
{
	ssize_t r = write(STDERR_FILENO, msg, strlen(msg));
	(void)r;
}

static void
on_stop (int sig)
{
	stop = sig;
	say("stopping\n");
}

int main(void)
{
	signal(SIGINT, on_stop);
	signal(SIGTERM, on_stop);
	while (!stop)
		pause();
	return 0;
}
