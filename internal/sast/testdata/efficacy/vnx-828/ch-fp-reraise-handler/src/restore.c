#include <signal.h>
#include <termios.h>
#include <unistd.h>

static struct termios saved;

static void restore_and_reraise(int sig)
{
	tcsetattr(STDIN_FILENO, TCSANOW, &saved);
	signal(sig, SIG_DFL);
	raise(sig);
}

void setup(void)
{
	tcgetattr(STDIN_FILENO, &saved);
	signal(SIGINT, restore_and_reraise);
	signal(SIGTERM, restore_and_reraise);
}
