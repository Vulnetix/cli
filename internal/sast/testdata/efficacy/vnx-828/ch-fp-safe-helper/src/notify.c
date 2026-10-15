#include <signal.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t got_hup;

static void write_str(const char *s)
{
	ssize_t r = write(STDERR_FILENO, s, strlen(s));
	(void)r;
}

static void on_hup(int sig)
{
	(void)sig;
	got_hup = 1;
	write_str("hup\n");
}

int main(void)
{
	signal(SIGHUP, on_hup);
	while (!got_hup)
		pause();
	return 0;
}
