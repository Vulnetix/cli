#include <sys/stat.h>
#include <unistd.h>

void daemonize(void)
{
	setsid();
	umask(027);
	chdir("/");
}

void make_fifo(const char *p)
{
	mode_t old = umask(0);
	mkfifo(p, 0620);
	umask(old);
}
