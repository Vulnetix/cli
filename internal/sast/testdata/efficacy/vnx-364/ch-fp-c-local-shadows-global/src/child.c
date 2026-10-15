#include <signal.h>
#include <sys/wait.h>
#include <errno.h>

int status;
volatile sig_atomic_t children_exited;

static void reap(int sig)
{
	int saved = errno;
	int status;
	(void)sig;
	while (waitpid(-1, &status, WNOHANG) > 0)
		children_exited = 1;
	status = 0;
	errno = saved;
}

int main(void)
{
	signal(SIGCHLD, reap);
	status = 1;
	return status;
}
