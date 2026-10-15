#include <pthread.h>
#include <unistd.h>
#include <sys/wait.h>

static void *poller(void *arg) { return arg; }

int rotate_logs(void)
{
	pthread_t t;
	pthread_create(&t, NULL, poller, NULL);
	pid_t pid = fork();
	if (pid == 0) {
		if (seteuid(0) != 0)
			_exit(1);
		execl("/usr/sbin/logrotate", "logrotate", (char *)0);
		_exit(127);
	}
	int status;
	waitpid(pid, &status, 0);
	return status;
}
