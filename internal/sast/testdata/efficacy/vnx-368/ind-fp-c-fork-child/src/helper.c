#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

int privileged_open(const char *path)
{
	pid_t pid = fork();
	if (pid == 0) {
		seteuid(0);
		int fd = open(path, O_RDONLY);
		_exit(fd < 0 ? 1 : 0);
	}
	int status;
	waitpid(pid, &status, 0);
	return status;
}

int with_lowered(uid_t user)
{
	seteuid(user);
	/* untrusted work */
	seteuid(0);
	return 0;
}
