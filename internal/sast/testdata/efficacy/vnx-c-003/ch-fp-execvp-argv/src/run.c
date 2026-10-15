#include <unistd.h>
#include <spawn.h>

extern char **environ;

int run(char **argv)
{
	pid_t pid;
	char *args[] = {"/usr/bin/convert", argv[1], "out.png", NULL};
	posix_spawn(&pid, args[0], NULL, NULL, args, environ);
	execvp(argv[1], &argv[1]);
	execl("/bin/ls", "ls", "-l", argv[1], (char *)NULL);
	return 0;
}
