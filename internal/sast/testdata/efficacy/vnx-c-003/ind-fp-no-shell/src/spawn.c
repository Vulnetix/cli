#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

int convert_file(const char *user_filename)
{
    pid_t pid;
    char *const args[] = {"convert", (char *)user_filename, "out.png", NULL};
    int status;

    if (posix_spawnp(&pid, "convert", NULL, NULL, args, environ) != 0)
        return -1;
    waitpid(pid, &status, 0);
    return status;
}

int main(int argc, char *argv[])
{
    if (argc < 2)
        return 1;
    if (fork() == 0) {
        execvp(argv[1], &argv[1]);
        _exit(127);
    }
    return convert_file(argv[1]);
}
