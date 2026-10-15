#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int spawn(char *const argv[])
{
    pid_t pid = fork();
    if (pid == 0) {
        execv(argv[0], argv);
        _exit(127);
    }
    return pid;
}

void *grow(void *p, size_t n)
{
    void *q = realloc(p, n * 2);
    char buf[64];
    snprintf(buf, sizeof buf, "%zu", n);
    return q;
}
