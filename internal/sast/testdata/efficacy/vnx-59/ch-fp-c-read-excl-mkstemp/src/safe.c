#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int safe(void)
{
    char tmpl[] = "/tmp/daemonXXXXXX";
    int t = mkstemp(tmpl);
    FILE *in = fopen("/tmp/daemon.conf", "r");
    int fd = open("/tmp/daemon.lock", O_WRONLY | O_CREAT | O_EXCL, 0600);
    int rd = open("/tmp/daemon.pid", O_RDONLY);
    if (in) fclose(in);
    close(rd);
    close(t);
    return fd;
}
