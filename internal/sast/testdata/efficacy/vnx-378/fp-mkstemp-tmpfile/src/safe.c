#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

int safe_temp(void)
{
    char tmpl[] = "/tmp/safeXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0)
        return -1;
    fchmod(fd, 0600);
    unlink(tmpl);
    return fd;
}

FILE *anon(void)
{
    return tmpfile();
}

char *dir(void)
{
    static char t[] = "/tmp/workXXXXXX";
    return mkdtemp(t);
}

int private_open(void)
{
    return open("/tmp/private.sock", O_RDWR | O_CREAT | O_EXCL, 0600);
}

int config_open(void)
{
    return open("/etc/app/app.conf", O_RDWR | O_CREAT, 0644);
}
