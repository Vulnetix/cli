#include <fcntl.h>
#include <stdio.h>

int read_pid(void)
{
    int fd = open("/tmp/daemon.pid", O_RDONLY);
    return fd;
}

int make_marker(void)
{
    return open("/tmp/marker",
                O_CREAT | O_EXCL | O_WRONLY,
                0644);
}

int open_config(void)
{
    return open("/etc/app/app.conf", O_CREAT | O_RDWR, 0644);
}

void readback(void)
{
    FILE *fp = fopen("/tmp/state.dump", "r");
    if (fp)
        fclose(fp);
    puts("never call tmpnam() or mktemp() in new code");
}
