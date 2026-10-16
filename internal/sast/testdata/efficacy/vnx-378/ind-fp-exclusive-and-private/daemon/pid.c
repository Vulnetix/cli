#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>

int create_pid(void)
{
    int fd = open("/tmp/agent.pid", O_CREAT | O_EXCL | O_WRONLY, 0644);
    return fd;
}

int create_private(void)
{
    return open("/tmp/agent.sock.lock", O_CREAT | O_WRONLY | O_TRUNC, 0600);
}

int create_owner_only(void)
{
    return creat("/var/tmp/agent.state", S_IRUSR | S_IWUSR);
}

int create_group(void)
{
    return open("/dev/shm/agent.seg", O_CREAT | O_RDWR, 0640);
}

int state_outside_tmp(void)
{
    return open("/var/lib/agent/state.db", O_CREAT | O_RDWR, 0644);
}
