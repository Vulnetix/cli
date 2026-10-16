#include <fcntl.h>
#include <stdio.h>

FILE *open_log(void)
{
    FILE *f = fopen("/tmp/appd.log", "a");
    return f;
}

int open_lock(void)
{
    return open("/tmp/appd.lock", O_WRONLY | O_CREAT | O_TRUNC, 0644);
}
