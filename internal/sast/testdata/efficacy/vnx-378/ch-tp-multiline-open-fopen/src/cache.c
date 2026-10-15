#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>

int open_cache(void)
{
~>    int fd = open("/var/tmp/cache.db",
                  O_RDWR | O_CREAT,
                  S_IRUSR | S_IWUSR | S_IROTH);
    return fd;
}

void dump_state(const char *state)
{
~>    FILE *fp = fopen("/tmp/state.dump", "w");
    if (!fp)
        return;
    fputs(state, fp);
    fclose(fp);
}
