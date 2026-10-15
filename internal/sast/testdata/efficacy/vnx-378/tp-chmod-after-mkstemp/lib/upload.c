#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

int stage_upload(char *tmpl)
{
    int fd = mkstemp(tmpl);
    if (fd < 0)
        return -1;
~>    fchmod(fd, 0666);
    return fd;
}

int stage_shared(char *tmpl)
{
    int tfd = mkstemp(tmpl);
    if (tfd < 0)
        return -1;
~>    chmod(tmpl, S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH);
    return tfd;
}
