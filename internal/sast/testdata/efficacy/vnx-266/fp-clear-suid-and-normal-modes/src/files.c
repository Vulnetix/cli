#include <sys/stat.h>

void sanitize(const char *p, mode_t mode, int fd)
{
    chmod(p, mode & ~(S_ISUID | S_ISGID));
    chmod(p, 0644);
    fchmod(fd, 0755);
    mkdir("/var/lib/app", 0750);
    chmod(p, 00755);
}
