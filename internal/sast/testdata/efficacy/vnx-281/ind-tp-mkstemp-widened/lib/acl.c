#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int acl_replace(const char *aclfile, const char *body)
{
    char tmpname[] = "/etc/myd/acl.XXXXXX";
    int fd = mkstemp(tmpname);
    if (fd < 0)
        return -1;
    size_t n = strlen(body);
    if (write(fd, body, n) != (ssize_t)n)
        goto fail;
    if (fchmod(fd, 0644) != 0)
        goto fail;
    fsync(fd);
    close(fd);
~>    return rename(tmpname, aclfile);
fail:
    close(fd);
    unlink(tmpname);
    return -1;
}
