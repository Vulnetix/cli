#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

int acl_store_write(const char *aclfile, const char *buf, size_t n) {
    char tmpname[] = "/var/lib/app/acl.XXXXXX";
    int fd = mkstemp(tmpname);
    if (fd == -1) return -1;
    write(fd, buf, n);
    fchmod(fd, 0644);
    close(fd);
~>    if (rename(tmpname, aclfile) == -1) {
        unlink(tmpname);
        return -1;
    }
    return 0;
}
