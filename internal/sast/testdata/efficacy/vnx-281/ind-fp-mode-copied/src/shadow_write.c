#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int shadow_update(const char *path, const char *contents)
{
    struct stat st;
    char tmpname[256];

    if (stat(path, &st) != 0)
        return -1;
    snprintf(tmpname, sizeof tmpname, "%s.XXXXXX", path);
    int fd = mkstemp(tmpname);
    if (fd < 0)
        return -1;
    write(fd, contents, strlen(contents));
    if (fchmod(fd, st.st_mode & 07777) != 0 || fchown(fd, st.st_uid, st.st_gid) != 0) {
        close(fd);
        unlink(tmpname);
        return -1;
    }
    fsync(fd);
    close(fd);
    return rename(tmpname, path);
}
