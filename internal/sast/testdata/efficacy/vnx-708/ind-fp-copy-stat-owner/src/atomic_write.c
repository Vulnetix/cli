#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

/* Replace dest atomically, preserving the original file's owner. */
int atomic_replace(const char *dest, const char *tmp)
{
    struct stat st;
    if (stat(dest, &st) != 0)
        return -1;

    int fd = open(tmp, O_WRONLY);
    if (fd < 0)
        return -1;
    if (fchown(fd, st.st_uid, st.st_gid) != 0) {
        close(fd);
        return -1;
    }
    close(fd);
    if (chown(tmp, st.st_uid, st.st_gid) != 0)
        return -1;
    return rename(tmp, dest);
}
