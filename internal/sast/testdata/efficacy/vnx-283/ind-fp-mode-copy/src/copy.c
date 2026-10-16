#include <sys/stat.h>
#include <fcntl.h>

int copy_mode(const char *src, int dstfd)
{
    struct stat st;
    if (stat(src, &st) != 0)
        return -1;
    mode_t mode = st.st_mode & 07777;
    return fchmod(dstfd, mode);
}
