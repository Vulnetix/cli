#include <fcntl.h>
#include <sys/stat.h>

int open_log(const char *path)
{
    int fd;
    if (path != NULL) {
        fd = open(path, O_WRONLY | O_APPEND);
    }
~>    return fd;
}

int protect(const char *p, int private_file)
{
    mode_t mode;
    unsigned int bits;
    if (private_file) bits = 0600;
~>    return chmod(p, bits);
}
