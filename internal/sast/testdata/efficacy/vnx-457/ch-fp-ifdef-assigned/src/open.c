#include <fcntl.h>

int open_config(const char *path)
{
    int fd;
#ifdef _WIN32
    fd = _open(path, _O_RDONLY);
#else
    fd = open(path, O_RDONLY | O_CLOEXEC);
#endif
    if (fd < 0)
        return -1;
    return fd;
}
