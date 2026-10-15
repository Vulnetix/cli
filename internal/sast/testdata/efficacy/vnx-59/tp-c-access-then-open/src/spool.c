#include <fcntl.h>
#include <unistd.h>

int open_spool(const char *path) {
~>    if (access(path, W_OK) == 0) {
        return open(path, O_WRONLY | O_APPEND);
    }
    return -1;
}
