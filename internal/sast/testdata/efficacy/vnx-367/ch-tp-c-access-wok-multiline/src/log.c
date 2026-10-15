#include <fcntl.h>
#include <unistd.h>

int open_log(const char *logfile) {
    if (access(logfile, W_OK) != 0) {
        return -1;
    }
~>    int fd = open(logfile,
                  O_WRONLY | O_APPEND);
    return fd;
}
