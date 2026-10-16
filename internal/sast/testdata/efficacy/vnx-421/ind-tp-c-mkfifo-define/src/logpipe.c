#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#define LOG_FIFO "/tmp/logshipper.fifo"

int open_log_pipe(void)
{
~>    if (mkfifo(LOG_FIFO, 0600) < 0 && errno != EEXIST)
        return -1;
    return open(LOG_FIFO, O_RDONLY | O_NONBLOCK);
}
