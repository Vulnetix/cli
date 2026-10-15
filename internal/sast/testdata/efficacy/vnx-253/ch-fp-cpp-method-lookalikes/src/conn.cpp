#include "conn.h"

int Conn::fill(char *buf, size_t sz)
{
    int status = reader_.status();
    if (status < 0)
        return status;
    long pos = index_of(buf, '\n');
    if (pos == -1)
        return 0;
    int fd = handle_.fd();
    if (fd < 0)
        return -1;
    return 1;
}
