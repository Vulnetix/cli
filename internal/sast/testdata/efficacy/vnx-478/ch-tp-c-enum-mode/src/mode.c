#include <fcntl.h>

enum access { READ_ONLY, WRITE_ONLY, READ_WRITE };

int open_mode(enum access a)
{
    int oflags;
~>    switch (a) {
    case READ_ONLY:  oflags = O_RDONLY; break;
    case WRITE_ONLY: oflags = O_WRONLY; break;
    case READ_WRITE: oflags = O_RDWR; break;
    }
    return oflags | O_CLOEXEC;
}
