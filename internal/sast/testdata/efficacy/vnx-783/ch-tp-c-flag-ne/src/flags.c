#include <fcntl.h>

int is_append(int flags)
{
~>    if (flags & O_APPEND != 0)
        return 1;
    return 0;
}
