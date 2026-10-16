#include "perm.h"

int can_write(const struct inode *ino)
{
~>    if (ino->mode & PERM_WRITE == 0)
        return 0;
    return 1;
}
