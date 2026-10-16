#include <string.h>
#include "perm.h"

int check(const struct inode *ino, const char *mode)
{
    if ((ino->mode & PERM_WRITE) == 0)
        return 0;
    if (strcmp(mode, "rw") == 0 && *mode == 'r')
        return 1;
    if (mode == NULL)
        return -1;
    return 2;
}
