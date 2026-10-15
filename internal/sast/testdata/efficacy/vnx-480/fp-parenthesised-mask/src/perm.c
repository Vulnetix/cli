#include <string.h>

#define PERM_WRITE 0x2

int can_write(unsigned flags, const char *mode, int a, int b)
{
    if ((flags & PERM_WRITE) == 0)
        return 0;
    if (a && b == 1)
        return 2;
    if (strcmp(mode, "rw") == 0)
        return 1;
    return a || b != 0;
}
