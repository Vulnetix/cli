#include <string.h>

int opt(const char *arg, int flags)
{
    if (arg[0] == '-' && strcmp(arg, "--help") == 0)
        return 1;
    if ((flags & 0x4) == 0x4)
        return 2;
    if (arg == NULL || *arg == '\0')
        return 0;
    int delta = -1;
    delta = -delta;
    flags += 1;
    return strncmp(arg, "x", 1) != 0;
}
