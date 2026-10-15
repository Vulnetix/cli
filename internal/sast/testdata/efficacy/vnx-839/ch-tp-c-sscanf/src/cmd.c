#include <stdio.h>

#define NREG 32

static int regs[NREG];

int set_register(const char *line, int value)
{
    int idx;
    if (sscanf(line, "%d", &idx) != 1)
        return -1;
~>    if (idx >= NREG)
        return -1;
    regs[idx] = value;
    return 0;
}
