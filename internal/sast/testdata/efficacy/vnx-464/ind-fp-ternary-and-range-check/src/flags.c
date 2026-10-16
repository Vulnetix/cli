#include <stdlib.h>

int set_flags(char *code, const char *arg, const char *s)
{
    int v;

    code[0] = atoi(s) ? 'Y' : 'N';
    v = atoi(arg);
    if (v <= 0 || v > 127)
        return -1;
    code[2] = v;
    return 0;
}
