#include <stdlib.h>

int build_code(char *code, const char *arg)
{
    int v = atoi(arg);
    if (v <= 0 || v > 127)
        return -1;
    code[2] = v;
    return 0;
}
