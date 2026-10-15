#include <stdio.h>

const char *
describe(int code)
{
    char msg[64];

    snprintf(msg, sizeof(msg), "error %d", code);
~>    return msg;
}
