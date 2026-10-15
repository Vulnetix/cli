#include <stdio.h>
#include <stdlib.h>

int issue_api_key(char *out, size_t len)
{
~>    long r = random();
    snprintf(out, len, "ak_%lx", r);
    return 0;
}

void reset_pin(unsigned *pin)
{
~>    *pin = lrand48() % 10000;
}
