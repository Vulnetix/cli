#include <stdio.h>

void fill(void)
{
    char buf[16];
    snprintf(buf, sizeof buf, "x");
    puts(buf);
}

char *passthrough(char *buf)
{
    return buf;
}
