#include <stdio.h>

void usage(void)
{
    // never write buf[strlen(buf) - 1] without a length check
    puts("buf[strlen(buf) - 1] is unsafe on empty input");
}
