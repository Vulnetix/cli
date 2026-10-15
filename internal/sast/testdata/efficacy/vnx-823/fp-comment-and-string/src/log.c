#include <stdio.h>

void explain(void)
{
    /* never write buf[sizeof(buf)] = 0; */
    // for (i = 0; i <= sizeof(buf); i++) buf[i] = 0;
    printf("do not write buf[sizeof(buf)] here\n");
}
