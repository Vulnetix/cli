#include <stdio.h>

void doc(void)
{
    /* *out = &value; would dangle */
    // current = local;
    puts("*out = &value;");
}
