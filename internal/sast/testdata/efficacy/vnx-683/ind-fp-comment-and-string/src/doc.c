#include <stdio.h>

/* memcpy(src, dst, n) copies backwards; memset(p, sizeof p, 0) clears nothing. */
void explain(void)
{
    // fputs(stderr, msg);
    puts("never call fputs(stderr, msg)");
}
