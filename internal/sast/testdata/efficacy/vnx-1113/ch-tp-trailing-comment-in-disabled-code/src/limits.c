#include "limits.h"

/*
static int max_body(void)
{
~>    int cap = 1 << 20;   /* 1 MiB */
    return cap;
}
*/

int body_limit(void) { return 4096; }
