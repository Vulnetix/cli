#include <stdio.h>

void explain(void) {
again:
    /* the old code did: goto again; */
    // goto again;
    puts("never write goto again; in new code");
    return;
}
