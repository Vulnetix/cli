#include <stdio.h>

void log_flush(FILE *fp)
{
    fflush(stdout);
    fflush(stderr);
    fflush(fp);
    /* fflush(stdin) is undefined; do not use it */
}
