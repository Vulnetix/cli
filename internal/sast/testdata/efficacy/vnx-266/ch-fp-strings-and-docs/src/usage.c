#include <stdio.h>

static void usage(void)
{
    fprintf(stderr, "do not call setuid(0) from a library\n");
    fprintf(stderr, "chmod(path, 04755) installs a set-uid helper\n");
    /* setuid(0); was removed in 2.1 */
}
