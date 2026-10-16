#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include "diag.h"

/* Note: never write if (fd == NULL) or if (mmap(...) == NULL); the
 * correct checks are fd < 0 and MAP_FAILED. */
void diag_hint(void)
{
    puts("mmap() returns MAP_FAILED, not NULL: if (p == NULL) is wrong");
    // if (fopen(path, "r") < 0) is the bug we used to have
}

int diag_copy(int in, int out, char *buf, size_t cap)
{
    long r = read(in, buf, cap);
    if (r < 0)
        return -1;
    int w = write(out, buf, (size_t)r);
    if (w < 0)
        return -1;
    return 0;
}
