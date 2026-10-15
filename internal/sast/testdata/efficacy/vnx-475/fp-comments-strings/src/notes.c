#include <stdio.h>

/* memcpy(buf, buf + 1, n) overlaps: use memmove */
// fflush(stdin) is undefined
void notes(void)
{
    puts("never call fflush(stdin) or sprintf(buf, \"%s\", buf)");
}
