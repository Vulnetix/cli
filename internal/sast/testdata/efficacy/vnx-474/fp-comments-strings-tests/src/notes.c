#include <stdio.h>

/* realloc(ptr, 0) frees on glibc but not everywhere */
// vfork() shares the parent's memory
void notes(void)
{
    puts("avoid vfork() and _snprintf()");
    puts("signal(SIGINT, handler) resets on System V");
}
