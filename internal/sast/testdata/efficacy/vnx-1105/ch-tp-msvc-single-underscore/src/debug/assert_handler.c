#include <stdio.h>

void report_failure(const char *expr, const char *file, int line)
{
    fprintf(stderr, "assertion failed: %s (%s:%d)\n", expr, file, line);
#ifdef _MSC_VER
~>    _asm int 3
#else
~>    __asm__("int3");
#endif
}
