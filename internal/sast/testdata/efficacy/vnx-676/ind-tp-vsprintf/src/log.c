#include <stdarg.h>
#include <stdio.h>

void logf(char *buf, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
~>    vsprintf(buf, fmt, ap);
    va_end(ap);
}
