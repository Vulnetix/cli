#include <stdarg.h>
#include <stdio.h>

~>void log_event(int level, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}
