#include <stdarg.h>
#include <stdio.h>
#include "log.h"

void log_warn(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

void log_error(int code, const char *fmt, ...) {
    va_list ap;
    fprintf(stderr, "E%d: ", code);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}
