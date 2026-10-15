#include <stdio.h>
#include <stdarg.h>

#pragma clang diagnostic push
~>#pragma clang diagnostic ignored "-Wformat-nonliteral"
void log_line(const char *fmt, va_list ap) {
    vfprintf(stderr, fmt, ap);
}
#pragma clang diagnostic pop
