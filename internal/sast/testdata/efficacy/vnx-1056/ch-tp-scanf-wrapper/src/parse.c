#include <stdarg.h>
#include <stdio.h>

~>int parse_fields(const char *line, const char *fmt, ...) {
    va_list ap;
    int n;
    va_start(ap, fmt);
    n = vsscanf(line, fmt, ap);
    va_end(ap);
    return n;
}
