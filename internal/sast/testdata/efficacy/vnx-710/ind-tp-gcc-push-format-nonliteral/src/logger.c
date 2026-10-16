#include <stdarg.h>
#include <stdio.h>

#pragma GCC diagnostic push
~>#pragma GCC diagnostic ignored "-Wformat-nonliteral"
void log_line(FILE *out, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(out, fmt, ap);
    va_end(ap);
}
#pragma GCC diagnostic pop

void log_user(FILE *out, const char *msg)
{
#pragma clang diagnostic push
~>#pragma clang diagnostic ignored "-Wformat-security"
    fprintf(out, msg);
#pragma clang diagnostic pop
}
