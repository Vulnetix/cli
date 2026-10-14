#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>

void log_message(int level, const char *fmt, ...)
{
    va_list ap;
    char buf[1024];

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    va_start(ap, fmt);
    vsyslog(level, fmt, ap);
    va_end(ap);
}

void log_choice(const char *fmt, int code)
{
    fprintf(stderr, fmt, code);
}
