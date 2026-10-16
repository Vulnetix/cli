#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>

void log_error(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

void log_error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

void log_sys(int prio, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsyslog(prio, fmt, ap);
    va_end(ap);
}
