#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>

~>static int fmt_into(char *buf, size_t n, const char *format, ...)
{
    va_list args;
    int r;
    va_start(args, format);
    r = vsnprintf(buf, n, format, args);
    va_end(args);
    return r;
}

~>void audit(int prio, const char *message, ...)
{
    va_list ap;
    va_start(ap, message);
    vsyslog(prio, message, ap);
    va_end(ap);
}
