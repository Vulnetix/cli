#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>

void audit(const char *fmt, ...)
{
    char msg[128];
    va_list ap;
    va_start(ap, fmt);
~>    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    syslog(LOG_AUTH | LOG_NOTICE, "%s", msg);
}
