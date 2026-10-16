#include <stdarg.h>
#include <stdio.h>

static char logbuf[256];

void log_greeting(const char *who, int unread)
{
    char out[64];
~>    sprintf(out, "hello %s, you have %d new messages", who, unread);
    puts(out);
}

void log_fmt(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
~>    vsprintf(logbuf, fmt, ap);
    va_end(ap);
}
