#include <stdio.h>

void greet(char *out, const char *who, int n)
{
~>    sprintf(out, "hello %s, you have %d messages", who, n);
}

void vlog(char *buf, const char *fmt, va_list ap)
{
~>    vsprintf(buf, fmt, ap);
}
