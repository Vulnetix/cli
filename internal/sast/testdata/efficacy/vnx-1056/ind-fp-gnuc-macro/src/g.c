#include <stdarg.h>
#include <stdio.h>
void g_log(const char *fmt, ...) G_GNUC_PRINTF(1, 2);

void g_log(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}
