#include <cstdio>
#include <cstdarg>

void log_line(char *buf, size_t n, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
~>    _vsnprintf(buf, n, fmt, ap);
    va_end(ap);
}

void log_id(char *buf, size_t n, int id)
{
~>    _snprintf(buf, n, "id=%d", id);
}
