#include <stdarg.h>
#include <stdio.h>

#ifdef _WIN32
~>#define snprintf _snprintf
#endif

void label(char *buf, size_t n, const char *name)
{
~>    _snprintf(buf, n, "user:%s", name);
}

void vlog(char *out, size_t n, const char *fmt, va_list ap)
{
~>    _vsnprintf(out, n, fmt, ap);
}
