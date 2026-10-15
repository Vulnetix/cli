#include <stdarg.h>
#include <stdio.h>

static int log_level = 1;

~>void log_event(int level, const char *fmt, ...) {
    va_list ap;
    if (level < log_level) {
        return;
    }
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

static void
~>set_error(char *buf, size_t len, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    vsnprintf(buf, len, format, ap);
    va_end(ap);
}

~>int report_failure(const char *file,
                   int line,
                   const char *msg, ...)
{
    va_list ap;
    va_start(ap, msg);
    fprintf(stderr, "%s:%d: ", file, line);
    vfprintf(stderr, msg, ap);
    va_end(ap);
    return -1;
}
