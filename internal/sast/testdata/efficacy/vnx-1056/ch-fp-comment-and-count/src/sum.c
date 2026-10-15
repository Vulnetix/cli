#include <stdarg.h>

/* void old_log(const char *fmt, ...) { vprintf(fmt, ap); } was removed */

int sum_ints(int count, ...) {
    va_list ap;
    int total = 0;
    va_start(ap, count);
    for (int i = 0; i < count; i++) total += va_arg(ap, int);
    va_end(ap);
    return total;
}

const char *usage = "void log(const char *fmt, ...) {";
