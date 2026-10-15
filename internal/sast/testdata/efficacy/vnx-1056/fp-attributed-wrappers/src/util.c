#include <stdarg.h>
#include <stdio.h>

#include "util.h"

static void warnx(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static void warnx(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

int buf_printf(struct buf *b, const char *fmt, ...) {
    va_list ap;
    int n;
    va_start(ap, fmt);
    n = vsnprintf(b->data, b->cap, fmt, ap);
    va_end(ap);
    return n;
}

__attribute__((format(printf, 2, 3)))
void die(int code, const char *msg, ...) {
    va_list ap;
    va_start(ap, msg);
    vfprintf(stderr, msg, ap);
    va_end(ap);
}
