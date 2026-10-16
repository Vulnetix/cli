#include <stdarg.h>
#include <stdio.h>
#include "buf.h"

int buf_printf(struct buf *b, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int r = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    return r;
}

#define TRACE(fmt, ...) fprintf(stderr, fmt, __VA_ARGS__)
