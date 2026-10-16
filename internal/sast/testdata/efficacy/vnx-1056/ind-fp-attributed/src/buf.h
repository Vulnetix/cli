#pragma once
#include <stddef.h>
struct buf;
int buf_printf(struct buf *b, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
