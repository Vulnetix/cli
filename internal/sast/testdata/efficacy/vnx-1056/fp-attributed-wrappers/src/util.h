#ifndef UTIL_H
#define UTIL_H

struct buf {
    char *data;
    unsigned long cap;
};

int buf_printf(struct buf *b, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

#endif
