#include <stdarg.h>
#include <stdio.h>

#define TRACE(fmt, ...) fprintf(stderr, fmt, __VA_ARGS__)

void log_event(int level, const char *fmt, ...);

static void (*logger)(const char *fmt, ...) = NULL;

/* void old_log(const char *fmt, ...) { was removed } */
// int report(const char *msg, ...) {

void install(void (*cb)(const char *fmt, ...)) {
    logger = cb;
}

int sum_ints(int count, ...) {
    va_list ap;
    int total = 0;
    va_start(ap, count);
    for (int i = 0; i < count; i++) {
        total += va_arg(ap, int);
    }
    va_end(ap);
    return total;
}

char *join_paths(const char *first, ...) {
    return NULL;
}
