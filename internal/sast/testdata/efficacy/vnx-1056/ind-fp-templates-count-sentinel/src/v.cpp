#include <cstdarg>
#include <cstdio>
#include <utility>

template <typename... Args>
void say(const char *fmt, Args &&...args) {
    std::printf(fmt, std::forward<Args>(args)...);
}

int sum_ints(int count, ...) {
    va_list ap;
    va_start(ap, count);
    int s = 0;
    for (int i = 0; i < count; i++) s += va_arg(ap, int);
    va_end(ap);
    return s;
}

void (*logger)(const char *fmt, ...);
// void old(const char *fmt, ...) { va_list ap; vfprintf(stderr, fmt, ap); }
void proto(const char *fmt, ...);
