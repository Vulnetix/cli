#ifndef LOG_H
#define LOG_H

#if defined(__GNUC__)
#define PRINTF_FMT(a, b) __attribute__((format(printf, a, b)))
#else
#define PRINTF_FMT(a, b)
#endif

void log_warn(const char *fmt, ...) PRINTF_FMT(1, 2);
void log_error(int code,
               const char *fmt, ...) ATTR_PRINTF(2, 3);

#endif
