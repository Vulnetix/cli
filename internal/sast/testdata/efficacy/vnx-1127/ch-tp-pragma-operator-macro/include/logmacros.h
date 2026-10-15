#ifndef LOGMACROS_H
#define LOGMACROS_H

#include <stdio.h>

#define LOG_RAW(fmt, ...)                                              \
    do {                                                               \
~>        _Pragma("GCC diagnostic ignored \"-Wformat-security\"")          \
        fprintf(stderr, fmt, __VA_ARGS__);                             \
    } while (0)

#if defined(__clang__)
~>_Pragma("clang diagnostic ignored \"-Wformat-nonliteral\"")
#endif

#endif
