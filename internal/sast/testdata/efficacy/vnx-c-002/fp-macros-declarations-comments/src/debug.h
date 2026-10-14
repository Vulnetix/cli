#ifndef DEBUG_H
#define DEBUG_H

#include <stdio.h>

int printf(const char *format, ...);
int sprintf(char *str, const char *format, ...) __attribute__((deprecated));

#define DEBUG_PRINT(...) printf(__VA_ARGS__)
#define TRACE(fp, ...) fprintf(fp, __VA_ARGS__)
#define TEST_TITLE(msg) do { \
        printf("== "); \
        printf(msg); \
    } while (0)
#define timed(msg) printf(msg ": %ld ms\n", elapsed)

#endif
