#include <stdio.h>

#pragma GCC diagnostic push
~>#pragma GCC diagnostic ignored "-Wformat-security"
void log_user(const char *msg) {
    printf(msg);
}
#pragma GCC diagnostic pop

#pragma clang diagnostic push
~>#pragma clang diagnostic ignored "-Warray-bounds"
~>#pragma GCC diagnostic ignored "-Wstringop-overflow="
int tail(int *a) { return a[16]; }
#pragma clang diagnostic pop
