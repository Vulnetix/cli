#include <stdio.h>
#include <stdarg.h>

~>#pragma GCC diagnostic ignored "-Wformat-security"

void log_msg(const char *msg) {
    printf(msg);
}
