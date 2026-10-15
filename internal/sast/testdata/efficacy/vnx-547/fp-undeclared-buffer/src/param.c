#include <string.h>

void copy_param(char *dst, const char *src) {
    strncpy(dst, src, 64);
}
