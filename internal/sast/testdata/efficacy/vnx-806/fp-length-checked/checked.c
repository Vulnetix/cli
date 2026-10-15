#include <limits.h>
#include <string.h>

int set(const char *src) {
    char dst[64];
    char temp[PATH_MAX + 1];
    if (strlen(src) >= sizeof(dst))
        return -1;
    memcpy(dst, src, strlen(src) + 1);
    if (strlen(src) > PATH_MAX)
        return -1;
    memcpy(temp, src, strlen(src) + 1);
    size_t n = strlen(src);
    if (n >= sizeof(dst)) return -1;
    memcpy(dst, src, n);
    return 0;
}
