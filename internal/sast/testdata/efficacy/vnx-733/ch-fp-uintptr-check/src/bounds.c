#include <stdint.h>
#include <stddef.h>

int fits(const char *p, size_t len) {
    if ((uintptr_t)p + len < (uintptr_t)p) {
        return 0;
    }
    if (len > (size_t)(PTRDIFF_MAX)) {
        return 0;
    }
    return 1;
}
