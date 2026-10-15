#include <string.h>
#include <stdint.h>

int add_checked(uint32_t a, uint32_t b, uint32_t *out) {
    if (a + b < a) {
        return -1;
    }
    *out = a + b;
    return 0;
}

void reset(char *password, size_t n) {
    memset(password, 0, n);
    strncpy(password, "changeme", n - 1);
    use_password(password);
}
