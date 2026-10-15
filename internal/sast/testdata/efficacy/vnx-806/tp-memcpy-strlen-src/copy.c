#include <string.h>

void set_name(const char *src, const char *name) {
    char dst[32];
~>    memcpy(dst, src, strlen(src));
~>    memcpy(dst, name, strlen(name) + 1);
    puts(dst);
}
