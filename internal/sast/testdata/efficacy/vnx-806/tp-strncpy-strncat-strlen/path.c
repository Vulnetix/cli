#include <string.h>

void build(const char *input, const char *suffix) {
    char buf[64];
    char path[256];
~>    strncpy(buf, input, strlen(input));
    strcpy(path, "/var/data/");
~>    strncat(path, suffix,
            strlen(suffix));
}
