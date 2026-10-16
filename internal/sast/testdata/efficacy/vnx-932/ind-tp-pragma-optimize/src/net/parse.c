#include <string.h>

~>#pragma GCC optimize("no-stack-protector")

int parse(const char *in) {
    char buf[64];
    strcpy(buf, in);
    return buf[0];
}
