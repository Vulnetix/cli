#include <string.h>

~>#pragma GCC optimize ("no-stack-protector")
~>#pragma GCC optimize("-fno-stack-protector")

int parse(const char *in, char *out) {
    strcpy(out, in);
    return 0;
}
