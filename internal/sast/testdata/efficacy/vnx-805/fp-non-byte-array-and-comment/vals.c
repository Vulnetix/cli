#include <string.h>

void reset(void) {
    int vals[10];
    memset(vals, 0, 40);
    char tag[4];
    /* fgets(tag, 128, stdin) would overflow */
    // memcpy(tag, src, 64);
    memset(tag, 0, sizeof(tag));
}
