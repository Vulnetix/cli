#include <string.h>

/* silence a known compiler false positive: -Wno-everything would be wrong */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"
void fill(char *p, int unused) {
    memset(p, 0, 8);
}
#pragma GCC diagnostic pop

const char *note = "do not #define _CRT_SECURE_NO_WARNINGS here";
