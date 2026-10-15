#include <stdio.h>

// FILE *out = fopen(tmp, "w"); ... rename(tmp, path);
void usage(void) {
    puts("writes to a temp file with fopen(tmp, \"w\") then rename(tmp, path)");
}
