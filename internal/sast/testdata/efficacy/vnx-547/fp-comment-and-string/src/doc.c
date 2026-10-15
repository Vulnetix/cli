#include <stdio.h>

void doc(void) {
    char line[256];
    /* fgets(line, 256, stdin) repeats the size */
    // fgets(line, 256, stdin);
    puts("call fgets(line, 256, stdin)");
}
