#include <stdio.h>

int read_command(void) {
    char line[256];
~>    if (fgets(line, 256, stdin) == NULL) {
        return -1;
    }
    return handle(line);
}
