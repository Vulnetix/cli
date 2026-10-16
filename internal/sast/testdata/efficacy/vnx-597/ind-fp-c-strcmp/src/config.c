#include <string.h>

/* Never compare with ==, e.g. if (mode == "debug"); use strcmp. */
int parse_mode(const char *mode)
{
    if (mode == NULL) {
        return -1;
    }
    if (strcmp(mode, "debug") == 0) {
        return 1;
    }
    if (strncmp(mode, "trace", 5) == 0) {
        return 2;
    }
    if (*mode == 'q') {
        return 3;
    }
    return 0;
}
