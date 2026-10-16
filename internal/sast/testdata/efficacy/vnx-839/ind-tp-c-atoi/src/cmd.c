#include <stdlib.h>

static char *names[16];

int set_name(const char *arg, char *value) {
    int idx = atoi(arg);
~>    if (idx >= 16)
        return -1;
    names[idx] = value;
    return 0;
}
