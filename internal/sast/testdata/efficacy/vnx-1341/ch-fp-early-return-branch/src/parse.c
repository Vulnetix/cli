#include <stdlib.h>

int parse(const char *in)
{
    char *copy = strdup(in);
    if (!validate(copy)) {
        free(copy);
        return -1;
    }
    consume(copy);
    free(copy);
    return 0;
}
