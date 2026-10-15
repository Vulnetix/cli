#include <stdlib.h>

long *alloc_slots(const char *arg)
{
    int slots = atoi(arg);
    if (slots <= 0)
        return NULL;
~>    return malloc(slots * sizeof(long));
}
