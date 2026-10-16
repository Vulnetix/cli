#include "registry.h"

struct registry {
    int refs;
    long total;
    char label[64];
};

static int counter;

int registry_next(void)
{
    counter++;
    return counter;
}
