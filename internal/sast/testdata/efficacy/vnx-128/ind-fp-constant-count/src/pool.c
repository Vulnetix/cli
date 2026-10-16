#include <stdlib.h>

#define MAX_ITEMS 256

struct item { int id; char name[32]; };

struct item *make_pool(void)
{
    return malloc(MAX_ITEMS * sizeof(struct item));
}
