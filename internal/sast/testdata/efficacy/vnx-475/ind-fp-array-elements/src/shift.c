#include <string.h>

struct item { int id; char name[16]; };

void swap_first(struct item *items)
{
    struct item tmp;
    memcpy(&tmp, &items[0], sizeof(items[0]));
    memcpy(&items[0], &items[1], sizeof(items[0]));
    memcpy(&items[1], &tmp, sizeof(tmp));
}
