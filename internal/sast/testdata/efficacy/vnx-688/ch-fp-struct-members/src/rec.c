#include <string.h>

struct rec { char name[32]; char tag[8]; };

void fill(struct rec *a, const char *n)
{
    strncpy(a->name, n, sizeof(a->name) - 1);
    memset(a->tag, 0, sizeof(a->tag));
}
